// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package winsoftware implements code to collect installed software from a Windows system.
package winsoftware

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

var (
	msi                  = syscall.NewLazyDLL("msi.dll")
	msiEnumProducts      = msi.NewProc("MsiEnumProductsW")
	msiGetProductInfo    = msi.NewProc("MsiGetProductInfoW")
	msiIsProductElevated = msi.NewProc("MsiIsProductElevatedW")
	advapi32             = syscall.NewLazyDLL("advapi32.dll")
	procRegLoadKey       = advapi32.NewProc("RegLoadKeyW")
	procRegUnLoadKey     = advapi32.NewProc("RegUnLoadKeyW")
)

const (
	ERROR_SUCCESS       = 0
	ERROR_MORE_DATA     = 234
	ERROR_NO_MORE_ITEMS = 259
	MAX_PATH            = 260
)

var msiPropertiesToFetch = []string{
	"ProductName",
	"AssignmentType",
	"Version",
	"VersionString",
	"InstallSource",
	"InstallDate",
	"Publisher",
	"LocalPackage",
	"VersionMinor",
	"VersionMajor",
}

var registryPropertiesToFetch = []string{
	"DisplayName",
	"Publisher",
	"DisplayVersion",
	"UninstallString",
	"InstallLocation",
	"VersionMajor",
	"VersionMinor",
	"EstimatedSize",
	"InstallDate",
	"Version",
	"InstallSource",
}

var mapMsiPropertiesToRegistryProperties = map[string]string{
	"ProductName":   "DisplayName",
	"VersionString": "DisplayVersion",
}

// Warning is a custom error type that can be used to return warnings
type Warning struct {
	Msg string
}

// Error implements the error interface
func (w Warning) Error() string {
	return "warning: " + w.Msg
}

func warnf(format string, args ...any) *Warning {
	return &Warning{Msg: fmt.Sprintf(format, args...)}
}

// GetSoftwareInventory returns a map of installed software from the registry and MSI database
func GetSoftwareInventory() (inventory map[string]map[string]string, err error, warn *Warning) {
	inventory = make(map[string]map[string]string)
	installedSoftware, err := collectInstalledSoftwareFromRegistry()
	if err != nil {
		err = fmt.Errorf("error collecting installed software: %v", err)
		return
	}
	msiProducts, err := collectSoftwareFromMsiDatabase(msiPropertiesToFetch)
	if err != nil {
		err = fmt.Errorf("error enumerating products from MSI database: %v", err)
		return
	}

	for productCode, metadata := range msiProducts {
		registryEntry, entryExists := installedSoftware[productCode]
		if !entryExists {
			if len(metadata) > 0 {
				installedSoftware[productCode] = metadata
			} else {
				warn = warnf("invalid software detected, consider repairing the MSI database: %s\n", productCode)
			}
		} else {
			for propName, propValue := range metadata {
				mappedPropName, mappingExists := mapMsiPropertiesToRegistryProperties[propName]
				if mappingExists {
					propName = mappedPropName
				}
				if _, propExist := registryEntry[propName]; propExist && registryEntry[propName] == "" {
					registryEntry[propName] = propValue
				} else {
					installedSoftware[productCode][propName] = propValue
				}
			}
		}
	}

	for productCode, metadata := range installedSoftware {
		inventory[productCode] = metadata
	}
	return
}

func getMsiProductInfo(productCode []uint16, propertiesToFetch []string) (map[string]string, error) {
	// Helper to fetch a property
	getProp := func(propName string) string {
		const bufSize = MAX_PATH
		buf := make([]uint16, bufSize)
		bufLen := uint32(bufSize)
		r, _, _ := msiGetProductInfo.Call(
			uintptr(unsafe.Pointer(&productCode[0])),
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(propName))),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&bufLen)),
		)
		if r == 0 {
			return syscall.UTF16ToString(buf[:bufLen])
		}
		return ""
	}

	properties := make(map[string]string)
	for _, propName := range propertiesToFetch {
		propValue := getProp(propName)
		if propValue != "" {
			properties[propName] = propValue
		}
	}

	return properties, nil
}

func collectSoftwareFromMsiDatabase(propertiesToFetch []string) (map[string]map[string]string, error) {
	// When making multiple calls to MsiEnumProducts to enumerate all of the products, each call should be made from the same thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var index uint32 = 0
	products := map[string]map[string]string{}
	for {
		productCode := make([]uint16, 39)
		ret, _, _ := msiEnumProducts.Call(
			uintptr(index),
			uintptr(unsafe.Pointer(&productCode[0])),
		)
		if ret == ERROR_NO_MORE_ITEMS {
			break
		}
		if ret != ERROR_SUCCESS {
			fmt.Printf("error enumerating products at index %d: %d\n", index, ret)
			break
		}
		info, err := getMsiProductInfo(productCode, propertiesToFetch)
		if err != nil {
			fmt.Printf("error getting product info: %v\n", err)
		} else {
			products[syscall.UTF16ToString(productCode)] = info
		}
		index++
	}
	return products, nil
}

// Helper to collect from a given root key and subkey
func collectFromKey(root registry.Key, subkey string, view uint32) map[string]map[string]string {
	results := make(map[string]map[string]string)
	key, err := registry.OpenKey(root, subkey, registry.READ|view)
	if err != nil {
		return results
	}
	defer key.Close()
	subkeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return results
	}
	for _, skey := range subkeys {
		sk, err := registry.OpenKey(key, skey, registry.READ|view)
		if err != nil {
			continue
		}
		item := make(map[string]string)
		for _, field := range registryPropertiesToFetch {
			val, _, err := sk.GetStringValue(field)
			if err == nil {
				item[field] = val
			}
		}
		if name, ok := item["DisplayName"]; ok && name != "" {
			item["ProductCode"] = skey
			results[skey] = item
		}
		sk.Close()
	}
	return results
}

// Mounts a user's NTUSER.DAT hive under HKU\temp, returns error if unsuccessful
func mountHive(hivePath string) error {
	hivePathPtr, _ := syscall.UTF16PtrFromString(hivePath)
	tempPtr, _ := syscall.UTF16PtrFromString("temp")
	r, _, err := procRegLoadKey.Call(uintptr(syscall.HKEY_USERS), uintptr(unsafe.Pointer(tempPtr)), uintptr(unsafe.Pointer(hivePathPtr)))
	if r != 0 {
		return err
	}
	return nil
}

// Unmounts HKU\temp
func unmountHive() error {
	tempPtr, _ := syscall.UTF16PtrFromString("temp")
	r, _, err := procRegUnLoadKey.Call(uintptr(syscall.HKEY_USERS), uintptr(unsafe.Pointer(tempPtr)))
	if r != 0 {
		return err
	}
	return nil
}

// collectInstalledSoftwareFromRegistry returns a slice of maps with installed software from HKLM registry (both 64-bit and 32-bit views)
func collectInstalledSoftwareFromRegistry() (map[string]map[string]string, error) {
	results := make(map[string]map[string]string)
	paths := []struct {
		root   registry.Key
		subkey string
		view   uint32
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, registry.WOW64_64KEY},
		{registry.LOCAL_MACHINE, `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, registry.WOW64_32KEY},
	}

	// 1. Global (HKLM)
	for _, p := range paths {
		for subkey, item := range collectFromKey(p.root, p.subkey, p.view) {
			if _, exists := results[subkey]; exists {
				fmt.Printf("warning: duplicate software detected %s (%s)\n", item["DisplayName"], item["ProductCode"])
			}
			results[subkey] = item
		}
	}

	// 2. All loaded user hives (HKU)
	hku, err := registry.OpenKey(registry.USERS, "", registry.READ)
	if err == nil {
		defer hku.Close()
		userSIDs, _ := hku.ReadSubKeyNames(-1)
		for _, sid := range userSIDs {
			// Only collect user hives for regular users, not system accounts
			if !strings.HasPrefix(sid, "S-1-5-21-") {
				continue
			}
			for _, p := range paths {
				for subkey, item := range collectFromKey(registry.USERS, sid+`\`+p.subkey, p.view) {
					if _, exists := results[subkey]; exists {
						fmt.Printf("warning: duplicate software detected %s (%s)\n", item["DisplayName"], item["ProductCode"])
					}
					results[subkey] = item
				}
			}
		}
	}

	// 3. All unmounted user hives (mount, collect, unmount)
	userDirs, _ := os.ReadDir(`C:\Users`)
	for _, dir := range userDirs {
		profilePath := filepath.Join(`C:\Users`, dir.Name())
		ntuser := filepath.Join(profilePath, "NTUSER.DAT")
		usr, err := user.Lookup(dir.Name())
		if err != nil || usr.Uid == "" || strings.HasPrefix(usr.Uid, "S-1-5-18") {
			continue
		}
		sid := usr.Uid
		hku, _ := registry.OpenKey(registry.USERS, "", registry.READ)
		loadedSIDs, _ := hku.ReadSubKeyNames(-1)
		hku.Close()
		alreadyLoaded := false
		for _, s := range loadedSIDs {
			if s == sid {
				alreadyLoaded = true
				break
			}
		}
		if alreadyLoaded {
			continue
		}
		if _, err := os.Stat(ntuser); err == nil {
			if err := mountHive(ntuser); err == nil {
				for _, p := range paths {
					for subkey, item := range collectFromKey(registry.USERS, `temp\`+p.subkey, p.view) {
						if _, exists := results[subkey]; exists {
							fmt.Printf("warning: duplicate software detected %s (%s)\n", item["DisplayName"], item["ProductCode"])
						}
						results[subkey] = item
					}
				}
				unmountHive()
			}
		}
	}

	return results, nil
}
