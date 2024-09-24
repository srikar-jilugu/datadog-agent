// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package module

import (
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/process"

	"github.com/DataDog/datadog-agent/cmd/system-probe/api/module"
	sysconfigtypes "github.com/DataDog/datadog-agent/cmd/system-probe/config/types"
	"github.com/DataDog/datadog-agent/cmd/system-probe/utils"

	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery/apm"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery/envs"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery/language"

	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery/model"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery/usm"

	"github.com/DataDog/datadog-agent/pkg/process/procutil"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/winutil"
	"github.com/DataDog/datadog-agent/pkg/util/winutil/iphelper"
)

const (
	pathServices = "/services"

	// Well-known PIDs
	idleProcessPid   = 0
	systemProcessPid = 4
)

var (
	ignoredPids = map[int32]bool{
		idleProcessPid: true,
	}
)

// Ensure discovery implements the module.Module interface.
var (
	_ module.Module = &discovery{}
)

// serviceInfo caches static data about a process.
type serviceInfo struct {
	generatedName      string
	ddServiceName      string
	ddServiceInjected  bool
	language           language.Language
	apmInstrumentation apm.Instrumentation
	cmdLine            []string
	startTimeMillis    uint64

	lastCPUUsage float64
	isRestricted bool
}

type resourceInfo struct {
	cpuUsage float64
	rss      uint64
	ports    []uint16
}

// discovery is an implementation of the Module interface for the discovery module.
type discovery struct {
	mux *sync.RWMutex
	// cache maps pids to data that should be cached between calls to the endpoint.
	cache map[int32]*serviceInfo

	// scrubber is used to remove potentially sensitive data from the command line
	scrubber *procutil.DataScrubber

	lastTotalSystemCPUUsage float64

	scmMonitor *winutil.SCMMonitor
}

// NewDiscoveryModule creates a new discovery system probe module.
func NewDiscoveryModule(*sysconfigtypes.Config, module.FactoryDependencies) (module.Module, error) {
	return &discovery{
		mux:        &sync.RWMutex{},
		cache:      make(map[int32]*serviceInfo),
		scrubber:   procutil.NewDefaultDataScrubber(),
		scmMonitor: winutil.GetServiceMonitor(),
	}, nil
}

// GetStats returns the stats of the discovery module.
func (s *discovery) GetStats() map[string]interface{} {
	return nil
}

// Register the discovery module with the provided HTTP mux.
func (s *discovery) Register(httpMux *module.Router) error {
	httpMux.HandleFunc("/status", s.handleStatusEndpoint)
	httpMux.HandleFunc(pathServices, utils.WithConcurrencyLimit(utils.DefaultMaxConcurrentRequests, s.handleServices))
	return nil
}

// Close cleans resources used by the discovery module.
func (s *discovery) Close() {
	s.mux.Lock()
	defer s.mux.Unlock()
	clear(s.cache)
}

// handleStatusEndpoint is the handler for the /status endpoint.
// Reports the status of the discovery module.
func (s *discovery) handleStatusEndpoint(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("Discovery Module is running"))
}

// handleServers is the handler for the /services endpoint.
// Returns the list of currently running services.
func (s *discovery) handleServices(w http.ResponseWriter, _ *http.Request) {
	services, err := s.getServices()
	if err != nil {
		_ = log.Errorf("failed to handle /discovery%s: %v", pathServices, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp := &model.ServicesResponse{
		Services: *services,
	}
	utils.WriteAsJSON(w, resp)
}

func removeIgnoredPids(pids []int32) []int32 {
	var pidCount = len(pids)

	if pidCount == 0 {
		return pids
	}

	var i = 0
	var tail = pidCount - 1

	// We need to keep System process because that is the host for IIS sites.
	for i < tail {
		p := pids[i]
		if _, ok := ignoredPids[p]; ok {
			// Swap the value in this bucket with something from the tail.
			// If the tail is also a well-known PID, we will process it again
			// in the next loop iteration.
			pids[i] = pids[tail]
			tail--
		} else {
			i++
		}
	}

	// Truncate the list without the well-known PIDs.
	return pids[:(tail + 1)]
}

// getServices returns the list of currently running services.
func (s *discovery) getServices() (*[]model.Service, error) {
	// Get a snapshot of the total system CPU usage in seconds.
	// This calls Win32 GetSystemTimes
	systemStats, err := cpu.Times(false)
	if err != nil {
		return nil, err
	}
	totalSystemCPUUsage := systemStats[0].User + systemStats[0].System
	systemCPUUsageDelta := totalSystemCPUUsage - s.lastTotalSystemCPUUsage

	// Get all current live processes. This calls Win32 EnumProcess.
	pids, err := process.Pids()
	if err != nil {
		return nil, err
	}

	pids = removeIgnoredPids(pids)

	newServiceInfos := make(map[int32]*serviceInfo, len(pids))
	var services []model.Service

	// Query all opened TCP ports.
	tcpTable, err := iphelper.GetExtendedTcpV4Table()
	if err != nil {
		return nil, err
	}

	for _, pid := range pids {
		// Query static process information. The results are cached.
		serviceInfo, err := s.getServiceInfo(pid)
		if err != nil {
			continue
		}

		if serviceInfo.isRestricted && pid != systemProcessPid {
			// Do not report restricted processes like PPL.
			// The only exception is System, which hosts IIS sites.
			continue
		}

		// Query resource usage by the process at this time.
		resInfo, err := queryUsedResources(pid, tcpTable)
		if err != nil {
			continue
		}

		newServiceInfos[pid] = serviceInfo

		// Compile a snapshot to report to the cloud.
		service, err := s.buildServiceSnapshot(pid, serviceInfo, resInfo, systemCPUUsageDelta)
		if err != nil {
			continue
		}

		serviceInfo.lastCPUUsage = resInfo.cpuUsage

		services = append(services, *service)
	}

	// Save the total system CPU usage for the next iteration.
	s.lastTotalSystemCPUUsage = totalSystemCPUUsage

	s.cleanCache(newServiceInfos)

	return &services, nil
}

func (s *discovery) getServiceInfo(pid int32) (*serviceInfo, error) {
	var info *serviceInfo

	// This also calls Win32 GetProcessTimes and provides createTime.
	proc, err := process.NewProcess(pid)
	if err != nil {
		return nil, err
	}

	// Check if the process was previously detected.
	cachedInfo, ok := s.getCachedInfo(proc)
	if ok {
		return cachedInfo, nil
	}

	if pid == systemProcessPid {
		// System is the host of IIS sites.
		info, err = s.getSystemProcessInfo(proc)
		if err != nil {
			return nil, err
		}
	} else {
		// Fetch createTime from the process. This should already be cached.
		createTimeMs, err := proc.CreateTime()
		if err != nil {
			return nil, err
		}

		envVars, err := getEnvVars(proc)
		if err != nil {
			return nil, err
		}

		// This calls Win32 QueryFullProcessImageName, with a fallback calling
		// GetProcessImageFileNameW for XP.
		// Some processes have no dedicated .exe but are a subsystem of Windows.
		// For example, the Registry is a subsystem of ntoskrnl.exe.
		exe, err := proc.Exe()
		if err != nil {
			return nil, err
		}

		// This calls Win32 NtQueryInformationProcess and then ReadProcessMemory to
		// extract the command line from the PEB. Do not use CmdlineSlice since
		// it does not handle paths with spaces like C:\Program Files.
		cmd, err := proc.Cmdline()
		if err != nil {
			return nil, err
		}

		var restricted = false
		if len(cmd) == 0 && len(exe) != 0 {
			// Cmdline may return a blank command line if it gets access denied and
			// typically these are protected processes. For example: csrss.exe, wininit.exe
			// Use the process image name as the base command line.
			// The len(exe) != 0 is a redundant check to prevent the Go compiler from incorrectly
			// optimizing out this block.
			restricted = true
			cmd = exe
			log.Debugf("Restricted process: %s", exe)
		}

		// Slice the command ourselves since gopsutil does not handle spaces in paths.
		cmdSlice := sliceCommandLine(cmd)
		cmdSlice, _ = s.scrubber.ScrubCommand(cmdSlice)

		// Get the SCM name if available.
		// A PID with multiple services will have multiple names too.
		// TODO: centralize the SCM info cache.
		serviceNames := []string{}
		scmInfo, err := s.scmMonitor.GetServiceInfo(uint64(pid))
		if err != nil {
			serviceNames = scmInfo.ServiceName
		}

		// rootDir has no effect for GetServiceName since USM has only Linux executable detectors.
		rootDir := filepath.Dir(exe)

		contextMap := make(usm.DetectorContextMap)
		contextMap[usm.ServiceProc] = proc

		fs := usm.NewSubDirFS(rootDir)
		ctx := usm.NewDetectionContext(cmdSlice, envVars, fs)
		ctx.Pid = int(proc.Pid)
		ctx.ContextMap = contextMap

		// Try to detect the runtime language of process.
		lang := language.FindInArgs(exe, cmdSlice)

		nameMeta := servicediscovery.GetServiceName(lang, ctx)
		apmInstrumentation := apm.Detect(lang, ctx)

		// For a single service on a process, prefer the SCM name.
		// TODO: Report multiple services on a single process.
		preferredName := nameMeta.Name
		if len(serviceNames) == 1 {
			preferredName = serviceNames[0]
		}

		// This is static process information
		info = &serviceInfo{
			generatedName:      preferredName,
			ddServiceName:      nameMeta.DDService,
			ddServiceInjected:  nameMeta.DDServiceInjected,
			apmInstrumentation: apmInstrumentation,
			language:           lang,
			cmdLine:            cmdSlice,
			startTimeMillis:    uint64(createTimeMs),
			lastCPUUsage:       0,
			isRestricted:       restricted,
		}
	}

	// Add new info to cache
	s.addCachedInfo(proc, info)

	return info, nil
}

// queryUsedResources queries for resources used by a process, such as
// CPU usage, working set, and ports.
func queryUsedResources(pid int32, tcpTable map[uint32][]iphelper.MIB_TCPROW_OWNER_PID) (*resourceInfo, error) {
	// We do not call process.NewProcess because it does a few expensive checks that we don't need.
	proc := &process.Process{
		Pid: pid,
	}

	// This calls Win32 GetProcessMemoryInfo with the working set.
	memInfo, err := proc.MemoryInfo()
	if err != nil {
		return nil, err
	}

	// This calls Win32 GetProcessTimes with CPU usage.
	cpuTimes, err := proc.Times()
	if err != nil {
		return nil, err
	}

	// Get the reserved TCP ports by this PID.
	var ports []uint16
	var entries = tcpTable[uint32(pid)]
	for _, entry := range entries {
		// DwLocalPort is stored in network order and only uses 16-bits (not 32-bits).
		rawPort := (uint16)(entry.DwLocalPort)
		port := ((rawPort & 0xFF00) >> 8) | ((rawPort & 0x00FF) << 8)
		ports = append(ports, port)
	}

	cpuUsage := cpuTimes.User + cpuTimes.System
	if cpuUsage == float64(0) {
		log.Debugf("CPU time was zero")
	}

	return &resourceInfo{
		// CPU user and system (kernel) times are in seconds.
		cpuUsage: cpuUsage,

		// RSS is the same as the working set.
		rss: memInfo.RSS,

		ports: ports,
	}, nil
}

func (s *discovery) buildServiceSnapshot(pid int32, serviceInfo *serviceInfo, resInfo *resourceInfo, systemCPUUsageDelta float64) (*model.Service, error) {
	// Preferred the name from DD_TAGS.
	preferredName := serviceInfo.ddServiceName
	if preferredName == "" {
		preferredName = serviceInfo.generatedName
	}

	// Compute average CPU core usage.
	avgCPUCores := float64(0)
	if serviceInfo.lastCPUUsage != 0 {
		// Compute only if there are at least two samples, otherwise the first
		// result will show up as a spike.
		procCPUUsageDelta := resInfo.cpuUsage - serviceInfo.lastCPUUsage
		avgCPUCores = (procCPUUsageDelta / systemCPUUsageDelta) * float64(runtime.NumCPU())

		if procCPUUsageDelta > systemCPUUsageDelta || avgCPUCores < 0 {
			log.Errorf("Unexpected process CPU usage %f and system CPU usage %f",
				procCPUUsageDelta, systemCPUUsageDelta)
			avgCPUCores = 0
		}
	}

	return &model.Service{
		// Static metadata information
		PID:                int(pid),
		Name:               preferredName,
		GeneratedName:      serviceInfo.generatedName,
		DDService:          serviceInfo.ddServiceName,
		DDServiceInjected:  serviceInfo.ddServiceInjected,
		APMInstrumentation: string(serviceInfo.apmInstrumentation),
		Language:           string(serviceInfo.language),
		CommandLine:        serviceInfo.cmdLine,
		StartTimeMilli:     serviceInfo.startTimeMillis,

		// Dynamic resource information
		RSS:      resInfo.rss,
		CPUCores: avgCPUCores,
		Ports:    resInfo.ports,
	}, nil
}

func (s *discovery) getCachedInfo(proc *process.Process) (*serviceInfo, bool) {
	s.mux.RLock()
	service, ok := s.cache[proc.Pid]
	s.mux.RUnlock()

	if ok {
		// PIDs can be randomly reused. Check if this process matches the same start time.
		createTimeMs, err := proc.CreateTime()
		if err == nil && uint64(createTimeMs) == service.startTimeMillis {
			return service, true
		}
	}

	return nil, false
}

func (s *discovery) addCachedInfo(proc *process.Process, info *serviceInfo) {
	// If a PID was reused, this new entry will replace it.
	s.mux.RLock()
	s.cache[proc.Pid] = info
	s.mux.RUnlock()
}

// getEnvs gets the environment variables for the process, both the initial
// ones, and if present, the ones injected via the auto injector.
func getEnvVars(proc *process.Process) (envs.Variables, error) {
	var envVars = envs.Variables{}

	// This calls Win32 GetProcessEnvironmentVariables
	procEnvs, err := proc.Environ()
	if err != nil {
		return envVars, err
	}

	// Split the name/value pairs.
	for _, env := range procEnvs {
		name, value, found := strings.Cut(env, "=")
		if found {
			envVars.Set(name, value)
		}
	}

	return envVars, nil
}

func sliceCommandLine(cmd string) []string {
	doubleQuoted := false
	splitFunc := func(c rune) bool {
		if c == '"' {
			doubleQuoted = !doubleQuoted
			return true
		}

		// Split only if the space was found not under double quotes.
		return c == ' ' && !doubleQuoted
	}

	cmdSlice := strings.FieldsFunc(cmd, splitFunc)
	return cmdSlice
}

// getSystemProcessInfo fills information about the Windows System process,
// a protected process, which cannot be queried by System Probe.
func (s *discovery) getSystemProcessInfo(proc *process.Process) (*serviceInfo, error) {
	createTimeMs, err := proc.CreateTime()
	if err != nil {
		return nil, err
	}

	// SCM is not able to provide service names for System process.

	return &serviceInfo{
		generatedName:      "Windows System",
		ddServiceName:      "",
		ddServiceInjected:  false,
		apmInstrumentation: apm.None,
		language:           language.Unknown,
		cmdLine:            []string{},
		startTimeMillis:    uint64(createTimeMs),
		lastCPUUsage:       0,
		isRestricted:       true,
	}, nil
}

// ignoreComms is a list of process names (matched against /proc/PID/comm) to
// never report as a service. Note that comm is limited to 16 characters.
/*
var ignoreComms = map[string]struct{}{
	"sshd":             {},
	"dhclient":         {},
	"systemd":          {},
	"systemd-resolved": {},
	"systemd-networkd": {},
	"datadog-agent":    {},
	"livenessprobe":    {},
	"docker-proxy":     {},
}
*/

// updateCache deletes dead PIDs from the cache. Note that this does not actually
// shrink the map but should free memory for the service name strings referenced
// from it.
func (s *discovery) cleanCache(newServiceInfos map[int32]*serviceInfo) {
	s.mux.Lock()
	defer s.mux.Unlock()

	for pid, oldInfo := range s.cache {
		if newInfo, alive := newServiceInfos[pid]; alive {
			// PIDs can be reused.  Keep the info only if the start time matches.
			if oldInfo.startTimeMillis == newInfo.startTimeMillis {
				continue
			}
		}

		delete(s.cache, pid)
	}
}
