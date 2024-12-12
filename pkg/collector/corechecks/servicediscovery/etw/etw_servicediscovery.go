// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build windows

// Package etw implements service discovery through ETW.
package etw

import (
	"fmt"
	"sync"
	"time"
	"unsafe"

	sysconfigtypes "github.com/DataDog/datadog-agent/cmd/system-probe/config/types"
	"github.com/DataDog/datadog-agent/comp/etw"
	etwimpl "github.com/DataDog/datadog-agent/comp/etw/impl"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/http"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"golang.org/x/sys/windows"
)

// EtwServiceDiscovery tracks services discovered through ETW.
// nolint:revive // TODO(WKIT) Fix revive linter
type EtwServiceDiscovery struct {
	eventLoopWG sync.WaitGroup

	iis iisDiscovery

	// ETW component
	httpguid windows.GUID
	session  etw.Session
}

// NewEtwServiceDiscovery returns a new EtwServiceDiscovery instance
func NewEtwServiceDiscovery(_ *sysconfigtypes.Config) (*EtwServiceDiscovery, error) {
	etwsd := &EtwServiceDiscovery{}

	etwSessionName := "SystemProbeSD_ETW"
	etwcomp, err := etwimpl.NewEtw()
	if err != nil {
		return nil, err
	}

	etwsd.session, err = etwcomp.NewSession(etwSessionName, func(_ *etw.SessionConfiguration) {})
	if err != nil {
		return nil, err
	}
	// Microsoft-Windows-HttpService  {dd5ef90a-6398-47a4-ad34-4dcecdef795f}
	//     https://github.com/repnz/etw-providers-docs/blob/master/Manifests-Win10-18990/Microsoft-Windows-HttpService.xml
	etwsd.httpguid, err = windows.GUIDFromString("{dd5ef90a-6398-47a4-ad34-4dcecdef795f}")
	if err != nil {
		return nil, fmt.Errorf("Error creating GUID for HTTPService ETW provider: %v", err)
	}
	pidsList := []uint32{0}
	etwsd.session.ConfigureProvider(etwsd.httpguid, func(cfg *etw.ProviderConfiguration) {
		cfg.TraceLevel = etw.TRACE_LEVEL_INFORMATION
		cfg.PIDs = pidsList
		cfg.MatchAnyKeyword = 0x136
	})
	err = etwsd.session.EnableProvider(etwsd.httpguid)
	if err != nil {
		return nil, fmt.Errorf("Error enabling HTTPService ETW provider: %v", err)
	}
	return etwsd, nil
}

// Start initiates listening to ETW notifications.
func (etwsd *EtwServiceDiscovery) Start() error {
	err := etwsd.iis.initialize()
	if err != nil {
		return err
	}

	etwsd.eventLoopWG.Add(2)

	startingEtwChan := make(chan struct{})

	// Currently ETW needs be started on a separate thread
	// because it is blocked until subscription is stopped
	go func() {
		defer etwsd.eventLoopWG.Done()
		startingEtwChan <- struct{}{}
		err := etwsd.session.StartTracing(func(e *etw.DDEventRecord) {
			// By default this function call never exits and its callbacks or rather events
			// will be returned on the very the same thread until ETW is canceled via
			// etw.StopEtw(). There is asynchronous flag which implicitly will create a real
			// (Windows API) thread but it is not tested yet.
			etwsd.OnEvent(e)
		})

		if err == nil {
			log.Infof("ETW HttpService subscription completed")
		} else {
			log.Errorf("ETW HttpService subscription failed with error %v", err)
		}
	}()

	// This separate thread is needed for the first one to run.
	go func() {
		defer etwsd.eventLoopWG.Done()
		defer close(startingEtwChan)

		// Block until we get go ahead signal
		<-startingEtwChan

		// We need to make sure that we are invoked when etw.StartEtw() is called but
		// we cannot wait until it exits because it exits only when Agent exit. There
		// shoulbe be more elegant ways to deal with that, perhaps adding dedicated
		// callback from CGO but for now let's sleep for a second
		time.Sleep(time.Second)
	}()

	return nil
}

// Close stops listening to ETW notifications and ensures the infrastructure is gracefully shutdown.
func (etwsd *EtwServiceDiscovery) Close() {
	cfg := etwsd.iis.iisConfig.Swap(nil)
	if cfg != nil {
		cfg.Stop()
	}

	if etwsd.session != nil {
		_ = etwsd.session.StopTracing()
		etwsd.eventLoopWG.Wait()
	}
}

// GetIISSites returns the discovered IIS sites.
func (etwsd *EtwServiceDiscovery) GetIISSites() []IISSite {
	var sites []IISSite
	etwsd.iis.iisSitesRWMux.RLock()
	defer etwsd.iis.iisSitesRWMux.RUnlock()

	for _, site := range etwsd.iis.iisSites {
		sites = append(sites, *site)
	}

	return sites
}

// OnEvent receives ETW notifications and delegates the record to specific handlers.
func (etwsd *EtwServiceDiscovery) OnEvent(eventInfo *etw.DDEventRecord) {
	switch eventInfo.EventHeader.EventDescriptor.ID {

	// #21
	case http.EVENT_ID_HttpService_HTTPConnectionTraceTaskConnConn:
		etwsd.iis.handleHTTPConnectionTraceTaskConnConn(eventInfo)

	// #1
	case http.EVENT_ID_HttpService_HTTPRequestTraceTaskRecvReq:
		etwsd.iis.handleHTTPRequestTraceTaskRecvReq(eventInfo)

	// #3
	case http.EVENT_ID_HttpService_HTTPRequestTraceTaskDeliver:
		etwsd.iis.handleHTTPRequestTraceTaskDeliver(eventInfo)
	}
}

// Utilities

// FormatGUID converts a guid structure to a go string
func FormatGUID(guid etw.DDGUID) string {
	return fmt.Sprintf("{%08X-%04X-%04X-%02X%02X%02X%02X%02X%02X%02X%02X}",
		guid.Data1, guid.Data2, guid.Data3,
		guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
		guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7])
}

// GetRelatedActivityID gets the activity ID that is used for subsequent related
// ETW activities.  This is used to link various async notifications together.
func GetRelatedActivityID(e *etw.DDEventRecord) *etw.DDGUID {

	if e.ExtendedDataCount == 0 || e.ExtendedData == nil {
		return nil
	}
	exDatas := unsafe.Slice(e.ExtendedData, e.ExtendedDataCount)
	for _, exData := range exDatas {
		var g etw.DDGUID
		if exData.ExtType == etw.EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID && exData.DataSize == uint16(unsafe.Sizeof(g)) {
			activityID := (*etw.DDGUID)(unsafe.Pointer(exData.DataPtr))
			return activityID
		}
	}
	return nil
}
