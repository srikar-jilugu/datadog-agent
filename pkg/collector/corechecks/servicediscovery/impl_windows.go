// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package servicediscovery

import (
	"time"

	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery/model"

	//pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	processNet "github.com/DataDog/datadog-agent/pkg/process/net"
)

//go:generate mockgen -source=$GOFILE -package=$GOPACKAGE -destination=impl_linux_mock.go

func init() {
	newOSImpl = newWindowsImpl
}

type windowsImpl struct {
	getSysProbeClient func() (systemProbeClient, error)
	time              timer

	ignoreCfg map[string]bool

	ignoreProcs       map[int]bool
	aliveServices     map[int]*serviceInfo
	potentialServices map[int]*serviceInfo
}

func newWindowsImpl(ignoreCfg map[string]bool) (osImpl, error) {
	return &windowsImpl{
		getSysProbeClient: getSysProbeClient,
		time:              realTime{},
		ignoreCfg:         ignoreCfg,
		ignoreProcs:       make(map[int]bool),
		aliveServices:     make(map[int]*serviceInfo),
		potentialServices: make(map[int]*serviceInfo),
	}, nil
}

func (sd *windowsImpl) DiscoverServices() (*discoveredServices, error) {
	sysProbe, err := sd.getSysProbeClient()
	if err != nil {
		return nil, errWithCode{
			err:  err,
			code: errorCodeSystemProbeConn,
		}
	}

	response, err := sysProbe.GetDiscoveryServices()
	if err != nil {
		return nil, errWithCode{
			err:  err,
			code: errorCodeSystemProbeServices,
		}
	}

	// The endpoint could be refactored in the future to return a map to avoid this.
	serviceMap := make(map[int]*model.Service, len(response.Services))
	for _, service := range response.Services {
		serviceMap[service.PID] = &service
	}

	events := serviceEvents{}

	now := sd.time.Now()

	// potentialServices contains processes that we scanned in the previous iteration and had open ports.
	// we check if they are still alive in this iteration, and if so, we send a start-service telemetry event.
	for pid, prevSvc := range sd.potentialServices {
		// Check if the previous service was found again.
		if service, ok := serviceMap[pid]; ok {
			// Promote the potential service to alive if it meets the criteria.
			if isValidLiveService(service) {
				prevSvc.LastHeartbeat = now
				prevSvc.service.RSS = service.RSS
				prevSvc.service.CPUCores = service.CPUCores
				sd.aliveServices[pid] = prevSvc
				events.start = append(events.start, *prevSvc)

			}
		}
	}
	clear(sd.potentialServices)

	// Check for new services
	for _, service := range response.Services {
		pid := service.PID

		if liveService, ok := sd.aliveServices[pid]; !ok {
			// This is the first time we find this process.
			// May or may not have open ports, may be a temporary process.
			// Track it as a potential service.
			newSvc := sd.getServiceInfo(service)
			sd.potentialServices[pid] = &newSvc
		} else if !isValidLiveService(&service) {
			// The previous live service is not valid (e.g. no ports).
			// Demote it to potential service.
			delete(sd.aliveServices, pid)
			liveService.LastHeartbeat = now
			liveService.service.RSS = service.RSS
			liveService.service.CPUCores = service.CPUCores
			events.stop = append(events.stop, *liveService)
			sd.potentialServices[pid] = liveService
		}
	}

	// check if services previously marked as alive still are.
	for pid, svc := range sd.aliveServices {
		if service, ok := serviceMap[pid]; !ok {
			// The live service is gone.
			delete(sd.aliveServices, pid)
			events.stop = append(events.stop, *svc)
		} else if now.Sub(svc.LastHeartbeat).Truncate(time.Minute) >= heartbeatTime {
			svc.LastHeartbeat = now
			svc.service.RSS = service.RSS
			svc.service.CPUCores = service.CPUCores
			events.heartbeat = append(events.heartbeat, *svc)
		}
	}

	return &discoveredServices{
		ignoreProcs:     sd.ignoreProcs,
		potentials:      sd.potentialServices,
		runningServices: sd.aliveServices,
		events:          events,
	}, nil
}

func (sd *windowsImpl) getServiceInfo(service model.Service) serviceInfo {
	//serviceType := servicetype.Detect(service.Ports)
	serviceType := "unknown"

	meta := ServiceMetadata{
		Name:               service.Name,
		Language:           service.Language,
		Type:               string(serviceType),
		APMInstrumentation: service.APMInstrumentation,
	}

	return serviceInfo{
		meta:          meta,
		service:       service,
		LastHeartbeat: sd.time.Now(),
	}
}

// isValidLiveService determines if a process meets the criteria to be considered
// a live Datadog service.
func isValidLiveService(service *model.Service) bool {
	return len(service.Ports) > 0
}

type systemProbeClient interface {
	GetDiscoveryServices() (*model.ServicesResponse, error)
}

func getSysProbeClient() (systemProbeClient, error) {
	// Windows system probe uses a static named pipe and not a socket.
	return processNet.GetRemoteSystemProbeUtil("")
}
