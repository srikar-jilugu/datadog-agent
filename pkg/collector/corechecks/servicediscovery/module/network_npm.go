// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package module

import (
	"github.com/DataDog/datadog-agent/cmd/system-probe/config"
	sysconfigtypes "github.com/DataDog/datadog-agent/cmd/system-probe/config/types"
	"github.com/DataDog/datadog-agent/pkg/network"
	npm "github.com/DataDog/datadog-agent/pkg/network/tracer"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// XXX: default check time for process-agent to check conns. However,
// it might be changed in process-agent config.
const npmUpdateInterval = 30 // Seconds

func isNPMAvailable(cfg *sysconfigtypes.Config) bool {
	_, ok := cfg.EnabledModules[config.NetworkTracerModule]
	return ok
}

func isNPMCallbackSetup() bool {
	return npm.GetActiveConnectionCallback != nil
}

func registerNPMCallback(module *discovery) {
	log.Debug("registering NPM callback")
	npm.GetActiveConnectionCallback = module.getNPMConnStats
}

func unregisterNPMCallback() {
	npm.GetActiveConnectionCallback = nil
}

func (s *discovery) getNPMConnStats(delta *network.Delta) {
	log.Debug("called from NPM")
	s.mux.Lock()
	defer s.mux.Unlock()

	// Temporary cache
	type networkStats struct {
		rxBytes uint64
		txBytes uint64
	}

	deltaByPid := make(map[uint32]*networkStats)

	for _, conn := range delta.Conns {
		_, ok := s.cache[int32(conn.Pid)]
		if !ok {
			continue
		}

		stats, ok := deltaByPid[conn.Pid]
		if !ok {
			stats = &networkStats{}
			deltaByPid[conn.Pid] = stats
		}

		stats.rxBytes += conn.Last.RecvBytes
		stats.txBytes += conn.Last.SentBytes
	}

	for pid, delta := range deltaByPid {
		log.Debugf("%v: %v", pid, *delta)
	}

	for pid, delta := range deltaByPid {
		info := s.cache[int32(pid)]
		info.rxBytes += delta.rxBytes
		info.txBytes += delta.txBytes

		info.rxBps = float64(delta.rxBytes) / npmUpdateInterval
		info.txBps = float64(delta.txBytes) / npmUpdateInterval
	}
}
