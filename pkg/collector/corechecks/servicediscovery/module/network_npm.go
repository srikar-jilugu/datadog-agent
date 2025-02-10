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

func isNPMAvailable(cfg *sysconfigtypes.Config) bool {
	_, ok := cfg.EnabledModules[config.NetworkTracerModule]
	return ok
}

func registerNPMCallback() {
	log.Debug("registering NPM callback")
	npm.GetActiveConnectionCallback = getNPMConnStats
}

func getNPMConnStats(delta *network.Delta) {
	log.Debug("called from NPM")
}
