// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package fleetautomationextension

import (
	"context"
	"encoding/json"
	"sync"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/extension/extensioncapabilities"
	"go.uber.org/zap"
)

type fleetAutomationExtension struct {
	extension.Extension // Embed base Extension for common functionality.

	extensionConfig *Config
	telemetry       component.TelemetrySettings
	collectorConfig *confmap.Conf
	mu              sync.RWMutex
}

var _ extensioncapabilities.ConfigWatcher = (*fleetAutomationExtension)(nil)

// NotifyConfig implements the ConfigWatcher interface, which allows this extension
// to be notified of the Collector's effective configuration. See interface:
// https://github.com/open-telemetry/opentelemetry-collector/blob/d0fde2f6b98f13cbbd8657f8188207ac7d230ed5/extension/extension.go#L46.

// This method is called during the startup process by the Collector's Service right after
// calling Start.
func (e *fleetAutomationExtension) NotifyConfig(_ context.Context, conf *confmap.Conf) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.collectorConfig = conf
	e.telemetry.Logger.Info("Received new collector configuration")
	e.printCollectorConfig()
	return nil
}

func (e *fleetAutomationExtension) printCollectorConfig() {
	configMap := e.collectorConfig.ToStringMap()
	configJSON, err := json.MarshalIndent(configMap, "", "  ")
	if err != nil {
		e.telemetry.Logger.Error(err.Error())
		return
	}
	e.telemetry.Logger.Info("Collector Configuration: ", zap.String("config", string(configJSON)))
}

// Start starts the extension via the component interface.
func (e *fleetAutomationExtension) Start(_ context.Context, _ component.Host) error {
	e.telemetry.Logger.Info("Started Datadog Fleet Automation extension")
	return nil
}

// Shutdown stops the extension via the component interface.
func (e *fleetAutomationExtension) Shutdown(_ context.Context) error {
	e.telemetry.Logger.Info("Stopped Datadog Fleet Automation extension")
	return nil
}

func newExtension(config *Config, telemetry component.TelemetrySettings) *fleetAutomationExtension {
	return &fleetAutomationExtension{
		extensionConfig: config,
		telemetry:       telemetry,
		collectorConfig: &confmap.Conf{},
	}
}
