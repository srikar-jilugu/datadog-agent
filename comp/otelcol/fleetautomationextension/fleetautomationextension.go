// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package fleetautomationextension

import (
	"context"

	"go.opentelemetry.io/collector/component"
)

type fleetAutomationExtension struct {
	config    *Config
	telemetry component.TelemetrySettings
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
		config:    config,
		telemetry: telemetry,
	}
}
