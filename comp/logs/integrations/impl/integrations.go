// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package integrationsimpl implements the integrations component interface
package integrationsimpl

import (
	"github.com/DataDog/datadog-agent/comp/core/autodiscovery/integration"
	integrations "github.com/DataDog/datadog-agent/comp/logs/integrations/def"
	logger "github.com/DataDog/datadog-agent/pkg/util/log" // JMW
)

// Logsintegration is the integrations component implementation
type Logsintegration struct {
	logChan         chan integrations.IntegrationLog
	integrationChan chan integrations.IntegrationConfig
}

// NewLogsIntegration creates a new integrations instance
func NewLogsIntegration() *Logsintegration {
	return &Logsintegration{
		logChan:         make(chan integrations.IntegrationLog),
		integrationChan: make(chan integrations.IntegrationConfig),
	}
}

// RegisterIntegration registers an integration with the integrations component
func (li *Logsintegration) RegisterIntegration(id string, config integration.Config) {
	logger.Infof("JMW integrations RegisterIntegration() received id: %s, config: %+v", id, config)
	if len(config.LogsConfig) == 0 {
		logger.Infof("JMW integrations RegisterIntegration() len(config.LogsConfig) == 0 - returning")
		return
	}

	integrationConfig := integrations.IntegrationConfig{
		IntegrationID: id,
		Config:        config,
	}

	logger.Infof("JMW integrations RegisterIntegration() writing integrationConfig to channel: %+v", integrationConfig)
	li.integrationChan <- integrationConfig
}

// SendLog sends a log to any subscribers
func (li *Logsintegration) SendLog(log, integrationID string) {
	integrationLog := integrations.IntegrationLog{
		Log:           log,
		IntegrationID: integrationID,
	}

	logger.Infof("JMW integrations SendLog() writing integrationLog to channel: %s", integrationLog)
	li.logChan <- integrationLog
}

// Subscribe returns the channel that receives logs from integrations. Currently
// the integrations component only supports one subscriber, but can be extended
// later by making a new channel for any number of subscribers.
func (li *Logsintegration) Subscribe() chan integrations.IntegrationLog { // JMW
	logger.Infof("JMW integrations Subscribe() returning logChan")
	return li.logChan
}

// SubscribeIntegration returns the channel that receives integration configurations
func (li *Logsintegration) SubscribeIntegration() chan integrations.IntegrationConfig {
	logger.Infof("JMW integrations SubscribeIntegration() returning integrationChan")
	return li.integrationChan
}
