// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package autoinstrumentation

import (
	"fmt"

	"github.com/DataDog/datadog-agent/comp/core/config"
)

// InjectionFilterConfig holds the configuration for auto injection V2 and can be configured via apm_config.instrumentation.
type InjectionFilterConfig struct {
	// apm.instrumentation.enabled_namespaces
	EnabledNamespaces []string `mapstructure:"enabled_namespaces"`
	// apm.instrumentation.disabled_namespaces
	DisabledNamespaces []string `mapstructure:"disabled_namespaces"`
	// apm.instrumentation.enabled
	Enabled bool `mapstructure:"enabled"`
	// apm.instrumentation.lib_version
	LibVersions map[string]string `mapstructure:"lib_versions"`
}

// NewInjectionFilterConfig creates a new InjectionFilterConfig from the datadog config.
func NewInjectionFilterConfig(datadogConfig config.Component) (*InjectionFilterConfig, error) {
	cfg := &InjectionFilterConfig{}
	err := datadogConfig.UnmarshalKey("apm_config.instrumentation", cfg)
	if err != nil {
		return cfg, fmt.Errorf("error parsing apm_config.instrumentation: %w", err)
	}

	if len(cfg.EnabledNamespaces) > 0 && len(cfg.DisabledNamespaces) > 0 {
		return nil, fmt.Errorf("apm.instrumentation.enabled_namespaces and apm.instrumentation.disabled_namespaces configuration cannot be set together")
	}

	return cfg, nil
}
