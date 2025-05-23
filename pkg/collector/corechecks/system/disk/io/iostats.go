// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package io implements the io check.
package io

import (
	"regexp"

	yaml "gopkg.in/yaml.v2"

	"github.com/DataDog/datadog-agent/comp/core/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/pkg/aggregator/sender"
	"github.com/DataDog/datadog-agent/pkg/collector/check"
	core "github.com/DataDog/datadog-agent/pkg/collector/corechecks"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/option"
)

const (
	// SectorSize is used here to substitute non-exporeted from github.com/shirou/gopsutil/v4/disk package constant named "sectorSize"
	SectorSize = 512
	kB         = (1 << 10)
	// CheckName is the name of the io check.
	CheckName = "io"
)

// Configure the IOstats check
func (c *IOCheck) commonConfigure(senderManager sender.SenderManager, data integration.Data, initConfig integration.Data, source string) error {
	if err := c.CommonConfigure(senderManager, initConfig, data, source); err != nil {
		return err
	}

	conf := make(map[interface{}]interface{})

	err := yaml.Unmarshal([]byte(initConfig), &conf)
	if err != nil {
		return err
	}

	blacklistRe, ok := conf["device_exclude_re"]
	if !ok {
		blacklistRe, ok = conf["device_blacklist_re"]
		if ok {
			log.Warn("'device_blacklist_re' has been deprecated, use 'device_exclude_re' instead")
		}
	}
	if ok && blacklistRe != "" {
		if regex, ok := blacklistRe.(string); ok {
			c.blacklist, err = regexp.Compile(regex)
		}
	}

	if lowercaseDeviceTagOption, ok := conf["lowercase_device_tag"]; ok {
		if lowercaseDeviceTag, ok := lowercaseDeviceTagOption.(bool); ok {
			c.lowercaseDeviceTag = lowercaseDeviceTag
		} else {
			log.Warn("Can't cast value of 'lowercase_device_tag' option to boolean: ", lowercaseDeviceTagOption)
		}
	}

	return err
}

// Factory creates a new check factory
func Factory() option.Option[func() check.Check] {
	return option.New(newCheck)
}

func newCheck() check.Check {
	return &IOCheck{
		CheckBase: core.NewCheckBase(CheckName),
	}
}
