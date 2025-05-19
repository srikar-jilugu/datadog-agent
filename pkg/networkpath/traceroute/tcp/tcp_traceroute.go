// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package tcp

import (
	"context"
	"fmt"
	"time"

	"github.com/DataDog/datadog-agent/pkg/networkpath/traceroute/common"
)

// Traceroute runs a TCP traceroute
func (t *TCPv4) Traceroute(driverParams Params) (*common.Results, error) {
	driver, err := t.getTracerouteDriver(driverParams)
	if err != nil {
		return nil, err
	}

	commonParams := common.TracerouteParams{
		MinTTL:            t.MinTTL,
		MaxTTL:            t.MaxTTL,
		TracerouteTimeout: t.Timeout,
		PollFrequency:     100 * time.Millisecond,
		SendDelay:         t.Delay,
	}
	var resp []*common.ProbeResponse
	if t.CompatibilityMode {
		params := common.TracerouteSerialParams{
			TracerouteParams: commonParams,
		}
		resp, err = common.TracerouteSerial(context.Background(), driver, params)
		if err != nil {
			return nil, err
		}
	} else {
		params := common.TracerouteParallelParams{
			TracerouteParams: commonParams,
		}
		ctx := context.Background()
		resp, err = common.TracerouteParallel(ctx, driver, params)
		if err != nil {
			return nil, err
		}
	}

	hops, err := common.ToHops(commonParams, resp)
	if err != nil {
		return nil, fmt.Errorf("SYN traceroute ToHops failed: %w", err)
	}

	result := &common.Results{
		Source:     t.srcIP,
		SourcePort: t.srcPort,
		Target:     t.Target,
		DstPort:    t.DestPort,
		Hops:       hops,
		Tags:       []string{"tcp_method:syn", fmt.Sprintf("tcp_compatibility_mode:%t", t.CompatibilityMode)},
	}

	return result, nil
}
