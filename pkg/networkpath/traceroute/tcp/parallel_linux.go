// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build linux

package tcp

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/DataDog/datadog-agent/pkg/networkpath/traceroute/common"
)

func (t *TCPv4) TracerouteParallel(ctx context.Context, parallelParams common.TracerouteParallelParams) (*common.Results, error) {
	targetAddr, ok := netip.AddrFromSlice(t.Target)
	if !ok {
		return nil, fmt.Errorf("invalid target address: %s", t.Target)
	}
	driver, err := NewDriver(ctx, netip.AddrPortFrom(targetAddr, t.DestPort))
	if err != nil {
		return nil, fmt.Errorf("failed to create TCP driver: %w", err)
	}
	defer driver.Close()
	responses, err := common.TracerouteParallel(ctx, driver, parallelParams)
	if err != nil {
		return nil, fmt.Errorf("tcp traceroute Parallel failed: %w", err)
	}

	hops, err := common.ToHops(parallelParams, responses)
	if err != nil {
		return nil, fmt.Errorf("tcp traceroute ToHops failed: %w", err)
	}

	result := &common.Results{
		Source:     t.srcIP,
		SourcePort: driver.localPort,
		Target:     t.Target,
		DstPort:    t.DestPort,
		Hops:       hops,
		Tags:       []string{"tcp_method:syn"},
	}
	return result, nil
}
