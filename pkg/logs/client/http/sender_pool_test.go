// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package http

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/pkg/logs/client"
)

func TestLatencyThrottledSenderLowLatencyOneWorker(t *testing.T) {
	pool := newLatencyThrottledSenderPoolWithClick(10*time.Millisecond, 1, 100*time.Millisecond, client.NewNoopDestinationMetadata())

	for i := 0; i < 100; i++ {
		pool.Run(func() {
			time.Sleep(10 * time.Millisecond)
		})
	}

	require.InDelta(t, 10*time.Millisecond, pool.virtualLatency, float64(2*time.Millisecond))
}

func TestLatencyThrottledSenderPoolLowLatencyManyWorkers(t *testing.T) {
	pool := newLatencyThrottledSenderPoolWithClick(10*time.Millisecond, 10, 100*time.Millisecond, client.NewNoopDestinationMetadata())

	for i := 0; i < 100; i++ {
		pool.Run(func() {
			time.Sleep(10 * time.Millisecond)
		})
	}

	require.InDelta(t, 10*time.Millisecond, pool.virtualLatency, float64(2*time.Millisecond))
}

func TestLatencyThrottledSenderPoolScalesUpWorkersForHighLatency(t *testing.T) {
	pool := newLatencyThrottledSenderPoolWithClick(10*time.Millisecond, 10, 2*time.Millisecond, client.NewNoopDestinationMetadata())

	for i := 0; i < 1000; i++ {
		pool.Run(func() {
			time.Sleep(10 * time.Millisecond)
		})
	}
	// Should converge on virtual latency of 2ms
	require.InDelta(t, 2*time.Millisecond, pool.virtualLatency, float64(300*time.Microsecond))
}
