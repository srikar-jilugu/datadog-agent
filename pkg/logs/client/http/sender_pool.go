// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package http provides an HTTP destination for logs.
package http

import (
	"time"

	"github.com/benbjohnson/clock"

	"github.com/DataDog/datadog-agent/pkg/logs/client"
	"github.com/DataDog/datadog-agent/pkg/logs/metrics"
)

const (
	ewmaAlpha                           = 0.064
	concurrentSendersEwmaSampleInterval = 1 * time.Second
)

// SenderPool is an interface for managing the concurrency of senders.
type SenderPool interface {
	// Perform an operation with the sender concurrency implementation.
	Run(func())
}

// limitedSenderPool is a senderPool implementation that limits the number of concurrent senders.
type limitedSenderPool struct {
	pool chan struct{}
}

// NewLimitedMaxSenderPool returns a new senderPool implementation that limits the number of concurrent senders.
func NewLimitedMaxSenderPool(maxWorkers int) SenderPool {
	if maxWorkers <= 0 {
		maxWorkers = 1
	}
	return &limitedSenderPool{
		pool: make(chan struct{}, maxWorkers),
	}
}

func (l *limitedSenderPool) Run(doWork func()) {
	l.pool <- struct{}{}
	go func() {
		doWork()
		<-l.pool
	}()
}

type latencyThrottledSenderPool struct {
	pool                     chan struct{}
	clock                    clock.Clock
	virtualLatency           float64
	inUseSenders             int
	targetVirtualLatency     float64
	maxWorkers               int
	virtualLatencyLastSample time.Time
	destMeta                 *client.DestinationMetadata
}

// NewLatencyThrottledSenderPool returns a new senderPool implementation that limits the number of concurrent senders.
func NewLatencyThrottledSenderPool(maxWorkers int, targetLatency float64, destMeta *client.DestinationMetadata) SenderPool {
	return newLatencyThrottledSenderPoolWithClick(clock.New(), maxWorkers, targetLatency, destMeta)
}

func newLatencyThrottledSenderPoolWithClick(clock clock.Clock, maxWorkers int, targetLatency float64, destMeta *client.DestinationMetadata) *latencyThrottledSenderPool {
	if maxWorkers <= 0 {
		maxWorkers = 1
	}
	sp := &latencyThrottledSenderPool{
		pool:                 make(chan struct{}, maxWorkers),
		clock:                clock,
		maxWorkers:           maxWorkers,
		targetVirtualLatency: targetLatency,
		inUseSenders:         1,
		destMeta:             destMeta,
	}
	// Start with 1 sender
	sp.pool <- struct{}{}
	return sp
}

func (l *latencyThrottledSenderPool) Run(doWork func()) {
	now := l.clock.Now()
	<-l.pool
	go func() {
		doWork()
		l.pool <- struct{}{}
	}()
	l.resizePoolIfNeeded(now)
}

// Concurrency is scaled by attempting to converge on a target virtual latency.
// Virtual latency is the amount of time it takes to submit a payload to the sender pool.
// If Latency is above the target, more senders are added to the pool until the virtual latency is reached.
// This ensures the payload egress rate remains fair no matter how long the HTTP transaction takes
// (up to maxConcurrentBackgroundSends)
func (l *latencyThrottledSenderPool) resizePoolIfNeeded(then time.Time) {
	// Update the virtual latency every sample interval - an EWMA sampled every 1 second.
	since := l.clock.Since(l.virtualLatencyLastSample)
	if since >= concurrentSendersEwmaSampleInterval {
		latency := float64(l.clock.Since(then).Milliseconds())
		l.virtualLatency = l.virtualLatency*(1.0-ewmaAlpha) + (latency * ewmaAlpha)
		l.virtualLatencyLastSample = l.clock.Now()
	}

	// If the virtual latency is above the target, add a sender to the pool.
	if l.virtualLatency > l.targetVirtualLatency && l.inUseSenders < l.maxWorkers {
		l.pool <- struct{}{}
		l.inUseSenders++

	} else if l.inUseSenders > 1 {
		// else if the virtual latency is below the target, remove a sender from the pool if there are more than 1.
		<-l.pool
		l.inUseSenders--
	}
	metrics.TlmNumSenders.Set(float64(l.inUseSenders), l.destMeta.TelemetryName())
	metrics.TlmVirtualLatency.Set(l.virtualLatency, l.destMeta.TelemetryName())
}
