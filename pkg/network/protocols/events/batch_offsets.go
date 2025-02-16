// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

// Package events contains implementation to unify perf-map communication between kernel and user space.
package events

import (
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"sync"
)

// offsetManager is responsible for keeping track of which chunks of data we
// have consumed from each batch object
type offsetManager struct {
	mux        sync.Mutex
	stateByCPU []*cpuReadState
}

type cpuReadState struct {
	// this is the nextBatchID we're expecting for a particular CPU core. we use
	// this when we attempt to retrieve data that hasn't been sent from kernel space
	// yet because it belongs to an incomplete batch.
	nextBatchID int

	// information associated to partial batch reads
	partialBatchID int
	partialOffset  int
	lastGeneration uint64
}

func newOffsetManager(numCPUS int) *offsetManager {
	stateByCPU := make([]*cpuReadState, numCPUS)
	for i := range stateByCPU {
		stateByCPU[i] = new(cpuReadState)
	}

	return &offsetManager{stateByCPU: stateByCPU}
}

// Get returns the data offset that hasn't been consumed yet for a given batch
func (o *offsetManager) Get(cpu int, batch *Batch, syncing bool, id string) (begin, end int) {
	o.mux.Lock()
	defer o.mux.Unlock()
	state := o.stateByCPU[cpu]
	batchID := int(batch.Idx)

	log.Infof("[USM] Get called: cpu=%d, batchID=%d, batchLen=%d, generation=%d, syncing=%v, id=%s | State for cpu %d: nextBatchID=%d, partialBatchID=%d, partialOffset=%d, lastGeneration=%d",
		cpu, batchID, batch.Len, batch.Generation, syncing, id, cpu, state.nextBatchID, state.partialBatchID,
		state.partialOffset, state.lastGeneration)

	if batchID < state.nextBatchID {
		// we have already consumed this data
		log.Infof("[USM] Skipping batch: batchID %d is less than nextBatchID %d, id=%s", batchID, state.nextBatchID, id)
		return 0, 0
	}

	if batchComplete(batch) {
		log.Infof("[USM] Batch complete: updating nextBatchID to %d, id %s", state.nextBatchID, id)
		state.nextBatchID = batchID + 1
	}

	// Reset partial offset if generation has changed
	if int(batch.Idx) == state.partialBatchID && batch.Generation != state.lastGeneration {
		log.Infof("[USM] Generation changed from %d to %d, resetting partial offset for id=%s",
			state.lastGeneration, batch.Generation, id)
		state.partialOffset = 0
	}

	// determining the begin offset
	begin = 0
	if int(batch.Idx) == state.partialBatchID {
		if state.partialOffset > int(batch.Len) {
			log.Infof("[USM] Resetting stale offset: was %d but batch.Len is %d, id=%s",
				state.partialOffset, batch.Len, id)
			state.partialOffset = 0
		}
		begin = state.partialOffset
		log.Infof("[USM] Partial batch detected: setting begin offset to %d, for id=%s", begin, id)
	}

	// determining the end offset
	end = int(batch.Len)
	log.Infof("[USM] End offset set to: %d for id=%s", end, id)

	// Update state for syncing operations
	if syncing {
		state.partialBatchID = int(batch.Idx)
		state.partialOffset = end
		state.lastGeneration = batch.Generation
		log.Infof("[USM] Syncing: updating partialBatchID to %d, partialOffset to %d, and generation to %d for id=%s",
			state.partialBatchID, state.partialOffset, state.lastGeneration, id)
	}

	return
}

func (o *offsetManager) NextBatchID(cpu int) int {
	o.mux.Lock()
	defer o.mux.Unlock()

	return o.stateByCPU[cpu].nextBatchID
}

func batchComplete(b *Batch) bool {
	return b.Cap > 0 && b.Len == b.Cap
}
