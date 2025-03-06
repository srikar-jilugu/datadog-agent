// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf && test

package telemetry

// HelperErrorsMap represents the collected helper errors in a simple Go map.
type HelperErrorsMap map[string]map[string]uint64

// TestEBPFErrorsCollector wraps EBPFErrorsCollector for testing purposes.
type TestEBPFErrorsCollector struct {
	collector *EBPFErrorsCollector // Contained instance
}

// NewTestEBPFErrorsCollector creates a new TestEBPFErrorsCollector instance.
func NewTestEBPFErrorsCollector() *TestEBPFErrorsCollector {
	return &TestEBPFErrorsCollector{
		collector: NewEBPFErrorsCollector().(*EBPFErrorsCollector),
	}
}

// GetHelperErrorsMap collects and returns the helper errors map for testing.
func (t *TestEBPFErrorsCollector) GetHelperErrorsMap() HelperErrorsMap {
	t.collector.t.Lock() // Accessing the internal EBPFErrorsCollector
	defer t.collector.t.Unlock()

	helperErrors := make(HelperErrorsMap)

	if !t.collector.t.isInitialized() {
		return helperErrors
	}

	t.collector.t.ForEachHelperErrorEntryInMaps(func(tKey TelemetryKey, eBPFKey uint64, val helperErrTelemetry) bool {
		for i, helperName := range helperNames {
			base := maxErrno * i
			if count := getErrCount(val.Count[base : base+maxErrno]); len(count) > 0 {
				if _, exists := helperErrors[helperName]; !exists {
					helperErrors[helperName] = make(map[string]uint64)
				}
				for errStr, errCount := range count {
					helperErrors[helperName][errStr] += errCount
				}
			}
		}
		return true
	})

	return helperErrors
}
