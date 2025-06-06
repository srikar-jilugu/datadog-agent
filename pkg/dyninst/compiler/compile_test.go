// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package compiler

import (
	"testing"
)

func TestCompileBPFProgram(t *testing.T) {
	err := CompileBPFProgram()
	if err != nil {
		t.Fatalf("Failed to compile BPF program: %v", err)
	}
}
