// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package compiler

import (
	"testing"

	"github.com/DataDog/datadog-agent/pkg/dyninst/ir"
	"github.com/DataDog/datadog-agent/pkg/network/go/bininspect"
)

func TestCompileBPFProgram(t *testing.T) {
	pointee := &ir.BaseType{
		TypeCommon: ir.TypeCommon{
			ID:   4,
			Name: "int",
			Size: 4,
		},
	}
	pointer := &ir.PointerType{
		TypeCommon: ir.TypeCommon{
			ID:   3,
			Name: "*int",
			Size: 8,
		},
		Pointee: pointee,
	}
	sp := &ir.Subprogram{
		Name:              "CoolButBuggyFunction",
		OutOfLinePCRanges: []ir.PCRange{},
		InlinePCRanges:    [][]ir.PCRange{},
		Variables: []ir.Variable{
			{
				Name: "BadVar",
				Type: pointer,
				Locations: []ir.Location{
					{
						Range: ir.PCRange{
							Start: 1000,
							End:   1200,
						},
						Pieces: []bininspect.ParameterPiece{
							{
								Size:        8,
								InReg:       false,
								StackOffset: 12,
								Register:    -1,
							},
						},
					},
				},
				IsParameter: false,
			},
		},
		Lines: []ir.SubprogramLine{},
	}
	p := ir.Program{
		ID: 123,
		Probes: []*ir.Probe{
			{
				ID:         "UUID1",
				Type:       ir.ProbeKindLog,
				Version:    7,
				Tags:       nil,
				Subprogram: sp,
				Events: []ir.Event{
					{
						ID: 456,
						Type: &ir.EventRootType{
							TypeCommon: ir.TypeCommon{
								ID:   10,
								Name: "CoolButBuggyFunction",
								Size: 0,
							},
							PresenseBitsetSize: 0,
							Expressions: []ir.RootExpression{
								{
									Name:   "BadVar",
									Offset: 0,
									Expression: ir.Expression{
										Type: pointee,
										Operations: []ir.Op{
											&ir.LocationOp{
												Variable: &sp.Variables[0],
												Offset:   0,
												Size:     4,
											},
										},
									},
								},
							},
						},
						InjectionPCs: []uint64{1100},
						Condition:    nil,
					},
				},
			},
		},
		Subprograms: []*ir.Subprogram{sp},
		Types:       []ir.Type{pointer, pointee},
		MaxTypeID:   132,
	}
	err := CompileBPFProgram(p)
	if err != nil {
		t.Fatalf("Failed to compile BPF program: %v", err)
	}
}
