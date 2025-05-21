// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package codegen

import (
	"os"
	"testing"

	"github.com/DataDog/datadog-agent/pkg/dyninst/compiler/logical"
	"github.com/DataDog/datadog-agent/pkg/dyninst/ir"
)

func TestGenerateCode(t *testing.T) {
	fakePointee := &ir.BaseType{
		TypeCommon:       ir.TypeCommon{ID: 4, Name: "int", Size: 4},
		GoTypeAttributes: ir.GoTypeAttributes{},
	}
	functions := []logical.Function{
		{
			ID: logical.ProcessType{
				Type: &ir.PointerType{
					TypeCommon: ir.TypeCommon{
						ID:   3,
						Name: "*void",
						Size: 8,
					},
					GoTypeAttributes: ir.GoTypeAttributes{},
					Pointee:          fakePointee,
				},
			},
			Ops: []logical.Op{
				logical.ProcessPointerOp{
					Pointee: fakePointee,
				},
				logical.ReturnOp{},
			},
		},
		{
			ID: logical.ProcessType{
				Type: &ir.PointerType{
					TypeCommon: ir.TypeCommon{
						ID:   5,
						Name: "*int",
						Size: 8,
					},
					GoTypeAttributes: ir.GoTypeAttributes{},
					Pointee:          fakePointee,
				},
			},
			Ops: []logical.Op{
				logical.ProcessPointerOp{
					Pointee: fakePointee,
				},
				logical.ReturnOp{},
			},
		},
	}
	GenerateCode(logical.Program{Functions: functions}, os.Stdout)
}
