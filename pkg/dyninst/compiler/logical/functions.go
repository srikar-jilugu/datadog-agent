// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package logical

import (
	"fmt"

	"github.com/DataDog/datadog-agent/pkg/dyninst/ir"
)

type FunctionID interface {
	logicalFuncID() // marker

	PrettyString() string
}

// Implements interface marker.
type baseFunctionID struct{}

func (baseFunctionID) logicalFuncID() {}

// Global, unique functions.
type ChasePointers struct {
	baseFunctionID
}

func (ChasePointers) PrettyString() string {
	return "ChasePointers"
}

// Process user function event (call, line, etc..), at given injection PC.
type ProcessEvent struct {
	baseFunctionID
	EventRootType *ir.EventRootType
	InjectionPC   uint64
}

func (e ProcessEvent) PrettyString() string {
	return fmt.Sprintf("ProcessEvent[%s@%x]", e.EventRootType.GetName(), e.InjectionPC)
}

// Run expression evaluation from a context of event function frame, at given
// injection PC.
type ProcessExpression struct {
	baseFunctionID
	EventRootType *ir.EventRootType
	// The index of the expression in the event root type.
	ExprIdx     int
	InjectionPC uint64
}

func (e ProcessExpression) PrettyString() string {
	return fmt.Sprintf("ProcessExpression[%s@%x.expr[%d]]", e.EventRootType.GetName(), e.InjectionPC, e.ExprIdx)
}

// Process user data of a specific type, chasing pointers, resolving interfaces,
// etc (after the data was already read into ringbuf). The generated function
// expects output offset to be set to the beginning of the data.
type ProcessType struct {
	baseFunctionID
	Type ir.Type
}

func (e ProcessType) PrettyString() string {
	return fmt.Sprintf("ProcessType[%s]", e.Type.GetName())
}
