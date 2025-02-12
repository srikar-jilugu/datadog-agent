// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build test

package taggerimpl

// team: container-platform

import (
	taggermock "github.com/DataDog/datadog-agent/comp/core/tagger/mock"
)

// MockStore is a store designed to be used in unit tests
type taggerMock struct {
	*TaggerWrapper
}

// NewTaggerMock returns a Mock
func NewTaggerMock(req Requires) taggermock.Mock {
	taggerComp, _ := NewComponent(req)
	t := &taggerMock{
		TaggerWrapper: taggerComp.Comp.(*TaggerWrapper),
	}
	return t
}
