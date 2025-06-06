// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build test

package npcollectorimpl

import (
	model "github.com/DataDog/agent-payload/v5/process"
	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

// MockModule defines the fx options for the mock component.
func MockModule() fxutil.Module {
	return fxutil.Component(
		fx.Provide(newMock),
	)
}

type npCollectorMock struct{}

func (s *npCollectorMock) ScheduleConns(_ []*model.Connection, _ map[string]*model.DNSEntry) {
	panic("implement me")
}

func newMock() provides {
	// Mock initialization
	return provides{
		Comp: &npCollectorMock{},
	}
}
