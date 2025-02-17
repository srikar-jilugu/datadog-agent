// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build test

// Package mock contains the implementation of the mock for the tagger component.
package mock

import (
	tagger "github.com/DataDog/datadog-agent/comp/core/tagger/def"
	"github.com/DataDog/datadog-agent/comp/core/tagger/tagstore"
	"github.com/DataDog/datadog-agent/comp/core/tagger/types"
	"testing"

	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

// Provides is a struct containing the mock and the endpoint
type Provides struct {
	Comp Mock
}

// Mock implements mock-specific methods for the tagger component.
type Mock interface {
	tagger.Component

	// GetTagStore returns the tag store
	GetTagStore() *tagstore.TagStore

	// SetTags allows to set tags in the mock fake tagger
	SetTags(entityID types.EntityID, source string, low, orch, high, std []string)

	// SetGlobalTags allows to set tags in store for the global entity
	SetGlobalTags(low, orch, high, std []string)
}

// TODO (wassim): Remove old mock

// Module is a module containing the mock, useful for testing
func Module() fxutil.Module {
	return fxutil.Component(
		fxutil.ProvideComponentConstructor(New),
	)
}

// SetupFakeTagger calls fxutil.Test to create a mock tagger for testing
func SetupFakeTagger(t testing.TB) Mock {
	return fxutil.Test[Mock](t, Module())
}
