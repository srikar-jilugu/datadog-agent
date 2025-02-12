// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build test

// Package mock contains the implementation of the mock for the tagger component.
package mock

import (
	tagger "github.com/DataDog/datadog-agent/comp/core/tagger/def"
)

// Mock implements mock-specific methods.
type Mock interface {
	tagger.Component
}
