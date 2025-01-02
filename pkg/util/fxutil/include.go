// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package fxutil

import (
	"go.uber.org/fx"
)

// Include ensures that the specific component is always constructed
// Convenient for components that have no public interface but instead
// add functionality by merely being instantiated
func Include[T any]() fx.Option {
	return fx.Invoke(func(_ T) {})
}
