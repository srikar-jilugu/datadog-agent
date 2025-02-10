// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver

package common

// MutatorFilter combines both interfaces so that a single struct can be used to both mutate and filter pods.
type MutatorFilter interface {
	Mutator
	MutationFilter
}
