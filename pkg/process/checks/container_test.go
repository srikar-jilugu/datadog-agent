// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package checks

import (
	"fmt"
	"testing"

	model "github.com/DataDog/agent-payload/v5/process"
	"github.com/stretchr/testify/assert"
)

func TestChunkContainers(t *testing.T) {
	tests := []struct {
		name       string
		containers []*model.Container
		chunks     int
		expected   [][]*model.Container
	}{
		{
			name:       "empty containers",
			containers: []*model.Container{},
			chunks:     3,
			expected:   [][]*model.Container{},
		},
		{
			name: "invalid chunks count",
			containers: []*model.Container{
				{Id: "1", Tags: []string{"pod_name:pod1"}},
			},
			chunks:   0,
			expected: [][]*model.Container{},
		},
		{
			name: "more chunks than containers",
			containers: []*model.Container{
				{Id: "1", Tags: []string{"pod_name:pod1"}},
				{Id: "2", Tags: []string{"pod_name:pod2"}},
			},
			chunks: 5,
			expected: [][]*model.Container{
				{{Id: "1", Tags: []string{"pod_name:pod1"}}},
				{{Id: "2", Tags: []string{"pod_name:pod2"}}},
			},
		},
		{
			name: "all containers from same pod stay together",
			containers: []*model.Container{
				{Id: "1", Tags: []string{"pod_name:pod1"}},
				{Id: "2", Tags: []string{"pod_name:pod1"}},
				{Id: "3", Tags: []string{"pod_name:pod1"}},
				{Id: "4", Tags: []string{"pod_name:pod2"}},
				{Id: "5", Tags: []string{"pod_name:pod2"}},
				{Id: "6", Tags: []string{"pod_name:pod3"}},
			},
			chunks: 3,
			expected: [][]*model.Container{
				{
					{Id: "1", Tags: []string{"pod_name:pod1"}},
					{Id: "2", Tags: []string{"pod_name:pod1"}},
					{Id: "3", Tags: []string{"pod_name:pod1"}},
				},
				{
					{Id: "4", Tags: []string{"pod_name:pod2"}},
					{Id: "5", Tags: []string{"pod_name:pod2"}},
				},
				{
					{Id: "6", Tags: []string{"pod_name:pod3"}},
				},
			},
		},
		{
			name: "mix of grouped and ungrouped containers",
			containers: []*model.Container{
				// Pod 1 with 5 containers
				{Id: "1", Tags: []string{"pod_name:pod1"}},
				{Id: "2", Tags: []string{"pod_name:pod1"}},
				{Id: "3", Tags: []string{"pod_name:pod1"}},
				{Id: "4", Tags: []string{"pod_name:pod1"}},
				{Id: "5", Tags: []string{"pod_name:pod1"}},

				// Pod 2 with 4 containers
				{Id: "6", Tags: []string{"pod_name:pod2"}},
				{Id: "7", Tags: []string{"pod_name:pod2"}},
				{Id: "8", Tags: []string{"pod_name:pod2"}},
				{Id: "9", Tags: []string{"pod_name:pod2"}},

				// 3 ungrouped containers
				{Id: "10", Tags: []string{"other:tag"}},
				{Id: "11", Tags: []string{"other:tag2"}},
				{Id: "12", Tags: []string{"other:tag3"}},
			},
			chunks: 2,
			expected: [][]*model.Container{
				{
					{Id: "1", Tags: []string{"pod_name:pod1"}},
					{Id: "2", Tags: []string{"pod_name:pod1"}},
					{Id: "3", Tags: []string{"pod_name:pod1"}},
					{Id: "4", Tags: []string{"pod_name:pod1"}},
					{Id: "5", Tags: []string{"pod_name:pod1"}},
					{Id: "11", Tags: []string{"other:tag2"}},
				},
				{
					{Id: "6", Tags: []string{"pod_name:pod2"}},
					{Id: "7", Tags: []string{"pod_name:pod2"}},
					{Id: "8", Tags: []string{"pod_name:pod2"}},
					{Id: "9", Tags: []string{"pod_name:pod2"}},
					{Id: "10", Tags: []string{"other:tag"}},
					{Id: "12", Tags: []string{"other:tag3"}},
				},
			},
		},
		{
			name: "mostly ungrouped containers",
			containers: []*model.Container{
				{Id: "1", Tags: []string{"other:tag1"}},
				{Id: "2", Tags: []string{"other:tag2"}},
				{Id: "3", Tags: []string{"other:tag3"}},
				{Id: "4", Tags: []string{"other:tag4"}},
				{Id: "5", Tags: []string{"other:tag5"}},
				{Id: "6", Tags: []string{"pod_name:pod1"}},
				{Id: "7", Tags: []string{"pod_name:pod1"}},
			},
			chunks: 3,
			expected: [][]*model.Container{
				{
					{Id: "6", Tags: []string{"pod_name:pod1"}},
					{Id: "7", Tags: []string{"pod_name:pod1"}},
					{Id: "5", Tags: []string{"other:tag5"}},
				},
				{
					{Id: "1", Tags: []string{"other:tag1"}},
					{Id: "3", Tags: []string{"other:tag3"}},
				},
				{
					{Id: "2", Tags: []string{"other:tag2"}},
					{Id: "4", Tags: []string{"other:tag4"}},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := chunkContainers(tc.containers, tc.chunks)
			fmt.Println(result)
			if tc.expected != nil {
				assert.True(t, areChunksEqual(tc.expected, result))
			}
		})
	}
}

func areChunksEqual(a, b [][]*model.Container) bool {
	if len(a) != len(b) {
		fmt.Printf("Different array lengths: expected %d, got %d\n", len(a), len(b))
		return false
	}

	for i := range a {
		if len(a[i]) != len(b[i]) {
			fmt.Printf("Different chunk lengths: expected %d, got %d\n", len(a[i]), len(b[i]))
			return false
		}
		for j := range a[i] {
			if a[i][j].Id != b[i][j].Id {
				fmt.Printf("Different container IDs: expected %s, got %s\n", a[i][j].Id, b[i][j].Id)
				return false
			}
		}
	}

	return true
}
