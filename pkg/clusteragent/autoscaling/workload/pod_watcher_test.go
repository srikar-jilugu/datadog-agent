// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver

package workload

import (
	"context"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/comp/core/config"
	log "github.com/DataDog/datadog-agent/comp/core/log/def"
	logmock "github.com/DataDog/datadog-agent/comp/core/log/mock"
	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	workloadmetafxmock "github.com/DataDog/datadog-agent/comp/core/workloadmeta/fx-mock"
	workloadmetamock "github.com/DataDog/datadog-agent/comp/core/workloadmeta/mock"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
)

func TestHandleSetEvent(t *testing.T) {
	pw := NewPodWatcher(nil, nil)
	pod := &workloadmeta.KubernetesPod{
		EntityID: workloadmeta.EntityID{
			Kind: workloadmeta.KindKubernetesPod,
			ID:   "p1",
		},
		EntityMeta: workloadmeta.EntityMeta{
			Name:      "pod1",
			Namespace: "default",
		},
		Owners: []workloadmeta.KubernetesPodOwner{{Kind: kubernetes.ReplicaSetKind, Name: "deploymentName-766dbb7846"}},
		Ready:  true,
	}
	event := workloadmeta.Event{
		Type:   workloadmeta.EventTypeSet,
		Entity: pod,
	}

	pw.HandleEvent(event)

	expectedOwner := NamespacedPodOwner{
		Namespace: "default",
		Kind:      kubernetes.DeploymentKind,
		Name:      "deploymentName",
	}
	pods := pw.GetPodsForOwner(expectedOwner)
	require.Len(t, pods, 1)
	assert.Equal(t, pod, pods[0])

	numReadyPods := pw.GetReadyPodsForOwner(expectedOwner)
	assert.Equal(t, int32(1), numReadyPods)
}

func TestHandleUnsetEvent(t *testing.T) {
	pw := NewPodWatcher(nil, nil)
	pod := &workloadmeta.KubernetesPod{
		EntityID: workloadmeta.EntityID{
			Kind: workloadmeta.KindKubernetesPod,
			ID:   "p1",
		},
		EntityMeta: workloadmeta.EntityMeta{
			Name:      "pod1",
			Namespace: "default",
		},
		Owners: []workloadmeta.KubernetesPodOwner{{Kind: kubernetes.ReplicaSetKind, Name: "deploymentName-766dbb7846"}},
		Ready:  true,
	}
	setEvent := workloadmeta.Event{
		Type:   workloadmeta.EventTypeSet,
		Entity: pod,
	}
	unsetEvent := workloadmeta.Event{
		Type:   workloadmeta.EventTypeUnset,
		Entity: pod,
	}

	expectedOwner := NamespacedPodOwner{
		Namespace: "default",
		Kind:      kubernetes.DeploymentKind,
		Name:      "deploymentName",
	}

	pw.HandleEvent(setEvent)

	numReadyPods := pw.GetReadyPodsForOwner(expectedOwner)
	assert.Equal(t, int32(1), numReadyPods)

	pw.HandleEvent(unsetEvent)

	pods := pw.GetPodsForOwner(expectedOwner)
	assert.Nil(t, pods)
	assert.NotNil(t, pw.podsPerPodOwner)

	numReadyPods = pw.GetReadyPodsForOwner(expectedOwner)
	assert.Equal(t, int32(0), numReadyPods)
}

func TestPodWatcherStartStop(t *testing.T) {
	wlm := fxutil.Test[workloadmetamock.Mock](t, fx.Options(
		fx.Provide(func() log.Component { return logmock.New(t) }),
		config.MockModule(),
		fx.Supply(context.Background()),
		workloadmetafxmock.MockModule(workloadmeta.NewParams()),
	))
	pw := NewPodWatcher(wlm, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go pw.Run(ctx)
	pod := &workloadmeta.KubernetesPod{
		EntityID: workloadmeta.EntityID{
			Kind: workloadmeta.KindKubernetesPod,
			ID:   "p1",
		},
		EntityMeta: workloadmeta.EntityMeta{
			Name:      "pod1",
			Namespace: "default",
		},
		Owners: []workloadmeta.KubernetesPodOwner{{Kind: kubernetes.ReplicaSetKind, Name: "deploymentName-766dbb7846"}},
		Ready:  false,
	}

	wlm.Set(pod)

	expectedOwner := NamespacedPodOwner{
		Namespace: "default",
		Kind:      kubernetes.DeploymentKind,
		Name:      "deploymentName",
	}

	assert.Eventuallyf(t, func() bool {
		pods := pw.GetPodsForOwner(expectedOwner)
		return pods != nil
	}, 5*time.Second, 200*time.Millisecond, "expected pod to be added to the pod watcher")
	newPods := pw.GetPodsForOwner(expectedOwner)
	require.Len(t, newPods, 1)
	assert.Equal(t, pod, newPods[0])
	cancel()

	numReadyPods := pw.GetReadyPodsForOwner(expectedOwner)
	assert.Equal(t, int32(0), numReadyPods)
	_, ok := pw.readyPodsPerPodOwner[expectedOwner]
	assert.False(t, ok)
}

func TestGetNamespacedPodOwner(t *testing.T) {
	for _, tt := range []struct {
		name     string
		ns       string
		owner    *workloadmeta.KubernetesPodOwner
		expected NamespacedPodOwner
		err      error
	}{
		{
			name: "pod owned by deployment",
			ns:   "default",
			owner: &workloadmeta.KubernetesPodOwner{
				Kind: kubernetes.ReplicaSetKind,
				Name: "datadog-agent-linux-cluster-agent-f64dd88",
			},
			expected: NamespacedPodOwner{
				Namespace: "default",
				Kind:      kubernetes.DeploymentKind,
				Name:      "datadog-agent-linux-cluster-agent",
			},
		},
		{
			name: "pod owned by daemonset",
			ns:   "default",
			owner: &workloadmeta.KubernetesPodOwner{
				Kind: kubernetes.DaemonSetKind,
				Name: "datadog-agent-f64dd88",
			},
			expected: NamespacedPodOwner{
				Namespace: "default",
				Kind:      kubernetes.DaemonSetKind,
				Name:      "datadog-agent-f64dd88",
			},
		},
		{
			name: "pod owned by replica set",
			ns:   "default",
			owner: &workloadmeta.KubernetesPodOwner{
				Kind: kubernetes.ReplicaSetKind,
				Name: "datadog-agent-linux-cluster-agent",
			},
			expected: NamespacedPodOwner{
				Namespace: "default",
				Kind:      kubernetes.ReplicaSetKind,
				Name:      "datadog-agent-linux-cluster-agent",
			},
		},
		{
			name: "pod owned by deployment directly",
			ns:   "default",
			owner: &workloadmeta.KubernetesPodOwner{
				Kind: kubernetes.DeploymentKind,
				Name: "datadog-agent-linux-cluster-agent",
			},
			expected: NamespacedPodOwner{
				Namespace: "default",
				Kind:      kubernetes.ReplicaSetKind,
				Name:      "datadog-agent-linux-cluster-agent",
			},
			err: errDeploymentNotValidOwner,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			res, err := getNamespacedPodOwner(tt.ns, tt.owner)
			if tt.err != nil {
				assert.Equal(t, tt.err, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, res)
			}
		})
	}
}
