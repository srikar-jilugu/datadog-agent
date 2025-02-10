// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver

package autoinstrumentation

import (
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/util"
	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	"github.com/DataDog/datadog-agent/pkg/clusteragent/admission/metrics"
	mutatecommon "github.com/DataDog/datadog-agent/pkg/clusteragent/admission/mutate/common"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// TargetProcessor filters and mutates pods based on a set of targeting rules. It implments both the Mutator and
// the MutationFilter interfaces so that it can be used for both use cases.
type TargetProcessor struct {
	targets            []targetInternal
	disabledNamespaces map[string]bool
}

// targetInternal is the struct we use to convert the config based target into
// something more performant to check against.
type targetInternal struct {
	name                 string
	podSelector          labels.Selector
	nameSpaceSelector    labels.Selector
	useNamespaceSelector bool
	enabledNamespaces    map[string]bool
	libVersions          []libInfo
	wmeta                workloadmeta.Component
}

// NewTargetProcessor creates a new TargetProcessor from a list of targets and disabled namespaces. We convert the
// targets into a more efficient internal format for quick lookups.
func NewTargetProcessor(targets []Target, wmeta workloadmeta.Component, disabledNamespaces []string, containerRegistry string) (*TargetProcessor, error) {
	// Create a map of disabled namespaces for quick lookups.
	disabledNamespacesMap := make(map[string]bool, len(disabledNamespaces))
	for _, ns := range disabledNamespaces {
		disabledNamespacesMap[ns] = true
	}

	// Convert the targets to internal format.
	internalTargets := make([]targetInternal, len(targets))
	for i, t := range targets {
		// Convert the pod selector to a label selector.
		podSelector, err := t.PodSelector.AsLabelSelector()
		if err != nil {
			return nil, fmt.Errorf("could not convert selector to label selector: %w", err)
		}

		// Determine if we should use the namespace selector or if we should use enabledNamespaces.
		useNamespaceSelector := len(t.NamespaceSelector.MatchLabels)+len(t.NamespaceSelector.MatchExpressions) > 0

		// Convert the namespace selector to a label selector.
		var namespaceSelector labels.Selector
		if useNamespaceSelector {
			namespaceSelector, err = t.NamespaceSelector.AsLabelSelector()
			if err != nil {
				return nil, fmt.Errorf("could not convert selector to label selector: %w", err)
			}
		}

		// Create a map of enabled namespaces for quick lookups.
		var enabledNamespaces map[string]bool
		if !useNamespaceSelector {
			enabledNamespaces = make(map[string]bool, len(t.NamespaceSelector.MatchNames))
			for _, ns := range t.NamespaceSelector.MatchNames {
				enabledNamespaces[ns] = true
			}
		}

		// Get the library versions to inject. If no versions are specified, we inject all libraries.
		var libVersions []libInfo
		if len(t.TracerVersions) == 0 {
			libVersions = getAllLatestDefaultLibraries(containerRegistry)
		} else {
			libVersions = getPinnedLibraries(t.TracerVersions, containerRegistry)
		}

		// Store the target in the internal format.
		internalTargets[i] = targetInternal{
			name:                 t.Name,
			podSelector:          podSelector,
			useNamespaceSelector: useNamespaceSelector,
			nameSpaceSelector:    namespaceSelector,
			wmeta:                wmeta,
			enabledNamespaces:    enabledNamespaces,
			libVersions:          libVersions,
		}
	}

	return &TargetProcessor{
		targets:            internalTargets,
		disabledNamespaces: disabledNamespacesMap,
	}, nil
}

// MutatePod implements the Mutator interface.
func (tp *TargetProcessor) MutatePod(pod *corev1.Pod, _ string, _ interface{}) (bool, error) {
	// Sanitize input.
	if pod == nil {
		return false, errors.New(metrics.InvalidInput)
	}

	// If the namespace is disabled, we should not mutate the pod.
	if _, ok := tp.disabledNamespaces[pod.Namespace]; ok {
		return false, nil
	}

	// The admission can be re-run for the same pod. Fast return if we injected the library already.
	for _, lang := range supportedLanguages {
		if containsInitContainer(pod, initContainerName(lang)) {
			log.Debugf("Init container %q already exists in pod %q", initContainerName(lang), mutatecommon.PodString(pod))
			return false, nil
		}
	}

	// Get the libraries to inject. If there are no libraries to inject, we should not mutate the pod.
	libraries := tp.getLibraries(pod)
	if len(libraries) == 0 {
		return false, nil
	}

	for _, mutator := range tp.securityClientLibraryPodMutators {
		if err := mutator.mutatePod(pod); err != nil {
			return false, fmt.Errorf("error mutating pod for security client: %w", err)
		}
	}

	for _, mutator := range tp.profilingClientLibraryPodMutators {
		if err := mutator.mutatePod(pod); err != nil {
			return false, fmt.Errorf("error mutating pod for profiling client: %w", err)
		}
	}

	// TODO: actually mutate the pod.

	return false, nil
}

// ShouldMutatePod implements the MutationFilter#ShouldMutatePod interface. This is used primarily in other mutators
// SSI relies on like the config or tags to labels mutators.
func (tp *TargetProcessor) ShouldMutatePod(pod *corev1.Pod) bool {
	// If the namespace is disabled, we should not mutate the pod.
	if _, ok := tp.disabledNamespaces[pod.Namespace]; ok {
		return false
	}
	// If there are no tracer libraries to inject, we should not mutate the pod.
	return len(tp.getTargetLibraries(pod)) > 0
}

// IsNamespaceEligible implements the MutationFilter#IsNamespaceEligible interface. Its currently only used by the
// enableNamespaces based flow and will likely not be used by SSI. We should look to refactor IsNamespaceEligible out of
// the interface.
func (tp *TargetProcessor) IsNamespaceEligible(namespace string) bool {
	// If the namespace is disabled, we should not mutate the pod.
	if _, ok := tp.disabledNamespaces[namespace]; ok {
		return false
	}

	for _, target := range tp.targets {
		// Check the pod namespace against the namespace selector.
		matches, err := target.matchesNamespaceSelector(namespace)
		if err != nil {
			log.Errorf("error encountered matching targets, aborting all together to avoid inaccurate match: %v", err)
			return false

		}
		if matches {
			return true
		}
	}

	return false
}

func (tp *TargetProcessor) getLibraries(pod *corev1.Pod) []libInfo {
	// If the pod has explict tracer libraries defined as annotations, they take precedence.
	libraries := tp.getAnnotationLibraries(pod)
	if len(libraries) > 0 {
		return libraries
	}

	// If there are no annotations, check if the pod matches any of the targets.
	return tp.getTargetLibraries(pod)
}

// getAnnotationLibraries determines which tracing libraries to use given a pod's annotations. It returns the list of
// tracing libraries to inject.
func (tp *TargetProcessor) getAnnotationLibraries(pod *corev1.Pod) []libInfo {
	return extractLibrariesFromAnnotations(pod, tp.config.containerRegistry)
}

// getTargetLibraries determines which tracing libraries to use given a target list. It returns the list of tracing
// libraries to inject.
func (tp *TargetProcessor) getTargetLibraries(pod *corev1.Pod) []libInfo {
	// If the namespace is disabled, we should not mutate the pod.
	if _, ok := tp.disabledNamespaces[pod.Namespace]; ok {
		return nil
	}

	// Check if the pod matches any of the targets. The first match wins.
	for _, target := range tp.targets {
		// Check the pod namespace against the namespace selector.
		matches, err := target.matchesNamespaceSelector(pod.Namespace)
		if err != nil {
			log.Errorf("error encountered matching targets, aborting all together to avoid inaccurate match: %v", err)
			return nil

		}
		if !matches {
			continue
		}

		// Check the pod labels against the pod selector.
		if !target.matchesPodSelector(pod.Labels) {
			continue
		}

		// If the namespace and pod selector match, return the libraries to inject.
		return target.libVersions
	}

	// No target matched.
	return nil
}

func (ti targetInternal) matchesNamespaceSelector(namespace string) (bool, error) {
	// If we are using the namespace selector, check if the namespace matches the selector.
	if ti.useNamespaceSelector {
		// Get the namespace metadata.
		id := util.GenerateKubeMetadataEntityID("", "namespaces", "", namespace)
		ns, err := ti.wmeta.GetKubernetesMetadata(id)
		if err != nil {
			return false, fmt.Errorf("could not get kubernetes namespace to match against for %s: %w", namespace, err)
		}

		// Check if the namespace labels match the selector.
		return ti.nameSpaceSelector.Matches(labels.Set(ns.EntityMeta.Labels)), nil
	}

	// If there are no match names, we match all namespaces.
	if len(ti.enabledNamespaces) == 0 {
		return true, nil
	}

	// Check if the pod namespace is in the match names.
	_, ok := ti.enabledNamespaces[namespace]
	return ok, nil
}

func (ti targetInternal) matchesPodSelector(podLabels map[string]string) bool {
	return ti.podSelector.Matches(labels.Set(podLabels))
}
