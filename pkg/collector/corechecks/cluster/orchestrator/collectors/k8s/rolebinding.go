// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver && orchestrator

package k8s

import (
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/collectors"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/processors"
	k8sProcessors "github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/processors/k8s"
	"github.com/DataDog/datadog-agent/pkg/config/utils"
	"github.com/DataDog/datadog-agent/pkg/orchestrator"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes"

	"k8s.io/apimachinery/pkg/labels"
	rbacv1Informers "k8s.io/client-go/informers/rbac/v1"
	rbacv1Listers "k8s.io/client-go/listers/rbac/v1"
	"k8s.io/client-go/tools/cache"
)

// NewRoleBindingCollectorVersions builds the group of collector versions.
func NewRoleBindingCollectorVersions(metadataAsTags utils.MetadataAsTags) collectors.CollectorVersions {
	return collectors.NewCollectorVersions(
		NewRoleBindingCollector(metadataAsTags),
	)
}

// RoleBindingCollector is a collector for Kubernetes RoleBindings.
type RoleBindingCollector struct {
	informer  rbacv1Informers.RoleBindingInformer
	lister    rbacv1Listers.RoleBindingLister
	metadata  *collectors.CollectorMetadata
	processor *processors.Processor
}

// NewRoleBindingCollector creates a new collector for the Kubernetes
// RoleBinding resource.
func NewRoleBindingCollector(metadataAsTags utils.MetadataAsTags) *RoleBindingCollector {
	resourceType := getResourceType(roleBindingName, roleBindingVersion)
	labelsAsTags := metadataAsTags.GetResourcesLabelsAsTags()[resourceType]
	annotationsAsTags := metadataAsTags.GetResourcesAnnotationsAsTags()[resourceType]

	return &RoleBindingCollector{
		metadata: &collectors.CollectorMetadata{
			IsDefaultVersion:                     true,
			IsStable:                             true,
			IsMetadataProducer:                   true,
			IsManifestProducer:                   true,
			SupportsManifestBuffering:            true,
			Name:                                 roleBindingName,
			Kind:                                 kubernetes.RoleBindingKind,
			NodeType:                             orchestrator.K8sRoleBinding,
			Version:                              roleBindingVersion,
			LabelsAsTags:                         labelsAsTags,
			AnnotationsAsTags:                    annotationsAsTags,
			SupportsTerminatedResourceCollection: true,
		},
		processor: processors.NewProcessor(new(k8sProcessors.RoleBindingHandlers)),
	}
}

// Informer returns the shared informer.
func (c *RoleBindingCollector) Informer() cache.SharedInformer {
	return c.informer.Informer()
}

// Init is used to initialize the collector.
func (c *RoleBindingCollector) Init(rcfg *collectors.CollectorRunConfig) {
	c.informer = rcfg.OrchestratorInformerFactory.InformerFactory.Rbac().V1().RoleBindings()
	c.lister = c.informer.Lister()
}

// Metadata is used to access information about the collector.
func (c *RoleBindingCollector) Metadata() *collectors.CollectorMetadata {
	return c.metadata
}

// Run triggers the collection process.
func (c *RoleBindingCollector) Run(rcfg *collectors.CollectorRunConfig) (*collectors.CollectorRunResult, error) {
	list, err := c.lister.List(labels.Everything())
	if err != nil {
		return nil, collectors.NewListingError(err)
	}

	return c.Process(rcfg, list)
}

// Process is used to process the list of resources and return the result.
func (c *RoleBindingCollector) Process(rcfg *collectors.CollectorRunConfig, list interface{}) (*collectors.CollectorRunResult, error) {
	ctx := collectors.NewK8sProcessorContext(rcfg, c.metadata)

	processResult, listed, processed := c.processor.Process(ctx, list)

	if processed == -1 {
		return nil, collectors.ErrProcessingPanic
	}

	result := &collectors.CollectorRunResult{
		Result:             processResult,
		ResourcesListed:    listed,
		ResourcesProcessed: processed,
	}

	return result, nil
}
