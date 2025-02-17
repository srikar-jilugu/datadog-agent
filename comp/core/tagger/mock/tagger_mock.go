// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build test

package mock

// team: container-platform

import (
	"context"

	tagger "github.com/DataDog/datadog-agent/comp/core/tagger/def"
	"github.com/DataDog/datadog-agent/comp/core/tagger/origindetection"
	"github.com/DataDog/datadog-agent/comp/core/tagger/tagstore"
	"github.com/DataDog/datadog-agent/comp/core/tagger/telemetry"
	"github.com/DataDog/datadog-agent/comp/core/tagger/types"
	taggertypes "github.com/DataDog/datadog-agent/pkg/tagger/types"
	"github.com/DataDog/datadog-agent/pkg/tagset"
)

// taggerMock is a mock implementation of the tagger component.
type taggerMock struct {
	tagStore *tagstore.TagStore
}

// NewTaggerMock returns a Mock
func NewTaggerMock() Provides {
	return Provides{
		Comp: &taggerMock{
			tagStore: tagstore.NewTagStore(nil),
		},
	}
}

// Mock interface

// SetTags allows to set tags in store for a given source, entity
func (t *taggerMock) SetTags(entityID types.EntityID, source string, low, orch, high, std []string) {
	t.tagStore.ProcessTagInfo([]*types.TagInfo{
		{
			Source:               source,
			EntityID:             entityID,
			LowCardTags:          low,
			OrchestratorCardTags: orch,
			HighCardTags:         high,
			StandardTags:         std,
		},
	})
}

// SetGlobalTags allows to set tags in store for the global entity
func (t *taggerMock) SetGlobalTags(low, orch, high, std []string) {
	t.SetTags(types.GetGlobalEntityID(), "static", low, orch, high, std)
}

func (t *taggerMock) GetTagStore() *tagstore.TagStore {
	return t.tagStore
}

// Tagger interface

func (t *taggerMock) Start(context.Context) error {
	return nil
}

func (t *taggerMock) Stop() error {
	return nil
}

func (t *taggerMock) ReplayTagger() tagger.ReplayTagger {
	return nil
}

func (t *taggerMock) GetTaggerTelemetryStore() *telemetry.Store {
	return nil
}

func (t *taggerMock) Tag(entityID types.EntityID, cardinality types.TagCardinality) ([]string, error) {
	tags := t.tagStore.Lookup(entityID, cardinality)
	return tags, nil
}

func (t *taggerMock) LegacyTag(string, types.TagCardinality) ([]string, error) {
	return nil, nil
}

// GenerateContainerIDFromOriginInfo generates a container ID from Origin Info.
// This is a no-op for the noop tagger
func (t *taggerMock) GenerateContainerIDFromOriginInfo(origindetection.OriginInfo) (string, error) {
	return "", nil
}

func (t *taggerMock) AccumulateTagsFor(types.EntityID, types.TagCardinality, tagset.TagsAccumulator) error {
	return nil
}

func (t *taggerMock) Standard(types.EntityID) ([]string, error) {
	return nil, nil
}

func (t *taggerMock) List() types.TaggerListResponse {
	return types.TaggerListResponse{}
}

func (t *taggerMock) GetEntity(types.EntityID) (*types.Entity, error) {
	return nil, nil
}

func (t *taggerMock) Subscribe(string, *types.Filter) (types.Subscription, error) {
	return nil, nil
}

func (t *taggerMock) GetEntityHash(types.EntityID, types.TagCardinality) string {
	return ""
}

func (t *taggerMock) AgentTags(types.TagCardinality) ([]string, error) {
	return nil, nil
}

func (t *taggerMock) GlobalTags(types.TagCardinality) ([]string, error) {
	return nil, nil
}

func (t *taggerMock) SetNewCaptureTagger(tagger.Component) {}

func (t *taggerMock) ResetCaptureTagger() {}

func (t *taggerMock) EnrichTags(tagset.TagsAccumulator, taggertypes.OriginInfo) {}

func (t *taggerMock) ChecksCardinality() types.TagCardinality {
	return types.LowCardinality
}

func (t *taggerMock) DogstatsdCardinality() types.TagCardinality {
	return types.LowCardinality
}
