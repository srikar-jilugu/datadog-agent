// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// The Tagger is the central source of truth for client-side entity tagging.
// It subscribes to WorkloadMeta to get updates for all the entity kinds
// (containers, kubernetes pods, kubernetes nodes, etc.) and extracts the tags for each of them.
// Tags are then stored in memory (by the TagStore) and can be queried by the tagger.Tag()
// method.

// Package taggerimpl contains the implementation of the tagger component.
package taggerimpl

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	api "github.com/DataDog/datadog-agent/comp/api/api/def"
	"github.com/DataDog/datadog-agent/comp/core/config"
	log "github.com/DataDog/datadog-agent/comp/core/log/def"
	"github.com/DataDog/datadog-agent/comp/core/tagger/collectors"
	taggerdef "github.com/DataDog/datadog-agent/comp/core/tagger/def"
	"github.com/DataDog/datadog-agent/comp/core/tagger/origindetection"
	"github.com/DataDog/datadog-agent/comp/core/tagger/tagstore"
	"github.com/DataDog/datadog-agent/comp/core/tagger/telemetry"
	"github.com/DataDog/datadog-agent/comp/core/tagger/types"
	"github.com/DataDog/datadog-agent/comp/core/tagger/utils"
	coretelemetry "github.com/DataDog/datadog-agent/comp/core/telemetry"
	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	compdef "github.com/DataDog/datadog-agent/comp/def"
	"github.com/DataDog/datadog-agent/comp/dogstatsd/packets"
	taggertypes "github.com/DataDog/datadog-agent/pkg/tagger/types"
	"github.com/DataDog/datadog-agent/pkg/tagset"
	"github.com/DataDog/datadog-agent/pkg/util/common"
	"github.com/DataDog/datadog-agent/pkg/util/containers/metrics"
	"github.com/DataDog/datadog-agent/pkg/util/containers/metrics/provider"
	httputils "github.com/DataDog/datadog-agent/pkg/util/http"
	"github.com/DataDog/datadog-agent/pkg/util/option"
)

const (
	// pidCacheTTL is the time to live for the PID cache
	pidCacheTTL = 1 * time.Second
	// inodeCacheTTL is the time to live for the inode cache
	inodeCacheTTL = 1 * time.Second
	// externalDataCacheTTL is the time to live for the external data cache
	externalDataCacheTTL = 1 * time.Second
)

// datadogConfig contains the Agent configuration.
type datadogConfig struct {
	checksCardinality                  types.TagCardinality // Cardinality for checks
	dogstatsdCardinality               types.TagCardinality // Cardinality for DogStatsD Custom Metrics.
	dogstatsdEntityIDPrecedenceEnabled bool                 // Disable Origin Detection for DogStatsD metrics when EntityID is set.
	dogstatsdOptOutEnabled             bool                 // Disable Origin Detection if enabled and cardinality is none.
	originDetectionUnifiedEnabled      bool                 // Unifies Origin Detection mechanisms to use the same logic.
}

// Tagger is the entry class for entity tagging. It holds the tagger collector,
// memory tagStore, and handles the query logic. One should use the package
// methods in comp/core/tagger to use the default Tagger instead of instantiating it
// directly.
type localTagger struct {
	sync.RWMutex

	tagStore      *tagstore.TagStore
	workloadStore workloadmeta.Component
	log           log.Component
	cfg           config.Component
	collector     *collectors.WorkloadMetaCollector

	datadogConfig              datadogConfig
	tlmUDPOriginDetectionError coretelemetry.Counter
	telemetryStore             *telemetry.Store
	ctx                        context.Context
	cancel                     context.CancelFunc
}

// Requires defines the dependencies of the tagger component.
type Requires struct {
	compdef.In

	Lc           compdef.Lifecycle
	Config       config.Component
	Log          log.Component
	WorkloadMeta workloadmeta.Component
	Telemetry    coretelemetry.Component
}

// Provides contains the fields provided by the tagger constructor.
type Provides struct {
	compdef.Out

	Comp     taggerdef.Component
	Endpoint api.AgentEndpointProvider
}

// NewComponent returns a new tagger client
func NewComponent(req Requires) (Provides, error) {
	tagger, err := newLocalTagger(req.Config, req.WorkloadMeta, req.Log, req.Telemetry, nil)
	if err != nil {
		return Provides{}, err
	}

	req.Log.Info("Tagger is created")
	req.Lc.Append(compdef.Hook{OnStart: func(_ context.Context) error {
		// Main context passed to components, consistent with the one used in the workloadmeta component
		mainCtx, _ := common.GetMainCtxCancel()
		return tagger.Start(mainCtx)
	}})
	req.Lc.Append(compdef.Hook{OnStop: func(context.Context) error {
		return tagger.Stop()
	}})

	return Provides{
		Comp: tagger,
		Endpoint: api.NewAgentEndpointProvider(func(writer http.ResponseWriter, _ *http.Request) {
			response := tagger.List()
			jsonTags, err := json.Marshal(response)
			if err != nil {
				httputils.SetJSONError(writer, req.Log.Errorf("Unable to marshal tagger list response: %s", err), 500)
				return
			}
			_, err = writer.Write(jsonTags)
			if err != nil {
				_ = req.Log.Errorf("Unable to write tagger list response: %s", err)
			}
		}, "/tagger-list", "GET"),
	}, nil
}

func newLocalTagger(cfg config.Component, wmeta workloadmeta.Component, log log.Component, telemetryComp coretelemetry.Component, tagStore *tagstore.TagStore) (taggerdef.Component, error) {
	dc := datadogConfig{}
	dc.dogstatsdEntityIDPrecedenceEnabled = cfg.GetBool("dogstatsd_entity_id_precedence")
	dc.originDetectionUnifiedEnabled = cfg.GetBool("origin_detection_unified")
	dc.dogstatsdOptOutEnabled = cfg.GetBool("dogstatsd_origin_optout_enabled")

	checksTagCardinalityRawConfig := cfg.GetString("checks_tag_cardinality")
	dogstatsdTagCardinalityRawConfig := cfg.GetString("dogstatsd_tag_cardinality")

	var err error
	dc.checksCardinality, err = types.StringToTagCardinality(checksTagCardinalityRawConfig)
	if err != nil {
		log.Warnf("failed to parse check tag cardinality, defaulting to low. Error: %s", err)
	}
	dc.dogstatsdCardinality, err = types.StringToTagCardinality(dogstatsdTagCardinalityRawConfig)
	if err != nil {
		log.Warnf("failed to parse dogstatsd tag cardinality, defaulting to low. Error: %s", err)
	}
	telemetryStore := telemetry.NewStore(telemetryComp)
	if tagStore == nil {
		tagStore = tagstore.NewTagStore(telemetryStore)
	}

	// we use to pull tagger metrics in dogstatsd. Pulling it later in the
	// pipeline improve memory allocation. We kept the old name to be
	// backward compatible and because origin detection only affect
	// dogstatsd metrics.
	tlmUDPOriginDetectionError := telemetryComp.NewCounter("dogstatsd", "udp_origin_detection_error", nil, "Dogstatsd UDP origin detection error count")

	return &localTagger{
		tagStore:                   tagStore,
		workloadStore:              wmeta,
		log:                        log,
		telemetryStore:             telemetryStore,
		cfg:                        cfg,
		tlmUDPOriginDetectionError: tlmUDPOriginDetectionError,
		datadogConfig:              dc,
	}, nil
}

// Start starts the workloadmeta collector and then it is ready for requests.
func (t *localTagger) Start(ctx context.Context) error {
	t.ctx, t.cancel = context.WithCancel(ctx)

	t.collector = collectors.NewWorkloadMetaCollector(
		t.ctx,
		t.cfg,
		t.workloadStore,
		t.tagStore,
	)

	go t.tagStore.Run(t.ctx)
	go t.collector.Run(t.ctx, t.cfg)

	return nil
}

// Stop queues a shutdown of Tagger
func (t *localTagger) Stop() error {
	t.cancel()
	return nil
}

// getTags returns a read only list of tags for a given entity.
func (t *localTagger) getTags(entityID types.EntityID, cardinality types.TagCardinality) (tagset.HashedTags, error) {
	if entityID.Empty() {
		t.telemetryStore.QueriesByCardinality(cardinality).EmptyEntityID.Inc()
		return tagset.HashedTags{}, fmt.Errorf("empty entity ID")
	}

	cachedTags := t.tagStore.LookupHashedWithEntityStr(entityID, cardinality)

	t.telemetryStore.QueriesByCardinality(cardinality).Success.Inc()
	return cachedTags, nil
}

// AccumulateTagsFor appends tags for a given entity from the tagger to the TagsAccumulator
func (t *localTagger) AccumulateTagsFor(entityID types.EntityID, cardinality types.TagCardinality, tb tagset.TagsAccumulator) error {
	tags, err := t.getTags(entityID, cardinality)
	tb.AppendHashed(tags)
	return err
}

// Tag returns a copy of the tags for a given entity
func (t *localTagger) Tag(entityID types.EntityID, cardinality types.TagCardinality) ([]string, error) {
	tags, err := t.getTags(entityID, cardinality)
	if err != nil {
		return nil, err
	}
	return tags.Copy(), nil
}

// GenerateContainerIDFromOriginInfo generates a container ID from Origin Info.
// The resolutions will be done in the following order:
// * OriginInfo.LocalData.ContainerID: If the container ID is already known, return it.
// * OriginInfo.LocalData.ProcessID: If the process ID is known, do a PID resolution.
// * OriginInfo.LocalData.Inode: If the inode is known, do an inode resolution.
// * OriginInfo.ExternalData: If the ExternalData are known, do an ExternalData resolution.
func (t *localTagger) GenerateContainerIDFromOriginInfo(originInfo origindetection.OriginInfo) (containerID string, err error) {
	t.log.Debugf("Generating container ID from OriginInfo: %+v", originInfo)
	// If the container ID is already known, return it.
	if originInfo.LocalData.ContainerID != "" {
		t.log.Debugf("Found OriginInfo.LocalData.ContainerID: %s", originInfo.LocalData.ContainerID)
		containerID = originInfo.LocalData.ContainerID
		return
	}

	// Get the MetaCollector from WorkloadMeta.
	metaCollector := metrics.GetProvider(option.New(t.workloadStore)).GetMetaCollector()

	// If the process ID is known, do a PID resolution.
	if originInfo.LocalData.ProcessID != 0 {
		t.log.Debugf("Resolving container ID from PID: %d", originInfo.LocalData.ProcessID)
		containerID, err = metaCollector.GetContainerIDForPID(int(originInfo.LocalData.ProcessID), pidCacheTTL)
		if err != nil {
			t.log.Debugf("Error resolving container ID from PID: %v", err)
		} else if containerID == "" {
			t.log.Debugf("No container ID found for PID: %d", originInfo.LocalData.ProcessID)
		} else {
			return
		}
	}

	// If the inode is known, do an inode resolution.
	if originInfo.LocalData.Inode != 0 {
		t.log.Debugf("Resolving container ID from inode: %d", originInfo.LocalData.Inode)
		containerID, err = metaCollector.GetContainerIDForInode(originInfo.LocalData.Inode, inodeCacheTTL)
		if err != nil {
			t.log.Debugf("Error resolving container ID from inode: %v", err)
		} else if containerID == "" {
			t.log.Debugf("No container ID found for inode: %d", originInfo.LocalData.Inode)
		} else {
			return
		}
	}

	// If the ExternalData are known, do an ExternalData resolution.
	if originInfo.ExternalData.PodUID != "" && originInfo.ExternalData.ContainerName != "" {
		t.log.Debugf("Resolving container ID from ExternalData: %+v", originInfo.ExternalData)
		containerID, err = metaCollector.ContainerIDForPodUIDAndContName(originInfo.ExternalData.PodUID, originInfo.ExternalData.ContainerName, originInfo.ExternalData.Init, externalDataCacheTTL)
		if err != nil {
			t.log.Debugf("Error resolving container ID from ExternalData: %v", err)
		} else if containerID == "" {
			t.log.Debugf("No container ID found for ExternalData: %+v", originInfo.ExternalData)
		} else {
			return
		}
	}

	return "", fmt.Errorf("unable to resolve container ID from OriginInfo: %+v", originInfo)
}

// LegacyTag has the same behaviour as the Tag method, but it receives the entity id as a string and parses it.
// If possible, avoid using this function, and use the Tag method instead.
// This function exists in order not to break backward compatibility with rtloader and python
// integrations using the tagger
func (t *localTagger) LegacyTag(entity string, cardinality types.TagCardinality) ([]string, error) {
	prefix, id, err := types.ExtractPrefixAndID(entity)
	if err != nil {
		return nil, err
	}

	entityID := types.NewEntityID(prefix, id)
	return t.Tag(entityID, cardinality)
}

// Standard returns standard tags for a given entity
// It triggers a tagger fetch if the no tags are found
func (t *localTagger) Standard(entityID types.EntityID) ([]string, error) {
	if entityID.Empty() {
		return nil, fmt.Errorf("empty entity ID")
	}

	return t.tagStore.LookupStandard(entityID)
}

// GetEntity returns the entity corresponding to the specified id and an error
func (t *localTagger) GetEntity(entityID types.EntityID) (*types.Entity, error) {
	return t.tagStore.GetEntity(entityID)
}

// List the content of the tagger
func (t *localTagger) List() types.TaggerListResponse {
	return t.tagStore.List()
}

// Subscribe returns a channel that receives a slice of events whenever an entity is
// added, modified or deleted. It can send an initial burst of events only to the new
// subscriber, without notifying all of the others.
func (t *localTagger) Subscribe(subscriptionID string, filter *types.Filter) (types.Subscription, error) {
	return t.tagStore.Subscribe(subscriptionID, filter)
}

// GetTaggerTelemetryStore returns tagger telemetry tagStore
func (t *localTagger) GetTaggerTelemetryStore() *telemetry.Store {
	return t.telemetryStore
}

// GetEntityHash returns the hash for the tags associated with the given entity.
// Returns an empty string if the tags lookup fails.
func (t *localTagger) GetEntityHash(entityID types.EntityID, cardinality types.TagCardinality) string {
	tags, err := t.Tag(entityID, cardinality)
	if err != nil {
		return ""
	}
	return utils.ComputeTagsHash(tags)
}

// AgentTags returns the agent tags.
// It relies on the container provider utils to get the Agent container ID.
func (t *localTagger) AgentTags(cardinality types.TagCardinality) ([]string, error) {
	ctrID, err := metrics.GetProvider(option.New(t.workloadStore)).GetMetaCollector().GetSelfContainerID()
	if err != nil {
		return nil, err
	}

	if ctrID == "" {
		return nil, nil
	}

	entityID := types.NewEntityID(types.ContainerID, ctrID)
	return t.Tag(entityID, cardinality)
}

// GlobalTags queries global tags that should apply to all data coming from the
// agent.
func (t *localTagger) GlobalTags(cardinality types.TagCardinality) ([]string, error) {
	return t.Tag(types.GetGlobalEntityID(), cardinality)
}

// globalTagBuilder queries global tags that should apply to all data coming
// from the agent and appends them to the TagsAccumulator
func (t *localTagger) globalTagBuilder(cardinality types.TagCardinality, tb tagset.TagsAccumulator) error {
	return t.AccumulateTagsFor(types.GetGlobalEntityID(), cardinality, tb)
}

// EnrichTags extends a tag list with origin detection tags
// NOTE(remy): it is not needed to sort/dedup the tags anymore since after the
// enrichment, the metric and its tags is sent to the context key generator, which
// is taking care of deduping the tags while generating the context key.
// This function is dupliacted in the remote tagger `impl-remote`.
// When modifying this function make sure to update the copy `impl-remote` as well.
// TODO: extract this function to a share function so it can be used in both implementations
func (t *localTagger) EnrichTags(tb tagset.TagsAccumulator, originInfo taggertypes.OriginInfo) {
	cardinality := taggerCardinality(originInfo.Cardinality, t.datadogConfig.dogstatsdCardinality, t.log)

	containerIDFromSocketCutIndex := len(types.ContainerID) + types.GetSeparatorLengh()

	// Generate container ID from ProcessID
	var generatedContainerIDFromProcessID string
	if originInfo.LocalData.ProcessID != 0 {
		var processIDResolutionError error
		generatedContainerIDFromProcessID, processIDResolutionError = t.generateContainerIDFromProcessID(originInfo.LocalData, metrics.GetProvider(option.New(t.workloadStore)).GetMetaCollector())
		if processIDResolutionError != nil {
			t.log.Criticalf("Failed to resolve container ID from processID %d: %v", originInfo.LocalData.ProcessID, processIDResolutionError)
		}
	}

	// Check if ContainerIDFromSocket only has a prefix
	if originInfo.ContainerIDFromSocket == "container_id://" {
		t.log.Critical("Wassim DSD Debug - ContainerIDFromSocket only has a prefix")
	}

	// Check if ProcessID is set but not ContainerID
	if originInfo.LocalData.ProcessID != 0 && originInfo.ContainerIDFromSocket == "" {
		t.log.Critical("Wassim DSD Debug - ProcessID is set but not ContainerIDFromSocket")
		if generatedContainerIDFromProcessID != "" {
			t.log.Criticalf("Wassim DSD Debug - And we got a valid container ID from ProcessID: %s", generatedContainerIDFromProcessID)
			tags, _ := t.Tag(types.NewEntityID(types.ContainerID, generatedContainerIDFromProcessID), cardinality)
			t.log.Criticalf("Wassim DSD Debug - Tags: %+v", tags)
		}
	}

	// ContainerIDFromSocket looks like "container_id://<container_id>"
	// Check if ContainerIDFromSocket is set and ProcessID is set and that the resolution is either the same or different
	if originInfo.ContainerIDFromSocket != "" && originInfo.LocalData.ProcessID != 0 {
		generateEntityContainerIDFromProcessID := types.NewEntityID(types.ContainerID, generatedContainerIDFromProcessID).String()

		if generateEntityContainerIDFromProcessID != originInfo.ContainerIDFromSocket {
			t.log.Criticalf("Wassim DSD Debug - Tagger Resolution %s is different from DogStatsD %s", generateEntityContainerIDFromProcessID, originInfo.ContainerIDFromSocket)
		} else {
			t.log.Criticalf("Wassim DSD Debug - Tagger Resolution %s is equal to DogStatsD %s", generateEntityContainerIDFromProcessID, originInfo.ContainerIDFromSocket)
			originInfo.ContainerIDFromSocket = generateEntityContainerIDFromProcessID
		}
	}

	// Accumulate here
	/*if generatedContainerIDFromProcessID != "" {
		if err := t.AccumulateTagsFor(types.NewEntityID(types.ContainerID, generatedContainerIDFromProcessID), cardinality, tb); err != nil {
			t.log.Tracef("Cannot get tags for entity %s: %s", generatedContainerIDFromProcessID, err)
		}
	}*/

	/*
		if originInfo.ContainerIDFromSocket == "" && originInfo.LocalData.ProcessID != 0 {
			t.log.Criticalf("Wassim DSD Debug - ProcessID %d is set but not ContainerIDFromSocket", originInfo.LocalData.ProcessID)
			var containerIDFromProcessID string
			var processIDResolutionError error
			containerIDFromProcessID, processIDResolutionError = t.generateContainerIDFromProcessID(originInfo.LocalData, metrics.GetProvider(option.New(t.wmeta)).GetMetaCollector())
			if processIDResolutionError != nil {
				t.log.Tracef("Failed to resolve container ID from ProcessID %d: %v", originInfo.LocalData.ProcessID, processIDResolutionError)
			}
			if containerIDFromProcessID != "" {
				containerIDFromProcessID = types.NewEntityID(types.ContainerID, containerIDFromProcessID).String()
				tags, taggingError := t.Tag(types.NewEntityID(types.ContainerID, containerIDFromProcessID), types.HighCardinality)
				if taggingError != nil {
					t.log.Criticalf("tags: %+v", tags)
				}
			}
		}
		originInfo.ContainerIDFromSocket = ""
		if originInfo.LocalData.ProcessID != 0 {
			var containerIDFromProcessID string
			var processIDResolutionError error
			containerIDFromProcessID, processIDResolutionError = t.generateContainerIDFromProcessID(originInfo.LocalData, metrics.GetProvider(option.New(t.wmeta)).GetMetaCollector())
			if processIDResolutionError != nil {
				t.log.Tracef("Failed to resolve container ID from ProcessID %d: %v", originInfo.LocalData.ProcessID, processIDResolutionError)
			}
			if containerIDFromProcessID != "" {
				containerIDFromProcessID = types.NewEntityID(types.ContainerID, containerIDFromProcessID).String()
				if containerIDFromProcessID != originInfo.ContainerIDFromSocket {
					t.log.Criticalf("Wassim DSD Debug - Tagger Resolution %s is different from DogStatsD %s", containerIDFromProcessID, originInfo.ContainerIDFromSocket)
				} else {
					t.log.Criticalf("Wassim DSD Debug - Tagger Resolution %s is equal to DogStatsD %s", containerIDFromProcessID, originInfo.ContainerIDFromSocket)
					originInfo.ContainerIDFromSocket = containerIDFromProcessID
				}
			}
		}
	*/

	// Generate container ID from Inode
	if originInfo.LocalData.ContainerID == "" {
		var inodeResolutionError error
		originInfo.LocalData.ContainerID, inodeResolutionError = t.generateContainerIDFromInode(originInfo.LocalData, metrics.GetProvider(option.New(t.workloadStore)).GetMetaCollector())
		if inodeResolutionError != nil {
			t.log.Tracef("Failed to resolve container ID from inode %d: %v", originInfo.LocalData.Inode, inodeResolutionError)
		}
	}

	// Disable origin detection if cardinality is none
	if originInfo.Cardinality == types.NoneCardinalityString {
		originInfo.ContainerIDFromSocket = packets.NoOrigin
		originInfo.LocalData.PodUID = ""
		originInfo.LocalData.ContainerID = ""
		return
	}

	// Tag using Local Data
	if originInfo.ContainerIDFromSocket != packets.NoOrigin && len(originInfo.ContainerIDFromSocket) > containerIDFromSocketCutIndex {
		containerID := originInfo.ContainerIDFromSocket[containerIDFromSocketCutIndex:]
		originFromClient := types.NewEntityID(types.ContainerID, containerID)
		if err := t.AccumulateTagsFor(originFromClient, cardinality, tb); err != nil {
			t.log.Errorf("%s", err.Error())
		}
	}

	if err := t.AccumulateTagsFor(types.NewEntityID(types.ContainerID, originInfo.LocalData.ContainerID), cardinality, tb); err != nil {
		t.log.Tracef("Cannot get tags for entity %s: %s", originInfo.LocalData.ContainerID, err)
	}

	if err := t.AccumulateTagsFor(types.NewEntityID(types.KubernetesPodUID, originInfo.LocalData.PodUID), cardinality, tb); err != nil {
		t.log.Tracef("Cannot get tags for entity %s: %s", originInfo.LocalData.PodUID, err)
	}

	// Accumulate tags for pod UID
	if originInfo.ExternalData.PodUID != "" {
		if err := t.AccumulateTagsFor(types.NewEntityID(types.KubernetesPodUID, originInfo.ExternalData.PodUID), cardinality, tb); err != nil {
			t.log.Tracef("Cannot get tags for entity %s: %s", originInfo.ExternalData.PodUID, err)
		}
	}

	// Generate container ID from External Data
	generatedContainerID, err := t.generateContainerIDFromExternalData(originInfo.ExternalData, metrics.GetProvider(option.New(t.workloadStore)).GetMetaCollector())
	if err != nil {
		t.log.Tracef("Failed to generate container ID from %v: %s", originInfo.ExternalData, err)
	}

	// Accumulate tags for generated container ID
	if generatedContainerID != "" {
		if err := t.AccumulateTagsFor(types.NewEntityID(types.ContainerID, generatedContainerID), cardinality, tb); err != nil {
			t.log.Tracef("Cannot get tags for entity %s: %s", generatedContainerID, err)
		}
	}

	if err := t.globalTagBuilder(cardinality, tb); err != nil {
		t.log.Error(err.Error())
	}
}

// generateContainerIDFromProcessID generates a container ID from the CGroup inode.
func (t *localTagger) generateContainerIDFromProcessID(l origindetection.LocalData, metricsProvider provider.ContainerIDForPIDRetriever) (string, error) {
	return metricsProvider.GetContainerIDForPID(int(l.ProcessID), time.Second)
}

// generateContainerIDFromInode generates a container ID from the CGroup inode.
func (t *localTagger) generateContainerIDFromInode(e origindetection.LocalData, metricsProvider provider.ContainerIDForInodeRetriever) (string, error) {
	return metricsProvider.GetContainerIDForInode(e.Inode, time.Second)
}

// generateContainerIDFromExternalData generates a container ID from the External Data.
func (t *localTagger) generateContainerIDFromExternalData(e origindetection.ExternalData, metricsProvider provider.ContainerIDForPodUIDAndContNameRetriever) (string, error) {
	return metricsProvider.ContainerIDForPodUIDAndContName(e.PodUID, e.ContainerName, e.Init, time.Second)
}

// taggerCardinality converts tagger cardinality string to types.TagCardinality
// It should be defaulted to DogstatsdCardinality if the string is empty or unknown
func taggerCardinality(cardinality string,
	defaultCardinality types.TagCardinality,
	l log.Component) types.TagCardinality {
	if cardinality == "" {
		return defaultCardinality
	}

	taggerCardinality, err := types.StringToTagCardinality(cardinality)
	if err != nil {
		l.Tracef("Couldn't convert cardinality tag: %v", err)
		return defaultCardinality
	}

	return taggerCardinality
}

// ChecksCardinality defines the cardinality of tags we should send for check metrics
// this can still be overridden when calling get_tags in python checks.
func (t *localTagger) ChecksCardinality() types.TagCardinality {
	return t.datadogConfig.checksCardinality
}
