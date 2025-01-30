// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package inventoryhaagentimpl implements a component to generate the 'datadog_agent' metadata payload for inventory.
package inventoryhaagentimpl

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.uber.org/fx"

	api "github.com/DataDog/datadog-agent/comp/api/api/def"
	"github.com/DataDog/datadog-agent/comp/api/authtoken"
	"github.com/DataDog/datadog-agent/comp/core/config"
	flaretypes "github.com/DataDog/datadog-agent/comp/core/flare/types"
	log "github.com/DataDog/datadog-agent/comp/core/log/def"
	"github.com/DataDog/datadog-agent/comp/core/status"
	haagent "github.com/DataDog/datadog-agent/comp/haagent/def"
	"github.com/DataDog/datadog-agent/comp/metadata/internal/util"
	iointerface "github.com/DataDog/datadog-agent/comp/metadata/inventoryhaagent"
	"github.com/DataDog/datadog-agent/comp/metadata/runner/runnerimpl"
	"github.com/DataDog/datadog-agent/pkg/serializer"
	"github.com/DataDog/datadog-agent/pkg/serializer/marshaler"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
	"github.com/DataDog/datadog-agent/pkg/util/hostname"
	httputils "github.com/DataDog/datadog-agent/pkg/util/http"
	"github.com/DataDog/datadog-agent/pkg/util/uuid"
)

// Module defines the fx options for this component.
func Module() fxutil.Module {
	return fxutil.Component(
		fx.Provide(newInventoryHaAgentProvider))
}

type haAgentMetadata = map[string]interface{}

// Payload handles the JSON unmarshalling of the metadata payload
type Payload struct {
	Hostname  string          `json:"hostname"`
	Timestamp int64           `json:"timestamp"`
	Metadata  haAgentMetadata `json:"haagent_metadata"`
	UUID      string          `json:"uuid"`
}

// MarshalJSON serialization a Payload to JSON
func (p *Payload) MarshalJSON() ([]byte, error) {
	type PayloadAlias Payload
	return json.Marshal((*PayloadAlias)(p))
}

// SplitPayload implements marshaler.AbstractMarshaler#SplitPayload.
//
// In this case, the payload can't be split any further.
func (p *Payload) SplitPayload(_ int) ([]marshaler.AbstractMarshaler, error) {
	return nil, fmt.Errorf("could not split inventories agent payload any more, payload is too big for intake")
}

type inventoryhaagent struct {
	util.InventoryPayload

	conf       config.Component
	log        log.Component
	m          sync.Mutex
	data       haAgentMetadata
	hostname   string
	authToken  authtoken.Component
	httpClient *http.Client
	haAgent    haagent.Component
}

type dependencies struct {
	fx.In

	Log        log.Component
	Config     config.Component
	Serializer serializer.MetricSerializer
	AuthToken  authtoken.Component
	HaAgent    haagent.Component
}

type provides struct {
	fx.Out

	Comp                 iointerface.Component
	Provider             runnerimpl.Provider
	FlareProvider        flaretypes.Provider
	StatusHeaderProvider status.HeaderInformationProvider
	Endpoint             api.AgentEndpointProvider
}

func newInventoryHaAgentProvider(deps dependencies) (provides, error) {
	hname, _ := hostname.Get(context.Background())
	// HTTP client need not verify otel-agent cert since it's self-signed
	// at start-up. TLS used for encryption not authentication.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	i := &inventoryhaagent{
		conf:      deps.Config,
		log:       deps.Log,
		hostname:  hname,
		data:      make(haAgentMetadata),
		authToken: deps.AuthToken,
		httpClient: &http.Client{
			Transport: tr,
			Timeout:   httpTO,
		},
		haAgent: deps.HaAgent,
	}

	i.InventoryPayload = util.CreateInventoryPayload(deps.Config, deps.Log, deps.Serializer, i.getPayload, "ha-agent.json")

	if i.Enabled {
		// TODO: if there's an update on the OTel side we currently will not be
		//       notified. Is this a problem? Runtime changes are expected to be
		//       triggered by FA, so maybe this is OK.
		//
		// We want to be notified when the configuration is updated
		deps.Config.OnUpdate(func(_ string, _, _ any) { i.Refresh() })
	}

	return provides{
		Comp:                 i,
		Provider:             i.MetadataProvider(),
		FlareProvider:        i.FlareProvider(),
		StatusHeaderProvider: status.NewHeaderInformationProvider(i),
		Endpoint:             api.NewAgentEndpointProvider(i.writePayloadAsJSON, "/metadata/inventory-ha-agent", "GET"),
	}, nil
}

func (i *inventoryhaagent) fetchOtelAgentMetadata() {
	isEnabled := i.haAgent.Enabled()

	if !isEnabled {
		i.log.Infof("HA Agent Metadata unavailable as HA Agent is disabled")
		i.data = nil
		return
	}

	i.data["enabled"] = isEnabled
	i.data["config_id"] = i.haAgent.GetConfigID()
}

func (i *inventoryhaagent) refreshMetadata() {
	// Core Agent / agent
	i.fetchOtelAgentMetadata()
}

func (i *inventoryhaagent) getPayload() marshaler.JSONMarshaler {
	i.m.Lock()
	defer i.m.Unlock()

	i.refreshMetadata()

	// Create a static scrubbed copy of agentMetadata for the payload
	data := copyAndScrub(i.data)

	return &Payload{
		Hostname:  i.hostname,
		Timestamp: time.Now().UnixNano(),
		Metadata:  data,
		UUID:      uuid.GetUUID(),
	}
}

func (i *inventoryhaagent) writePayloadAsJSON(w http.ResponseWriter, _ *http.Request) {
	// GetAsJSON already return scrubbed data
	scrubbed, err := i.GetAsJSON()
	if err != nil {
		httputils.SetJSONError(w, err, 500)
		return
	}
	w.Write(scrubbed)
}

// Get returns a copy of the agent metadata. Useful to be incorporated in the status page.
func (i *inventoryhaagent) Get() haAgentMetadata {
	i.m.Lock()
	defer i.m.Unlock()

	data := haAgentMetadata{}
	for k, v := range i.data {
		data[k] = v
	}
	return data
}
