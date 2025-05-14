// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build windows

// Package inventorysoftware implements the inventory software component, to collect installed software inventory.
package inventorysoftware

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/DataDog/datadog-agent/comp/core/status"

	api "github.com/DataDog/datadog-agent/comp/api/api/def"
	"github.com/DataDog/datadog-agent/comp/core/config"
	flaretypes "github.com/DataDog/datadog-agent/comp/core/flare/types"
	log "github.com/DataDog/datadog-agent/comp/core/log/def"
	"github.com/DataDog/datadog-agent/comp/metadata/internal/util"
	"github.com/DataDog/datadog-agent/comp/metadata/runner/runnerimpl"
	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	"github.com/DataDog/datadog-agent/pkg/serializer"
	"github.com/DataDog/datadog-agent/pkg/serializer/marshaler"
	sysprobeclient "github.com/DataDog/datadog-agent/pkg/system-probe/api/client"
	sysconfig "github.com/DataDog/datadog-agent/pkg/system-probe/config"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
	httputils "github.com/DataDog/datadog-agent/pkg/util/http"
	"go.uber.org/fx"
)

const flareFileName = "inventorysoftware.json"

// Module defines the fx options for this component.
func Module() fxutil.Module {
	return fxutil.Component(
		fx.Provide(New))
}

// inventorySoftware is the implementation of the Component interface.
type inventorySoftware struct {
	util.InventoryPayload

	log             log.Component
	sysProbeClient  *sysprobeclient.CheckClient
	cachedInventory []*SoftwareMetadata
}

// Dependencies is the dependencies for the inventory software component.
type Dependencies struct {
	fx.In

	Log        log.Component
	Config     config.Component
	Serializer serializer.MetricSerializer
}

// Provides defines the output of the hostgpu component
type Provides struct {
	fx.Out

	Comp                 Component
	Provider             runnerimpl.Provider
	FlareProvider        flaretypes.Provider
	StatusHeaderProvider status.HeaderInformationProvider
	Endpoint             api.AgentEndpointProvider
}

// SoftwareMetadata is the metadata for a software product
type SoftwareMetadata struct {
	ProductCode string            `json:"product_code"`
	Metadata    map[string]string `json:"metadata"`
}

// Payload is the payload for the inventory software component
type Payload struct {
	Metadata []*SoftwareMetadata `json:"software_inventory_metadata"`
}

// MarshalJSON serialization a Payload to JSON
func (p *Payload) MarshalJSON() ([]byte, error) {
	type PayloadAlias Payload
	return json.Marshal((*PayloadAlias)(p))
}

// SplitPayload implements marshaler.AbstractMarshaler#SplitPayload.
// In this case, the payload can't be split any further.
func (p *Payload) SplitPayload(_ int) ([]marshaler.AbstractMarshaler, error) {
	return nil, fmt.Errorf("could not split inventories software payload any more, payload is too big for intake")
}

// New creates a new inventory software component.
func New(deps Dependencies) Provides {
	is := &inventorySoftware{
		log:            deps.Log,
		sysProbeClient: sysprobeclient.GetCheckClient(pkgconfigsetup.SystemProbe().GetString("system_probe_config.sysprobe_socket")),
	}
	is.log.Infof("Starting the inventory software component")
	is.InventoryPayload = util.CreateInventoryPayload(deps.Config, deps.Log, deps.Serializer, is.getPayload, flareFileName)
	return Provides{
		Comp:                 is,
		Provider:             is.InventoryPayload.MetadataProvider(),
		FlareProvider:        is.FlareProvider(),
		StatusHeaderProvider: status.NewHeaderInformationProvider(is),
		Endpoint:             api.NewAgentEndpointProvider(is.writePayloadAsJSON, "/metadata/software", "GET"),
	}
}

func (is *inventorySoftware) refreshCachedValues() error {
	is.log.Infof("Collecting Software Inventory")
	is.cachedInventory = nil

	installedSoftware, err := sysprobeclient.GetCheck[map[string]map[string]string](is.sysProbeClient, sysconfig.InventorySoftwareModule)
	if err != nil {
		return is.log.Errorf("error getting software inventory: %v", err)
	}

	for productCode, metadata := range installedSoftware {
		is.cachedInventory = append(is.cachedInventory, &SoftwareMetadata{
			ProductCode: productCode,
			Metadata:    metadata,
		})
	}

	return nil
}

func (is *inventorySoftware) getPayload() marshaler.JSONMarshaler {
	if err := is.refreshCachedValues(); err != nil {
		return nil
	}

	return &Payload{
		Metadata: is.cachedInventory,
	}
}

func (is *inventorySoftware) writePayloadAsJSON(w http.ResponseWriter, _ *http.Request) {
	json, err := is.GetAsJSON()
	if err != nil {
		httputils.SetJSONError(w, err, 500)
		return
	}
	w.Write(json)
}
