// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2020-present Datadog, Inc.

// Package statusimpl implements the Status component.
package statusimpl

import (
	"embed"
	"encoding/json"
	"expvar"
	"fmt"
	"io"
	"os"

	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/comp/core/status"
	"github.com/DataDog/datadog-agent/comp/forwarder/eventplatform"
	trapsStatus "github.com/DataDog/datadog-agent/comp/snmptraps/status"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

// Module defines the fx options for this component.
func Module() fxutil.Module {
	return fxutil.Component(
		fx.Provide(New),
	)
}

var (
	trapsExpvars                       = expvar.NewMap("snmp_traps")
	trapsPackets                       = expvar.Int{}
	trapsPacketsUnknownCommunityString = expvar.Int{}
	trapsBlaBla                        = expvar.Int{}
	// startError stores the error we report to GetStatus()
	startError error
)

func init() {
	fmt.Println("INIT SNMP TRAPS STATUS")
	if os.Geteuid() == 0 {
		fmt.Println("Running as admin (root).")
	} else {
		fmt.Println("Not running as admin.")
	}

	trapsExpvars.Set("Packets", &trapsPackets)
	trapsExpvars.Set("PacketsUnknownCommunityString", &trapsPacketsUnknownCommunityString)
	trapsExpvars.Set("BlaBla", &trapsBlaBla)
}

// New creates a new status manager component
func New() trapsStatus.Component {
	return &manager{}
}

type manager struct {
}

func (s *manager) AddTrapsPackets(i int64) {
	fmt.Println("ADD TRAPS PACKETS IN SNMP TRAPS STATUS")

	trapsPackets.Add(i)
}

func (s *manager) AddTrapsPacketsUnknownCommunityString(i int64) {
	fmt.Println("ADD TRAPS PACKETS UNKNOWN COMMUNITY STRING IN SNMP TRAPS STATUS")

	trapsPacketsUnknownCommunityString.Add(i)
}

func (s *manager) GetTrapsPackets() int64 {
	fmt.Println("GET TRAPS PACKETS IN SNMP TRAPS STATUS")

	return trapsPackets.Value()
}

func (s *manager) GetTrapsPacketsUnknownCommunityString() int64 {
	fmt.Println("GET TRAPS PACKETS UNKNOWN COMMUNITY STRING IN SNMP TRAPS STATUS")

	return trapsPacketsUnknownCommunityString.Value()
}

func (s *manager) GetStartError() error {
	fmt.Println("GET START ERROR IN SNMP TRAPS STATUS")

	return startError
}

func (s *manager) SetStartError(err error) {
	fmt.Println("SET START ERROR IN SNMP TRAPS STATUS")

	startError = err
}

func (s *manager) AddTrapsBlaBla(i int64) {
	fmt.Println("ADD TRAPS BLA BLA IN SNMP TRAPS STATUS")
	trapsBlaBla.Add(i)
}

func (s *manager) GetTrapsBlaBla() int64 {
	fmt.Println("GET TRAPS BLA BLA IN SNMP TRAPS STATUS")
	return trapsBlaBla.Value()
}

//go:embed status_templates
var templatesFS embed.FS

// Provider provides the functionality to populate the status output
type Provider struct{}

// Name returns the name
func (Provider) Name() string {
	fmt.Println("NAME SNMP TRAPS STATUS")

	return "SNMP Traps Name"
}

// Section return the section
func (Provider) Section() string {
	fmt.Println("SECTION SNMP TRAPS STATUS")

	return "SNMP Traps Section"
}

// JSON populates the status map
func (Provider) JSON(_ bool, stats map[string]interface{}) error {
	fmt.Println("JSON SNMP TRAPS STATUS")

	stats["snmpTrapsStats"] = GetStatus()

	return nil
}

// Text renders the text output
func (p Provider) Text(_ bool, buffer io.Writer) error {
	fmt.Println("TEXT SNMP TRAPS STATUS")

	return status.RenderText(templatesFS, "snmp.tmpl", buffer, p.populateStatus())
}

// HTML renders the html output
func (p Provider) HTML(_ bool, buffer io.Writer) error {
	fmt.Println("HTML SNMP TRAPS STATUS")

	return status.RenderHTML(templatesFS, "snmpHTML.tmpl", buffer, p.populateStatus())
}

func (p Provider) populateStatus() map[string]interface{} {
	fmt.Println("POPULATE STATUS SNMP TRAPS")

	stats := make(map[string]interface{})

	p.JSON(false, stats) //nolint:errcheck

	return stats
}

func getDroppedPackets() float64 {
	fmt.Println("GET DROPPED PACKETS IN SNMP TRAPS STATUS")

	aggregatorMetrics, ok := expvar.Get("aggregator").(*expvar.Map)
	if !ok {
		return 0
	}

	epErrors, ok := aggregatorMetrics.Get("EventPlatformEventsErrors").(*expvar.Map)
	if !ok {
		return 0
	}

	droppedPackets, ok := epErrors.Get(eventplatform.EventTypeSnmpTraps).(*expvar.Int)
	if !ok {
		return 0
	}
	return float64(droppedPackets.Value())
}

// GetStatus returns key-value data for use in status reporting of the traps server.
func GetStatus() map[string]interface{} {
	fmt.Println("GETTING STATUS IN SNMP TRAPS")

	status := make(map[string]interface{})

	metricsJSON := []byte(trapsExpvars.String())
	metrics := make(map[string]interface{})
	json.Unmarshal(metricsJSON, &metrics) //nolint:errcheck
	if dropped := getDroppedPackets(); dropped > 0 {
		metrics["PacketsDropped"] = dropped
	}
	status["metrics"] = metrics
	if startError != nil {
		status["error"] = startError.Error()
	}
	fmt.Println(status)
	return status
}
