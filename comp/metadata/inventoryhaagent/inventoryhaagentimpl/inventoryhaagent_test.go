// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package inventoryhaagentimpl

import (
	"bytes"
	"testing"
	"time"

	"go.uber.org/fx"
	"golang.org/x/exp/maps"

	authtokenimpl "github.com/DataDog/datadog-agent/comp/api/authtoken/fetchonlyimpl"
	"github.com/DataDog/datadog-agent/comp/core/config"
	log "github.com/DataDog/datadog-agent/comp/core/log/def"
	logmock "github.com/DataDog/datadog-agent/comp/core/log/mock"
	haagentmock "github.com/DataDog/datadog-agent/comp/haagent/mock"
	pkgconfigmodel "github.com/DataDog/datadog-agent/pkg/config/model"
	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	"github.com/DataDog/datadog-agent/pkg/serializer"
	serializermock "github.com/DataDog/datadog-agent/pkg/serializer/mocks"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
	"github.com/stretchr/testify/assert"
)

func getProvides(t *testing.T, confOverrides map[string]any) (provides, error) {
	return newInventoryHaAgentProvider(
		fxutil.Test[dependencies](
			t,
			fx.Provide(func() log.Component { return logmock.New(t) }),
			config.MockModule(),
			fx.Replace(config.MockParams{Overrides: confOverrides}),
			fx.Provide(func() serializer.MetricSerializer { return serializermock.NewMetricSerializer(t) }),
			authtokenimpl.Module(),
			haagentmock.Module(),
		),
	)
}

func getTestInventoryPayload(t *testing.T, confOverrides map[string]any) *inventoryhaagent {
	p, _ := getProvides(t, confOverrides)
	return p.Comp.(*inventoryhaagent)
}

func TestGetPayload(t *testing.T) {
	overrides := map[string]any{}

	io := getTestInventoryPayload(t, overrides)
	io.hostname = "hostname-for-test"

	haAgentMock := io.haAgent.(haagentmock.Component)
	haAgentMock.SetEnabled(true)

	startTime := time.Now().UnixNano()

	p := io.getPayload()
	payload := p.(*Payload)

	data := copyAndScrub(haAgentMetadata{
		"enabled":   true,
		"config_id": "config01",
	})

	assert.True(t, payload.Timestamp > startTime)
	assert.Equal(t, "hostname-for-test", payload.Hostname)
	assert.Equal(t, data, payload.Metadata)
}

func TestGet(t *testing.T) {
	overrides := map[string]any{}
	io := getTestInventoryPayload(t, overrides)
	haAgentMock := io.haAgent.(haagentmock.Component)
	haAgentMock.SetEnabled(true)

	// Collect metadata
	io.refreshMetadata()

	p := io.Get()

	// verify that the return map is a copy
	p["config_id"] = ""
	assert.Equal(t, "config01", io.data["config_id"])
	assert.NotEqual(t, p["config_id"], io.data["config_id"])
}

func TestFlareProviderFilename(t *testing.T) {
	io := getTestInventoryPayload(t, nil)
	assert.Equal(t, "ha-agent.json", io.FlareFileName)
}

func TestConfigRefresh(t *testing.T) {
	io := getTestInventoryPayload(t, nil)

	assert.False(t, io.RefreshTriggered())
	pkgconfigsetup.Datadog().Set("inventories_max_interval", 10*60, pkgconfigmodel.SourceAgentRuntime)
	assert.True(t, io.RefreshTriggered())
}

func TestStatusHeaderProvider(t *testing.T) {
	ret, _ := getProvides(t, nil)

	headerStatusProvider := ret.StatusHeaderProvider.Provider

	tests := []struct {
		name       string
		assertFunc func(t *testing.T)
	}{
		{"JSON", func(t *testing.T) {
			stats := make(map[string]interface{})
			headerStatusProvider.JSON(false, stats)

			keys := maps.Keys(stats)

			assert.Contains(t, keys, "haagent_metadata")
		}},
		{"Text", func(t *testing.T) {
			b := new(bytes.Buffer)
			err := headerStatusProvider.Text(false, b)

			assert.NoError(t, err)

			assert.NotEmpty(t, b.String())
		}},
		{"HTML", func(t *testing.T) {
			b := new(bytes.Buffer)
			err := headerStatusProvider.HTML(false, b)

			assert.NoError(t, err)

			assert.NotEmpty(t, b.String())
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.assertFunc(t)
		})
	}
}
