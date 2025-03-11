// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package workshop

import (
	_ "embed"
	"testing"
	"time"

	fi "github.com/DataDog/datadog-agent/test/fakeintake/client"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/e2e"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/environments"
	awshost "github.com/DataDog/datadog-agent/test/new-e2e/pkg/provisioners/aws/host"

	"github.com/DataDog/test-infra-definitions/components/datadog/agentparams"

	"github.com/stretchr/testify/assert"
)

type vmSuite5 struct {
	e2e.BaseSuite[environments.Host]
}

//go:embed testfixtures/custom_logs.yaml
var customLogsConfig string

func TestVMSuite5(t *testing.T) {
	e2e.Run(t, &vmSuite5{}, e2e.WithProvisioner(
		awshost.Provisioner(
			awshost.WithAgentOptions(
				agentparams.WithIntegration("custom_logs.d", customLogsConfig),
				agentparams.WithLogs(),
			),
		),
	))
}

func (s *vmSuite5) TestLogs() {
	fakeintakeClient := s.Env().FakeIntake.Client()

	s.EventuallyWithT(func(c *assert.CollectT) {
		logs, err := fakeintakeClient.FilterLogs("custom_logs")
		assert.NoError(c, err)
		assert.Equal(c, len(logs), 0, "Logs received while none expected")
	}, 5*time.Minute, 10*time.Second)

	s.EventuallyWithT(func(c *assert.CollectT) {
		s.Env().RemoteHost.MustExecute("echo 'totoro' >> /tmp/test.log")
		names, err := fakeintakeClient.GetLogServiceNames()
		assert.NoError(c, err)
		assert.Greater(c, len(names), 0, "No logs received")
		logs, err := fakeintakeClient.FilterLogs("custom_logs")
		assert.NoError(c, err)
		assert.Equal(c, len(logs), 1, "Expecting 1 log from 'custom_logs'")
		logs, err = fakeintakeClient.FilterLogs("custom_logs", fi.WithMessageContaining("totoro"))
		assert.NoError(c, err)
		assert.Equal(c, len(logs), 1, "Expecting 1 log from 'custom_logs' with 'totoro' content")
	}, 5*time.Minute, 10*time.Second)
}
