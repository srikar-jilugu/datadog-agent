// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package workshop

import (
	_ "embed"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/e2e"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/environments"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/provisioners"
	awshost "github.com/DataDog/datadog-agent/test/new-e2e/pkg/provisioners/aws/host"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/utils/e2e/client/agentclient"
	"github.com/DataDog/datadog-agent/test/new-e2e/tests/agent-configuration/secretsutils"
	"github.com/DataDog/test-infra-definitions/components/datadog/agentparams"
)

//go:embed config/cisco-nexus.yaml
var snmpConfig string

type vmSuite struct {
	e2e.BaseSuite[environments.Host]
}

func vmProvisioner(opts ...awshost.ProvisionerOption) provisioners.Provisioner {
	allOpts := []awshost.ProvisionerOption{
		awshost.WithDocker(),
		awshost.WithAgentOptions(
			agentparams.WithFile("/etc/datadog-agent/conf.d/snmp.d/snmp.yaml", snmpConfig, true),
		),
	}
	allOpts = append(allOpts, opts...)

	return awshost.Provisioner(
		allOpts...,
	)
}

func TestVMSuite(t *testing.T) {
	e2e.Run(t, &vmSuite{}, e2e.WithProvisioner(vmProvisioner()))
}

func (s *vmSuite) TestExecute() {
	vm := s.Env().RemoteHost
	fakeIntake := s.Env().FakeIntake.Client()
	agent := s.Env().Agent.Client

	err := vm.CopyFolder("compose/data", "/tmp/data")
	s.Require().NoError(err)

	vm.CopyFile("compose/snmpCompose.yaml", "/tmp/snmpCompose.yaml")

	_, err = vm.Execute("docker-compose -f /tmp/snmpCompose.yaml up -d")
	s.Require().NoError(err)

	s.Require().EventuallyWithT(func(c *assert.CollectT) {
		metrics, err := fakeIntake.GetMetricNames()
		s.Require().NoError(err)
		s.Require().Contains(metrics, "snmp.sysUpTimeInstance", "1: metrics %v doesn't contain snmp.sysUpTimeInstance", metrics)
	}, 2*time.Minute, 10*time.Second)

	apiKey1 := strings.Repeat("0", 32)
	apiKey2 := strings.Repeat("1", 32)

	secretClient := secretsutils.NewClient(s.T(), s.Env().RemoteHost, "/tmp/test-secret")
	secretClient.SetSecret("api_key", apiKey1)

	agentConfig := `
api_key: ENC[api_key]
log_level: debug

secret_backend_command: /tmp/test-secret/secret-resolver.py
secret_backend_arguments:
  - /tmp/test-secret
`

	s.UpdateEnv(
		vmProvisioner(
			awshost.WithAgentOptions(
				agentparams.WithAgentConfig(agentConfig),
				secretsutils.WithUnixSetupScript("/tmp/test-secret/secret-resolver.py", false),
				agentparams.WithSkipAPIKeyInConfig(),
			),
		),
	)

	s.Require().EventuallyWithT(func(t *assert.CollectT) {
		lastAPIKey, err := fakeIntake.GetLastAPIKey()
		s.Require().NoError(err)
		s.Require().Equal(apiKey1, lastAPIKey)
	}, 2*time.Minute, 10*time.Second)

	s.Require().EventuallyWithT(func(c *assert.CollectT) {
		metrics, err := fakeIntake.GetMetricNames()
		s.Require().NoError(err)
		s.Require().Contains(metrics, "snmp.sysUpTimeInstance", "2: metrics %v doesn't contain snmp.sysUpTimeInstance", metrics)
	}, 2*time.Minute, 10*time.Second)

	secretClient.SetSecret("api_key", apiKey2)
	agent.Secret(agentclient.WithArgs([]string{"refresh"}))

	s.Require().EventuallyWithT(func(t *assert.CollectT) {
		lastAPIKey, err := fakeIntake.GetLastAPIKey()
		s.Require().NoError(err)
		s.Require().Equal(apiKey2, lastAPIKey)
	}, 2*time.Minute, 10*time.Second)

	s.Require().EventuallyWithT(func(c *assert.CollectT) {
		metrics, err := fakeIntake.GetMetricNames()
		s.Require().NoError(err)
		s.Require().Contains(metrics, "snmp.sysUpTimeInstance", "3: metrics %v doesn't contain snmp.sysUpTimeInstance", metrics)
	}, 2*time.Minute, 10*time.Second)
}
