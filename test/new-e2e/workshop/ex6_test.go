// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package workshop

import (
	_ "embed"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/e2e"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/environments"
	awshost "github.com/DataDog/datadog-agent/test/new-e2e/pkg/provisioners/aws/host"
	"testing"

	"github.com/DataDog/test-infra-definitions/components/datadog/agentparams"
)

type vmSuite6 struct {
	e2e.BaseSuite[environments.Host]
}

func TestVMSuite6(t *testing.T) {
	e2e.Run(t, &vmSuite6{}, e2e.WithProvisioner(
		awshost.Provisioner(
			awshost.WithAgentOptions(
				agentparams.WithFile("/etc/hosts",
					"127.0.0.1 localhost\n"+
						"127.0.0.1 agentvm", false),
			),
		),
	))
}

func (s *vmSuite6) TestExecute6() {
	vm := s.Env().RemoteHost

	output, err := vm.Execute("cat /etc/hosts")
	s.Require().NoError(err, "Failed to read /etc/hosts")
	s.Require().Contains(output, "127.0.0.1 agentvm", "Hosts file was not updated correctly")

	err = vm.CopyFolder("ex6", "/tmp/ex6")
	s.Require().NoError(err)

	output, err = vm.Execute("ls -R /tmp/ex6")
	s.Require().NoError(err, "Failed to list uploaded folder")
	s.Require().Contains(output, "ex6_1", "ex6_1 not found on remote host")
	s.Require().Contains(output, "ex6_2", "ex6_2 not found on remote host")
}
