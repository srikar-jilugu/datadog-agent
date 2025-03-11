package workshop

import (
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/e2e"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/environments"
	awshost "github.com/DataDog/datadog-agent/test/new-e2e/pkg/provisioners/aws/host"
	"github.com/DataDog/test-infra-definitions/components/datadog/agentparams"
	"testing"
)

type vmSuite3 struct {
	e2e.BaseSuite[environments.Host]
}

// TestVMSuite runs tests for the VM interface to ensure its implementation is correct.
func TestVMSuite3(t *testing.T) {
	suiteParams := []e2e.SuiteOption{e2e.WithProvisioner(
		awshost.ProvisionerNoFakeIntake(
			awshost.WithAgentOptions(
				agentparams.WithAgentConfig(
					"log_level: debug"))))}

	e2e.Run(t, &vmSuite3{}, suiteParams...)
}

func (v *vmSuite3) TestExecute3_1() {
	agentClient := v.Env().Agent.Client
	v.Require().Contains(agentClient.Config(), "log_level: debug")
}

func (v *vmSuite3) TestExecute3_2() {
	v.UpdateEnv(awshost.ProvisionerNoFakeIntake(
		awshost.WithAgentOptions(
			agentparams.WithAgentConfig(
				"log_level: info"))))

	agentClient := v.Env().Agent.Client
	v.Require().Contains(agentClient.Config(), "log_level: info")
}
