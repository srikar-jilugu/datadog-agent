package workshop

import (
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/e2e"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/environments"
	awshost "github.com/DataDog/datadog-agent/test/new-e2e/pkg/provisioners/aws/host"
	"testing"
)

type vmSuite1 struct {
	e2e.BaseSuite[environments.Host]
}

// TestVMSuite runs tests for the VM interface to ensure its implementation is correct.
func TestVMSuite1(t *testing.T) {
	suiteParams := []e2e.SuiteOption{e2e.WithProvisioner(awshost.ProvisionerNoAgentNoFakeIntake())}

	e2e.Run(t, &vmSuite1{}, suiteParams...)
}

func (v *vmSuite1) TestExecute1() {
	vm := v.Env().RemoteHost

	out, err := vm.Execute("cat /etc/os-release")
	v.Require().NoError(err)
	v.Require().Contains(out, "Ubuntu", "OS release file does not contain Ubuntu")
}
