package workshop

import (
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/e2e"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/environments"
	awshost "github.com/DataDog/datadog-agent/test/new-e2e/pkg/provisioners/aws/host"
	"testing"
)

type vmSuite2 struct {
	e2e.BaseSuite[environments.Host]
}

// TestVMSuite runs tests for the VM interface to ensure its implementation is correct.
func TestVMSuite2(t *testing.T) {
	suiteParams := []e2e.SuiteOption{e2e.WithProvisioner(awshost.ProvisionerNoFakeIntake())}

	e2e.Run(t, &vmSuite2{}, suiteParams...)
}

func (v *vmSuite2) TestExecute2() {
	v.Require().True(v.Env().Agent.Client.IsReady())
}
