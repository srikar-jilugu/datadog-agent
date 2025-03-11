package workshop

import (
	"github.com/DataDog/datadog-agent/test/fakeintake/client"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/e2e"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/environments"
	awshost "github.com/DataDog/datadog-agent/test/new-e2e/pkg/provisioners/aws/host"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

type vmSuite4 struct {
	e2e.BaseSuite[environments.Host]
}

// TestVMSuite runs tests for the VM interface to ensure its implementation is correct.
func TestVMSuite4(t *testing.T) {
	suiteParams := []e2e.SuiteOption{e2e.WithProvisioner(awshost.Provisioner())}

	e2e.Run(t, &vmSuite4{}, suiteParams...)
}

func (v *vmSuite4) Test1_FakeIntakeReceivesMetrics() {
	v.EventuallyWithT(func(c *assert.CollectT) {
		metricNames, err := v.Env().FakeIntake.Client().GetMetricNames()
		assert.NoError(c, err)
		assert.Greater(c, len(metricNames), 0, "No metrics yet")
	}, 5*time.Minute, 10*time.Second)
}

func (v *vmSuite4) Test2_FakeIntakeReceivesSystemLoadMetric() {
	v.EventuallyWithT(func(c *assert.CollectT) {
		metrics, err := v.Env().FakeIntake.Client().FilterMetrics("system.load.1")
		assert.NoError(c, err)
		assert.Greater(c, len(metrics), 0, "No 'system.load.1' metrics yet")
	}, 5*time.Minute, 10*time.Second)
}

func (v *vmSuite4) Test3_FakeIntakeReceivesSystemUptimeHigherThanZero() {
	v.EventuallyWithT(func(c *assert.CollectT) {
		metrics, err := v.Env().FakeIntake.Client().FilterMetrics("system.uptime", client.WithMetricValueHigherThan(0))
		assert.NoError(c, err)
		assert.Greater(c, len(metrics), 0, "No 'system.uptime' greater than 0 yet")
	}, 5*time.Minute, 10*time.Second)
}
