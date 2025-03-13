package tests

import (
	"fmt"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/utils/e2e/client/agentclient"
	"github.com/DataDog/test-infra-definitions/components/datadog/agentparams"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/e2e"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/environments"
	awshost "github.com/DataDog/datadog-agent/test/new-e2e/pkg/provisioners/aws/host"
	"github.com/DataDog/datadog-agent/test/new-e2e/tests/agent-configuration/secretsutils"
)

type apiKeyRotationSuite struct {
	e2e.BaseSuite[environments.Host]
}

func TestAPIKeyRotation(t *testing.T) {
	e2e.Run(t, &apiKeyRotationSuite{}, e2e.WithProvisioner(
		awshost.Provisioner(),
	))
}

func (v *apiKeyRotationSuite) TestExecute() {
	doPrint := false

	apiKey1 := strings.Repeat("0", 32)
	apiKey2 := strings.Repeat("1", 32)

	secretClient := secretsutils.NewClient(v.T(), v.Env().RemoteHost, "/tmp/test-secret")
	secretClient.SetSecret("api_key", apiKey1)

	agentConfig := `
api_key: ENC[api_key]
log_level: debug

secret_backend_command: /tmp/test-secret/secret-resolver.py
secret_backend_arguments:
  - /tmp/test-secret

network_devices:
  namespace: COMP-CT46W9RX7J
  autodiscovery:
    loader: core
    use_device_id_as_hostname: true
  configs:
    community_string: public
    ip_address: 172.18.0.2
    port: 1161
`

	v.UpdateEnv(
		awshost.Provisioner(
			awshost.WithAgentOptions(
				agentparams.WithAgentConfig(agentConfig),
				secretsutils.WithUnixSetupScript("/tmp/test-secret/secret-resolver.py", false),
				agentparams.WithSkipAPIKeyInConfig(),
			),
		),
	)

	lastAPIKey, err := v.Env().FakeIntake.Client().GetLastAPIKey()
	v.Require().NoError(err, "Failed to fetch last API key")
	v.Require().Equal(apiKey1, lastAPIKey, "Initial API key does not match")

	if doPrint {
		for i := 0; i < 10; i++ {
			metrics, err := v.Env().FakeIntake.Client().GetMetricNames()
			v.Require().NoError(err)
			fmt.Println()
			fmt.Println()
			fmt.Println()
			fmt.Println()
			fmt.Println()
			fmt.Println(metrics)
			fmt.Println(len(metrics))
			fmt.Println()
			fmt.Println()
			fmt.Println()
			fmt.Println()
			fmt.Println()
			time.Sleep(10 * time.Second)
		}
	}

	secretClient.SetSecret("api_key", apiKey2)

	v.Env().Agent.Client.Secret(agentclient.WithArgs([]string{"refresh"}))

	lastAPIKey, err = v.Env().FakeIntake.Client().GetLastAPIKey()
	assert.EventuallyWithT(v.T(), func(t *assert.CollectT) {
		v.Require().NoError(err, "Failed to fetch last API key")
		v.Require().Equal(apiKey2, lastAPIKey, "API key was not updated after refresh")
	}, 1*time.Minute, 10*time.Second)

	if doPrint {
		for i := 0; i < 10; i++ {
			metrics, err := v.Env().FakeIntake.Client().GetMetricNames()
			v.Require().NoError(err)
			fmt.Println()
			fmt.Println()
			fmt.Println()
			fmt.Println()
			fmt.Println()
			fmt.Println(metrics)
			fmt.Println(len(metrics))
			fmt.Println()
			fmt.Println()
			fmt.Println()
			fmt.Println()
			fmt.Println()
			time.Sleep(10 * time.Second)
		}

		for i := 0; i < 10; i++ {
			fmt.Println("Sleep: " + fmt.Sprint(i))
			time.Sleep(1 * time.Minute)
		}

		metrics, err := v.Env().FakeIntake.Client().GetMetricNames()
		v.Require().NoError(err)
		fmt.Println()
		fmt.Println()
		fmt.Println()
		fmt.Println()
		fmt.Println()
		fmt.Println(metrics)
		fmt.Println(len(metrics))
		fmt.Println()
		fmt.Println()
		fmt.Println()
		fmt.Println()
		fmt.Println()

		fmt.Println("Done")
	}
}
