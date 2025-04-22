package command

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

func TestFxRunCommand(t *testing.T) {
	fxutil.TestRun(t, func() error {
		return runAgent(context.Background(), &GlobalParams{})
	})
}
