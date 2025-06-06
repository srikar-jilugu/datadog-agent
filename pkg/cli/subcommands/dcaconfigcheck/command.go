// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package dcaconfigcheck builds a 'configcheck' command to be used in binaries.
package dcaconfigcheck

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/comp/core"
	"github.com/DataDog/datadog-agent/comp/core/config"
	log "github.com/DataDog/datadog-agent/comp/core/log/def"
	clusterAgentFlare "github.com/DataDog/datadog-agent/pkg/flare/clusteragent"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

// GlobalParams contains the values of agent-global Cobra flags.
//
// A pointer to this type is passed to SubcommandFactory's, but its contents
// are not valid until Cobra calls the subcommand's Run or RunE function.
type GlobalParams struct {
	ConfFilePath string
	NoColor      bool
}

type cliParams struct {
	verbose bool
}

// MakeCommand returns a `configcheck` command to be used by cluster-agent
// binaries.
func MakeCommand(globalParamsGetter func() GlobalParams) *cobra.Command {
	cliParams := &cliParams{}
	cmd := &cobra.Command{
		Use:     "configcheck",
		Aliases: []string{"checkconfig"},
		Short:   "Print all configurations loaded & resolved of a running cluster agent",
		Long:    ``,
		RunE: func(*cobra.Command, []string) error {
			globalParams := globalParamsGetter()

			return fxutil.OneShot(run,
				fx.Supply(cliParams),
				fx.Supply(core.BundleParams{
					ConfigParams: config.NewClusterAgentParams(globalParams.ConfFilePath),
					LogParams:    log.ForOneShot("CLUSTER", "off", true),
				}),
				core.Bundle(),
			)
		},
	}

	cmd.Flags().BoolVarP(&cliParams.verbose, "verbose", "v", false, "print additional debug info")

	return cmd
}

func run(_ log.Component, _ config.Component, cliParams *cliParams) error {
	if err := clusterAgentFlare.GetClusterAgentConfigCheck(color.Output, cliParams.verbose); err != nil {
		return fmt.Errorf("the agent ran into an error while checking config: %w", err)
	}

	return nil
}
