// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package main implements the entrypoint of the `trace-agent` binary.
package main

import (
	"log"
	"os"

	"net/http"
	_ "net/http/pprof"

	"github.com/DataDog/datadog-agent/cmd/internal/runcmd"
	"github.com/DataDog/datadog-agent/cmd/trace-agent/command"
	"github.com/DataDog/datadog-agent/pkg/util/flavor"
)

func main() {
	go func() {
		log.Println("Starting pprof server on port 6060")
		log.Fatal(http.ListenAndServe(":6161", nil))
	}()
	flavor.SetFlavor(flavor.TraceAgent)

	os.Args = command.FixDeprecatedFlags(os.Args, os.Stdout)

	os.Exit(runcmd.Run(command.MakeRootCommand()))
}
