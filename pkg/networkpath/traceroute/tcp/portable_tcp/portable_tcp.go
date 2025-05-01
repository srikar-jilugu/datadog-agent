// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/DataDog/datadog-agent/pkg/networkpath/traceroute/tcp"

	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	pkglogsetup "github.com/DataDog/datadog-agent/pkg/util/log/setup"
)

func main() {
	loglevel := os.Getenv("LOG_LEVEL")
	if loglevel == "" {
		loglevel = "debug"
	}

	pkglogsetup.SetupLogger(
		pkglogsetup.LoggerName("sack"),
		loglevel,
		"",
		"",
		false,
		true,
		false,
		pkgconfigsetup.Datadog(),
	)

	if len(os.Args) < 2 {
		println("Usage: portable_sack <target>")
		os.Exit(1)
	}
	target := os.Args[1]

	addrPort := netip.MustParseAddrPort(target)

	cfg := tcp.NewTCPv4(addrPort.Addr().AsSlice(), addrPort.Port(), 1, 1, 30, 0, time.Second)

	results, err := cfg.TracerouteSequential()
	if err != nil {
		fmt.Printf("Traceroute failed: %s\n", err)
		os.Exit(1)
	}
	json, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("Error marshalling results: %s\n", err)
		os.Exit(1)
	}
	println(string(json))
}
