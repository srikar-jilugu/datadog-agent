// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package usm

import (
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/network/usm/utils"
	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"
	"io"
	"os"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/protocols"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/events"
	"github.com/DataDog/datadog-agent/pkg/network/usm/buildmode"
)

type protocol struct {
	cfg            *config.Config
	eventsConsumer *events.Consumer[protocols.Message]
	mgr            *manager.Manager
	devnull        io.Writer
}

const (
	readSyscallEnter = "tracepoint__sys_enter_read"
	readSyscallExit  = "tracepoint__sys_exit_read"
)

var ExampleSpec = &protocols.ProtocolSpec{
	Factory: newExampleProtocol,
	Maps: []*manager.Map{
		{
			Name: "example_map",
		},
	},
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: readSyscallEnter,
				UID:          "example",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: readSyscallExit,
				UID:          "example",
			},
		},
	},
}

func newExampleProtocol(mgr *manager.Manager, cfg *config.Config) (protocols.Protocol, error) {
	return &protocol{cfg: cfg, mgr: mgr}, nil
}

// Name return the program's name.
func (p *protocol) Name() string {
	return "Example"
}

// ConfigureOptions add the necessary options for the http monitoring to work,
// to be used by the manager. These are:
// - Set the `http_in_flight` map size to the value of the `max_tracked_connection` configuration variable.
//
// We also configure the http event stream with the manager and its options.
func (p *protocol) ConfigureOptions(opts *manager.Options) {
	opts.MapSpecEditors["example_map"] = manager.MapSpecEditor{
		MaxEntries: 100000,
		EditorFlag: manager.EditMaxEntries,
	}
	opts.ActivatedProbes = append(opts.ActivatedProbes, &manager.ProbeSelector{
		ProbeIdentificationPair: manager.ProbeIdentificationPair{
			EBPFFuncName: readSyscallEnter,
			UID:          "example",
		},
	}, &manager.ProbeSelector{
		ProbeIdentificationPair: manager.ProbeIdentificationPair{
			EBPFFuncName: readSyscallExit,
			UID:          "example",
		},
	})

	utils.EnableOption(opts, "example_monitoring_enabled")

	// Configure event stream
	events.Configure(p.cfg, "example", p.mgr, opts)
}

func (p *protocol) PreStart() (err error) {
	p.eventsConsumer, err = events.NewConsumer(
		"example",
		p.mgr,
		p.processExample,
	)
	if err != nil {
		return
	}

	p.devnull, err = os.OpenFile("/dev/null", os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open /dev/null: %w", err)
	}

	p.eventsConsumer.Start()

	return
}

func (p *protocol) PostStart() error {
	return nil
}

func (p *protocol) Stop() {
	if p.eventsConsumer != nil {
		p.eventsConsumer.Stop()
	}
}

func (p *protocol) DumpMaps(io.Writer, string, *ebpf.Map) {}

func (p *protocol) processExample(events []protocols.Message) {
	for i := range events {
		tx := &events[i]
		p.devnull.Write([]byte(fmt.Sprintf("Processing event from pid %d comm: %s; len %d\n", tx.Pid, string(tx.Comm_name[:]), tx.Buf_len)))
	}
}

// GetStats returns a map of HTTP stats and a callback to clean resources.
// The format of HTTP stats:
// [source, dest tuple, request path] -> RequestStats object
func (p *protocol) GetStats() (*protocols.ProtocolStats, func()) {
	p.eventsConsumer.Sync()
	return &protocols.ProtocolStats{
		Type:  protocols.HTTP,
		Stats: nil,
	}, func() {}
}

// IsBuildModeSupported returns always true, as http module is supported by all modes.
func (*protocol) IsBuildModeSupported(buildmode.Type) bool {
	return true
}
