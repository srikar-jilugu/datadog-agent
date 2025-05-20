// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package tcp

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/pkg/networkpath/traceroute/common"
	"github.com/DataDog/datadog-agent/pkg/networkpath/traceroute/packets"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/google/gopacket/layers"
)

// Params is extra TCP parameters specific to the tcpDriver
// TODO combine this with TCPv4?
type Params struct {
	// LoosenICMPSrc disables checking the source IP/port in ICMP payloads when enabled.
	// Reason: Some environments don't properly translate the payload of an ICMP TTL exceeded
	// packet meaning you can't trust the source address to correspond to your own private IP.
	LoosenICMPSrc bool
}

type probeData struct {
	sendTime time.Time
	ttl      uint8
	packetID uint16
	seqNum   uint32
}

type tcpDriver struct {
	config *TCPv4
	params Params

	sink packets.Sink

	source packets.Source
	buffer []byte
	parser *packets.FrameParser

	// mu guards against concurrent use of sentProbes
	mu         sync.Mutex
	sentProbes []probeData

	// if CompatibilityMode is enabled, we randomize the packet ID starting from this base
	basePacketID uint16
	// if CompatibilityMode is enabled, we store a single seqNum for the duration of the traceroute
	seqNum uint32

	portReservation net.Listener
}

var _ common.TracerouteDriver = &tcpDriver{}

func newTCPDriver(config *TCPv4, params Params, sink packets.Sink, source packets.Source) (*tcpDriver, error) {
	var basePacketID uint16
	var seqNum uint32
	if config.CompatibilityMode {
		basePacketID = uint16(rand.Uint32())
		seqNum = rand.Uint32()
	}

	addr, conn, err := common.LocalAddrForHost(config.Target, config.DestPort)
	if err != nil {
		return nil, fmt.Errorf("failed to get local address for target: %w", err)
	}
	conn.Close() // we don't need the UDP port here
	config.srcIP = addr.IP

	port, tcpListener, err := reserveLocalPort()
	if err != nil {
		return nil, fmt.Errorf("failed to create TCP listener: %w", err)
	}
	config.srcPort = port

	return &tcpDriver{
		config: config,
		params: params,

		sink: sink,

		source: source,
		buffer: make([]byte, 1024),
		parser: packets.NewFrameParser(),

		sentProbes: nil,

		basePacketID: basePacketID,
		seqNum:       seqNum,

		portReservation: tcpListener,
	}, nil
}

func (t *tcpDriver) storeProbe(probeData probeData) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sentProbes = append(t.sentProbes, probeData)
}

func (t *tcpDriver) findMatchingProbe(packetID *uint16, seqNum *uint32) probeData {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, probe := range t.sentProbes {
		if packetID != nil && probe.packetID != *packetID {
			continue
		}
		if seqNum != nil && probe.seqNum != *seqNum {
			continue
		}
		return probe
	}
	return probeData{}
}
func (t *tcpDriver) getLastSentProbe() (probeData, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.GetDriverInfo().SupportsParallel {
		return probeData{}, fmt.Errorf("getLastSentProbe is only possible in a serial traceroute")
	}

	if len(t.sentProbes) == 0 {
		return probeData{}, fmt.Errorf("getLastSentProbe was called before we sent anything")
	}
	return t.sentProbes[len(t.sentProbes)-1], nil
}

func (t *tcpDriver) getLocalAddrPort() netip.AddrPort {
	addr, _ := common.UnmappedAddrFromSlice(t.config.srcIP)
	return netip.AddrPortFrom(addr, t.config.srcPort)

}

func (t *tcpDriver) getTargetAddrPort() netip.AddrPort {
	addr, _ := common.UnmappedAddrFromSlice(t.config.Target)
	return netip.AddrPortFrom(addr, t.config.DestPort)
}

// GetDriverInfo returns metadata about this driver
func (t *tcpDriver) GetDriverInfo() common.TracerouteDriverInfo {
	return common.TracerouteDriverInfo{
		// in compatibility mode, we can't support parallel
		SupportsParallel: !t.config.CompatibilityMode,
	}
}

func (t *tcpDriver) getNextPacketIDAndSeqNum(ttl uint8) (uint16, uint32) {
	if t.config.CompatibilityMode {
		return t.basePacketID + uint16(ttl), t.seqNum
	}
	return 41821, rand.Uint32()
}

// SendProbe sends a traceroute packet with a specific TTL
func (t *tcpDriver) SendProbe(ttl uint8) error {
	packetID, seqNum := t.getNextPacketIDAndSeqNum(ttl)
	_, buffer, _, err := t.config.createRawTCPSynBuffer(packetID, seqNum, int(ttl))
	if err != nil {
		return fmt.Errorf("tcpDriver SendProbe failed to createRawTCPSynBuffer: %w", err)
	}

	log.Tracef("sending probe with ttl=%d, packetID=%d, seqNum=%d", ttl, packetID, seqNum)
	t.storeProbe(probeData{
		sendTime: time.Now(),
		ttl:      ttl,
		packetID: packetID,
		seqNum:   seqNum,
	})

	err = t.sink.WriteTo(buffer, t.getTargetAddrPort())
	if err != nil {
		return fmt.Errorf("tcpDriver SendProbe failed to write packet: %w", err)
	}
	return nil
}

// ReceiveProbe polls to get a traceroute response with a timeout.
func (t *tcpDriver) ReceiveProbe(timeout time.Duration) (*common.ProbeResponse, error) {
	err := t.source.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return nil, fmt.Errorf("tcpDriver failed to SetReadDeadline: %w", err)
	}

	err = packets.ReadAndParse(t.source, t.buffer, t.parser)
	if err != nil {
		return nil, err
	}

	return t.handleProbeLayers(t.parser)
}

func (t *tcpDriver) ExpectedIPPair() packets.IPPair {
	// from the target to us
	return packets.IPPair{
		SrcAddr: t.getTargetAddrPort().Addr(),
		DstAddr: t.getLocalAddrPort().Addr(),
	}
}

var errPacketDidNotMatchTraceroute = &common.ReceiveProbeNoPktError{Err: fmt.Errorf("packet did not match the traceroute")}

func (t *tcpDriver) handleProbeLayers(parser *packets.FrameParser) (*common.ProbeResponse, error) {
	ipPair, err := parser.GetIPPair()
	if err != nil {
		return nil, fmt.Errorf("tcpDriver failed to get IP pair: %w", err)
	}

	var probe probeData
	var isDest bool

	switch parser.GetTransportLayer() {
	case layers.LayerTypeTCP:
		// we only care about SYNACK
		if !(parser.TCP.SYN && parser.TCP.ACK) {
			return nil, errPacketDidNotMatchTraceroute
		}
		log.Tracef("saw synack")

		if ipPair != t.ExpectedIPPair() {
			return nil, errPacketDidNotMatchTraceroute
		}
		log.Tracef("ports?")
		// make sure the ports match
		if t.config.DestPort != uint16(parser.TCP.SrcPort) ||
			t.config.srcPort != uint16(parser.TCP.DstPort) {
			return nil, errPacketDidNotMatchTraceroute
		}

		expectedSeq := parser.TCP.Ack - 1

		log.Tracef("time to go")
		if t.config.CompatibilityMode {
			// in mode, traceroute is serialized and all we can do is use the most recent probe
			lastProbe, err := t.getLastSentProbe()
			if err != nil {
				return nil, fmt.Errorf("tcpDriver handleProbeLayers failed to getLastSentProbe: %w", err)
			}
			log.Tracef("last probe %+v", lastProbe)
			if lastProbe.seqNum == expectedSeq {
				probe = lastProbe
			}
		} else {
			// find the probe with the matching seq number
			probe = t.findMatchingProbe(nil, &expectedSeq)
		}

		if probe == (probeData{}) {
			log.Warnf("got synack but couldn't find probe matching seqNum=%d", expectedSeq)

		}
		isDest = true
	case layers.LayerTypeICMPv4:
		log.Tracef("saw icmp")
		icmpInfo, err := parser.GetICMPInfo()
		if err != nil {
			return nil, &common.BadPacketError{Err: fmt.Errorf("sackDriver failed to get ICMP info: %w", err)}
		}
		if icmpInfo.ICMPType != packets.TTLExceeded4 {
			return nil, errPacketDidNotMatchTraceroute
		}

		// make sure the source/destination match
		tcpInfo, err := packets.ParseTCPFirstBytes(icmpInfo.Payload)
		if err != nil {
			return nil, &common.BadPacketError{Err: fmt.Errorf("sackDriver failed to parse TCP info: %w", err)}
		}

		icmpDst := netip.AddrPortFrom(icmpInfo.ICMPPair.DstAddr, tcpInfo.DstPort)
		if icmpDst != t.getTargetAddrPort() {
			return nil, errPacketDidNotMatchTraceroute
		}
		if !t.params.LoosenICMPSrc {
			icmpSrc := netip.AddrPortFrom(icmpInfo.IPPair.SrcAddr, tcpInfo.SrcPort)
			expectedSrc := t.getLocalAddrPort()
			if icmpSrc != expectedSrc {
				log.Tracef("icmp src mismatch. expected: %s actual: %s", expectedSrc, icmpSrc)
				return nil, errPacketDidNotMatchTraceroute
			}
		}

		probe = t.findMatchingProbe(&icmpInfo.WrappedPacketID, &tcpInfo.Seq)
		if probe == (probeData{}) {
			log.Warnf("couldn't find probe matching packetID=%d and seqNum=%d", icmpInfo.WrappedPacketID, tcpInfo.Seq)
		}
	default:
		return nil, errPacketDidNotMatchTraceroute
	}

	if probe == (probeData{}) {
		return nil, errPacketDidNotMatchTraceroute
	}
	rtt := time.Since(probe.sendTime)

	return &common.ProbeResponse{
		TTL:    probe.ttl,
		IP:     ipPair.SrcAddr,
		RTT:    rtt,
		IsDest: isDest,
	}, nil
}

// Close closes the tcpDriver
func (t *tcpDriver) Close() error {
	sinkErr := t.sink.Close()
	sourceErr := t.source.Close()
	portErr := t.portReservation.Close()
	return errors.Join(sinkErr, sourceErr, portErr)
}
