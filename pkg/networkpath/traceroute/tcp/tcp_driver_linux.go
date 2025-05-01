// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build linux

package tcp

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"

	"github.com/DataDog/datadog-agent/pkg/networkpath/traceroute/common"
	"github.com/DataDog/datadog-agent/pkg/networkpath/traceroute/filter"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type handle struct {
	conn   *ipv4.RawConn
	parser *common.FrameParser
	buffer []byte
}

type tcpDriver struct {
	tcpHandle   *handle
	icmpHandle  *handle
	sendTimes   []time.Time
	localAddr   netip.Addr
	localPort   uint16
	target      netip.AddrPort
	seqNum      uint32
	tcpListener net.Listener
}

func newHandle(conn *ipv4.RawConn) *handle {
	return &handle{
		conn:   conn,
		parser: common.NewFrameParser(),
		buffer: make([]byte, 1024),
	}
}

// NewDriver creates a new TCP traceroute driver for parallel operation
func NewDriver(ctx context.Context, target netip.AddrPort) (*tcpDriver, error) {
	// Create a TCP listener to get a random port
	_, tcpListener, err := reserveLocalPort()
	if err != nil {
		return nil, fmt.Errorf("failed to create TCP listener: %w", err)
	}
	localAddrPort := tcpListener.Addr().(*net.TCPAddr).AddrPort()
	localAddr := localAddrPort.Addr()

	// Create socket filter for TCP
	filterCfg := filter.TCP4FilterConfig{
		Src: target,
		Dst: localAddrPort,
	}
	filterProg, err := filterCfg.GenerateTCP4Filter()
	if err != nil {
		return nil, fmt.Errorf("failed to generate TCP4 filter: %w", err)
	}
	tcpLc := &net.ListenConfig{
		Control: func(_network, _address string, c syscall.RawConn) error {
			return filter.SetBPFAndDrain(c, filterProg)
		},
	}

	// Create raw sockets for TCP and ICMP
	tcpConn, err := filter.MakeRawConn(ctx, tcpLc, "ip4:tcp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to make TCP raw conn: %w", err)
	}
	icmpConn, err := filter.MakeRawConn(ctx, &net.ListenConfig{}, "ip:icmp", localAddr)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("failed to make ICMP raw conn: %w", err)
	}

	retval := &tcpDriver{
		tcpHandle:   newHandle(tcpConn),
		icmpHandle:  newHandle(icmpConn),
		sendTimes:   make([]time.Time, 256), // Max TTL is 255
		localAddr:   localAddr,
		localPort:   localAddrPort.Port(),
		target:      target,
		seqNum:      rand.Uint32(),
		tcpListener: tcpListener,
	}
	return retval, nil
}

func (t *tcpDriver) Close() {
	t.tcpHandle.conn.Close()
	t.icmpHandle.conn.Close()
	t.tcpListener.Close()
}

func (t *tcpDriver) GetDriverInfo() common.TracerouteDriverInfo {
	return common.TracerouteDriverInfo{
		UsesReceiveICMPProbe: true,
	}
}

func (t *tcpDriver) SendProbe(ttl uint8) error {
	if ttl < 1 || ttl > 255 {
		return fmt.Errorf("invalid TTL %d", ttl)
	}
	if !t.sendTimes[ttl].IsZero() {
		return fmt.Errorf("probe for TTL %d was already sent", ttl)
	}
	t.sendTimes[ttl] = time.Now()

	// Create TCP SYN packet
	tcpHeader, tcpPacket, err := t.createRawTCPSyn(ttl)
	if err != nil {
		return fmt.Errorf("failed to create TCP packet: %w", err)
	}

	log.Tracef("sending TCP SYN with TTL %d", ttl)
	err = t.tcpHandle.conn.WriteTo(tcpHeader, tcpPacket, nil)
	if err != nil {
		return fmt.Errorf("failed to send TCP SYN: %w", err)
	}
	return nil
}

func (t *tcpDriver) ReceiveProbe(timeout time.Duration) (*common.ProbeResponse, error) {
	return t.receiveProbe(t.tcpHandle, timeout)
}

func (t *tcpDriver) ReceiveICMPProbe(timeout time.Duration) (*common.ProbeResponse, error) {
	return t.receiveProbe(t.icmpHandle, timeout)
}

func (t *tcpDriver) receiveProbe(handle *handle, timeout time.Duration) (*common.ProbeResponse, error) {
	err := handle.conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return nil, fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Read and parse the packet
	header, payload, _, err := handle.conn.ReadFrom(handle.buffer)
	if err != nil {
		return nil, common.ErrReceiveProbeNoPkt
	}

	err = handle.parser.ParseIPv4(payload)
	if err != nil {
		return nil, &common.BadPacketError{Err: fmt.Errorf("failed to parse IPv4 packet: %w", err)}
	}

	// Handle the response based on the transport layer
	switch handle.parser.GetTransportLayer() {
	case layers.LayerTypeTCP:
		ipPair, err := handle.parser.GetIPPair()
		if err != nil {
			return nil, fmt.Errorf("failed to get IP pair: %w", err)
		}

		// Check if this is a response to our probe
		if ipPair != t.ExpectedIPPair() {
			return nil, common.ErrReceiveProbeNoPkt
		}

		// Check ports
		if t.target.Port() != uint16(handle.parser.TCP.SrcPort) ||
			t.localPort != uint16(handle.parser.TCP.DstPort) {
			return nil, common.ErrReceiveProbeNoPkt
		}

		// If we get a SYN-ACK, we've reached the destination
		if handle.parser.TCP.SYN && handle.parser.TCP.ACK {
			ttl := uint8(header.TTL)
			rtt := time.Since(t.sendTimes[ttl])
			return &common.ProbeResponse{
				TTL:    ttl,
				IP:     ipPair.SrcAddr,
				RTT:    rtt,
				IsDest: true,
			}, nil
		}

		return nil, common.ErrReceiveProbeNoPkt

	case layers.LayerTypeICMPv4:
		icmpInfo, err := handle.parser.GetICMPInfo()
		if err != nil {
			return nil, &common.BadPacketError{Err: fmt.Errorf("failed to get ICMP info: %w", err)}
		}

		// We only care about TTL exceeded
		if icmpInfo.ICMPType != common.TTLExceeded4 {
			return nil, common.ErrReceiveProbeNoPkt
		}

		// Parse the TCP info from the ICMP payload
		tcpInfo, err := common.ParseTCPFirstBytes(icmpInfo.Payload)
		if err != nil {
			return nil, &common.BadPacketError{Err: fmt.Errorf("failed to parse TCP info: %w", err)}
		}

		// Check if this is a response to our probe
		icmpDst := netip.AddrPortFrom(icmpInfo.ICMPPair.DstAddr, tcpInfo.DstPort)
		if icmpDst != t.target {
			return nil, common.ErrReceiveProbeNoPkt
		}

		// Calculate TTL from sequence number
		ttl := uint8(tcpInfo.Seq - t.seqNum)
		if ttl < 1 || ttl > 255 {
			return nil, &common.BadPacketError{Err: fmt.Errorf("invalid TTL from sequence number: %d", ttl)}
		}

		rtt := time.Since(t.sendTimes[ttl])
		return &common.ProbeResponse{
			TTL:    ttl,
			IP:     icmpInfo.IPPair.SrcAddr,
			RTT:    rtt,
			IsDest: false,
		}, nil

	default:
		return nil, common.ErrReceiveProbeNoPkt
	}
}

func (t *tcpDriver) ExpectedIPPair() common.IPPair {
	return common.IPPair{
		SrcAddr: t.target.Addr(),
		DstAddr: t.localAddr,
	}
}

func (t *tcpDriver) createRawTCPSyn(ttl uint8) (*ipv4.Header, []byte, error) {
	// Create IPv4 header
	ipHeader := &ipv4.Header{
		Version:  4,
		Len:      20,
		TTL:      int(ttl),
		Protocol: 6, // TCP
		Src:      t.localAddr.AsSlice(),
		Dst:      t.target.Addr().AsSlice(),
	}

	// Create TCP header
	tcpHeader := &layers.TCP{
		SrcPort: layers.TCPPort(t.localPort),
		DstPort: layers.TCPPort(t.target.Port()),
		Seq:     t.seqNum + uint32(ttl),
		SYN:     true,
		Window:  14600,
	}

	// Serialize the packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buf, opts, tcpHeader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize TCP packet: %w", err)
	}

	return ipHeader, buf.Bytes(), nil
}

var _ common.TracerouteDriver = &tcpDriver{}
