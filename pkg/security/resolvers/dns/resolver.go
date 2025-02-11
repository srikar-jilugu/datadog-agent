// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

// Package envvars holds envvars related files
package dns

import (
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/security/probe/config"
	lru "github.com/hashicorp/golang-lru/v2"
	"net/netip"
)

// Resolver defines a resolver
type Resolver struct {
	cache *lru.Cache[netip.Addr, map[string]bool]
}

// NewDnsResolver returns a new resolver
func NewDnsResolver(cfg *config.Config) *Resolver {
	c, _ := lru.New[netip.Addr, map[string]bool](cfg.DNSResolverCacheSize)
	return &Resolver{
		cache: c,
	}
}

// HostFromIp gets a hostname from an IP address if cached
func (r *Resolver) HostListFromIp(addr netip.Addr) []string {

	hostname, ok := r.cache.Get(addr)
	if ok {
		ret := make([]string, 0)
		for k, _ := range hostname {
			ret = append(ret, k)
		}
		fmt.Printf("DNS Resolving host from IP. IP=%v. Host=%v. ok=%v\n", addr, ret, ok)
		return ret
	}
	return nil
}

// AddNew add new ip address to the resolver cache
func (r *Resolver) AddNew(hostname string, ip netip.Addr) {
	fmt.Printf("DNS Adding new IP %v resolving to host %v\n", ip, hostname)
	hostnames, ok := r.cache.Get(ip)

	if !ok {
		hostnames = map[string]bool{}
	}

	hostnames[hostname] = true
	r.cache.Add(ip, hostnames)
}
