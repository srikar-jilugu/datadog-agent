// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package main

import (
	"context"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/multierr"
)

type (
	packetResponse struct {
		IP   net.IP
		Type uint8
		Code uint8
		Port uint16
		Time time.Time
		Err  error
	}
)

func foo() packetResponse {
	return packetResponse{IP: net.ParseIP("127.0.0.1")}
}
func block(ctx context.Context) packetResponse {
	<-ctx.Done()
	return packetResponse{Err: os.ErrDeadlineExceeded}
}

func blast() packetResponse {
	respChan := make(chan packetResponse, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup
	var wrote, read atomic.Bool
	defer func() {
		wg.Wait()
		if !wrote.Load() {
			panic("should have wrote")
		}
		if !read.Load() {
			panic("should have read")
		}
	}()

	wg.Add(1)
	go func() {
		respChan <- foo()
		wrote.Store(true)
		wg.Done()
	}()
	go func() {
		respChan <- block(ctx)
	}()
	// wait for both responses to return
	// as one could error even if the other
	// succeeds
	var err error
	for i := 0; i < 2; i++ {
		select {
		case <-ctx.Done():
			println("timed out waiting for responses")
			return packetResponse{
				Err: err,
			}
		case resp := <-respChan:
			read.Store(true)
			if resp.Err == nil {
				return resp
			}
			// avoid adding canceled errors to the error list
			// TODO: maybe just return nil on timeout?
			err = multierr.Append(err, resp.Err)
		}
	}
	return packetResponse{
		Err: err,
	}
}

func main() {
	for i := range 10000000 {
		if i%100000 == 0 {
			println("iter ", i)
		}
		blast()
	}
}
