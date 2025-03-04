// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

package scheduler

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-agent/comp/core/autodiscovery/integration"
)

func makeConfig(name string) integration.Config {
	return integration.Config{
		Name: name,
	}
}

type event struct {
	isSchedule bool
	configName string
}

type scheduler struct {
	events []event
	mutex  sync.Mutex
}

func (s *scheduler) Schedule(configs []integration.Config) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for _, config := range configs {
		s.events = append(s.events, event{true, config.Name})
	}
}

func (s *scheduler) Unschedule(configs []integration.Config) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for _, config := range configs {
		s.events = append(s.events, event{false, config.Name})
	}
}

func (s *scheduler) Stop() {}

func (s *scheduler) reset() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.events = []event{}
}

func TestController(t *testing.T) {
	t.Run("basic scheduling and registration", func(t *testing.T) {
		ms := NewController()

		// schedule some configs before registering
		c1 := makeConfig("one")
		c2 := makeConfig("two")
		ms.ApplyChanges(integration.ConfigChanges{Schedule: []integration.Config{c1, c2}})
		// register a scheduler and see that it gets caught up
		s1 := &scheduler{}
		ms.Register("s1", s1, true)
		// all configs are scheduled once and only once
		assert.EventuallyWithTf(t, func(c *assert.CollectT) {
			s1.mutex.Lock()
			assert.ElementsMatch(c, []event{{true, "one"}, {true, "two"}}, s1.events)
			s1.mutex.Unlock()
		}, 5*time.Second, 100*time.Millisecond, "Failed to process configs before timeout")
		assert.Neverf(t, func() bool {
			s1.mutex.Lock()
			defer s1.mutex.Unlock()
			return len(s1.events) != 2 // no more sch or unsch events should be received
		}, 2*time.Second, 100*time.Millisecond, "Unexpected event received, s1 events = %v", s1.events)
		s1.reset()

		// remove one of those configs and add another
		ms.ApplyChanges(integration.ConfigChanges{Unschedule: []integration.Config{c1}})
		c3 := makeConfig("three")
		ms.ApplyChanges(integration.ConfigChanges{Schedule: []integration.Config{c3}})
		// check s1 was informed about those in order
		assert.EventuallyWithTf(t, func(c *assert.CollectT) {
			s1.mutex.Lock()
			assert.ElementsMatch(c, []event{{false, "one"}, {true, "three"}}, s1.events)
			s1.mutex.Unlock()
		}, 5*time.Second, 100*time.Millisecond, "Failed to process configs before timeout")
		s1.reset()

		// subscribe a new scheduler and see that it does not get c1
		s2 := &scheduler{}
		ms.Register("s2", s2, true)
		assert.Neverf(t, func() bool {
			s2.mutex.Lock()
			defer s2.mutex.Unlock()
			return len(s2.events) != 2
		}, 2*time.Second, 100*time.Millisecond, "Unexpected event received, s2 events = %v", s2.events)
		assert.ElementsMatch(t, []event{{true, "two"}, {true, "three"}}, s2.events)
		s2.reset()

		// unsubscribe s1 and see that it no longer gets events
		ms.Deregister("s1")
		ms.ApplyChanges(integration.ConfigChanges{Unschedule: []integration.Config{c2}})
		assert.Neverf(t, func() bool {
			s1.mutex.Lock()
			defer s1.mutex.Unlock()
			return len(s1.events) > 0
		}, 2*time.Second, 100*time.Millisecond, "Unexpected event received")

		assert.EventuallyWithTf(t, func(c *assert.CollectT) {
			s2.mutex.Lock()
			assert.ElementsMatch(c, []event{{false, "two"}}, s2.events)
			s2.mutex.Unlock()
		}, 5*time.Second, 100*time.Millisecond, "Failed to process configs before timeout")
		s2.reset()

		// verify that replay does not occur if not desired
		s3 := &scheduler{}
		ms.Register("s3", s3, false)
		assert.Neverf(t, func() bool {
			s3.mutex.Lock()
			defer s3.mutex.Unlock()
			return len(s3.events) > 0
		}, 2*time.Second, 100*time.Millisecond, "Unexpected event received")
		ms.Stop()
		s3.reset()
	})

	t.Run("concurrent map access", func(t *testing.T) {
		ms := NewController()
		s1 := &scheduler{}
		ms.Register("s1", s1, true)

		// Create configs to schedule/unschedule
		configs := make([]integration.Config, 100)
		for i := 0; i < 100; i++ {
			configs[i] = makeConfig(fmt.Sprintf("config-%d", i))
		}

		// Run concurrent goroutines that schedule and unschedule configs
		var wg sync.WaitGroup
		wg.Add(2)

		// Goroutine 1: Schedule configs
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				ms.ApplyChanges(integration.ConfigChanges{
					Schedule: []integration.Config{configs[i]},
				})
			}
		}()

		// Goroutine 2: Unschedule configs
		go func() {
			defer wg.Done()
			for i := 50; i < 100; i++ {
				ms.ApplyChanges(integration.ConfigChanges{
					Unschedule: []integration.Config{configs[i]},
				})
			}
		}()

		// Wait for all operations to complete
		wg.Wait()

		// Verify no panic occurred and operations completed
		assert.EventuallyWithTf(t, func(c *assert.CollectT) {
			s1.mutex.Lock()
			eventCount := len(s1.events)
			s1.mutex.Unlock()
			assert.True(c, eventCount > 0, "Expected some events to be processed")
		}, 5*time.Second, 100*time.Millisecond, "Failed to process configs before timeout")

		ms.Stop()
	})
}
