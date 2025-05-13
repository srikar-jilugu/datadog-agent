// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package checks

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	model "github.com/DataDog/agent-payload/v5/process"
	"github.com/DataDog/datadog-go/v5/statsd"

	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	pkgconfigmodel "github.com/DataDog/datadog-agent/pkg/config/model"
	proccontainers "github.com/DataDog/datadog-agent/pkg/process/util/containers"
	"github.com/DataDog/datadog-agent/pkg/system-probe/api/client"
	"github.com/DataDog/datadog-agent/pkg/util/flavor"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const (
	cacheValidityNoRT = 2 * time.Second
)

// NewContainerCheck returns an instance of the ContainerCheck.
func NewContainerCheck(config pkgconfigmodel.Reader, wmeta workloadmeta.Component, statsd statsd.ClientInterface) *ContainerCheck {
	return &ContainerCheck{
		config: config,
		wmeta:  wmeta,
		statsd: statsd,
	}
}

// ContainerCheck is a check that returns container metadata and stats.
type ContainerCheck struct {
	sync.Mutex

	config pkgconfigmodel.Reader

	hostInfo          *HostInfo
	containerProvider proccontainers.ContainerProvider
	lastRates         map[string]*proccontainers.ContainerRateMetrics
	networkID         string

	containerFailedLogLimit *log.Limit

	maxBatchSize int
	wmeta        workloadmeta.Component

	sysprobeClient *http.Client
	statsd         statsd.ClientInterface
}

// Init initializes a ContainerCheck instance.
func (c *ContainerCheck) Init(syscfg *SysProbeConfig, info *HostInfo, _ bool) error {
	sharedContainerProvider, err := proccontainers.GetSharedContainerProvider()
	if err != nil {
		return err
	}
	c.containerProvider = sharedContainerProvider
	c.hostInfo = info

	if syscfg.NetworkTracerModuleEnabled {
		c.sysprobeClient = client.Get(syscfg.SystemProbeAddress)
	}

	networkID, err := retryGetNetworkID(c.sysprobeClient)
	if err != nil {
		log.Infof("no network ID detected: %s", err)
	}
	c.networkID = networkID

	c.containerFailedLogLimit = log.NewLogLimit(10, time.Minute*10)
	c.maxBatchSize = getMaxBatchSize(c.config)
	return nil
}

// IsEnabled returns true if the check is enabled by configuration
// Keep in mind that ContainerRTCheck.IsEnabled should only be enabled if the `ContainerCheck` is enabled
func (c *ContainerCheck) IsEnabled() bool {
	if c.config.GetBool("process_config.run_in_core_agent.enabled") && flavor.GetFlavor() == flavor.ProcessAgent {
		return false
	}

	return canEnableContainerChecks(c.config, true)
}

// SupportsRunOptions returns true if the check supports RunOptions
func (c *ContainerCheck) SupportsRunOptions() bool {
	return false
}

// Name returns the name of the ProcessCheck.
func (c *ContainerCheck) Name() string { return ContainerCheckName }

// Realtime indicates if this check only runs in real-time mode.
func (c *ContainerCheck) Realtime() bool { return false }

// ShouldSaveLastRun indicates if the output from the last run should be saved for use in flares
func (c *ContainerCheck) ShouldSaveLastRun() bool { return true }

// Run runs the ContainerCheck to collect a list of running ctrList and the
// stats for each container.
//
//nolint:revive // TODO(PROC) Fix revive linter
func (c *ContainerCheck) Run(nextGroupID func() int32, options *RunOptions) (RunResult, error) {
	c.Lock()
	defer c.Unlock()
	startTime := time.Now()

	var err error
	var containers []*model.Container
	var lastRates map[string]*proccontainers.ContainerRateMetrics
	containers, lastRates, _, err = c.containerProvider.GetContainers(cacheValidityNoRT, c.lastRates)
	if err == nil {
		c.lastRates = lastRates
	} else {
		log.Debugf("Unable to gather stats for containers, err: %v", err)
	}

	if len(containers) == 0 {
		log.Trace("No containers found")
		return nil, nil
	}

	groupSize := len(containers) / c.maxBatchSize
	if len(containers)%c.maxBatchSize != 0 {
		groupSize++
	}

	// For no chunking, set groupsize as 1 to ensure one chunk
	if options != nil && options.NoChunking {
		groupSize = 1
	}

	chunked := chunkContainers(containers, groupSize)
	messages := make([]model.MessageBody, 0, groupSize)
	groupID := nextGroupID()
	for i := 0; i < groupSize; i++ {
		messages = append(messages, &model.CollectorContainer{
			HostName:          c.hostInfo.HostName,
			NetworkId:         c.networkID,
			Info:              c.hostInfo.SystemInfo,
			Containers:        chunked[i],
			GroupId:           groupID,
			GroupSize:         int32(groupSize),
			ContainerHostType: c.hostInfo.ContainerHostType,
		})
	}

	numContainers := float64(len(containers))
	agentNameTag := fmt.Sprintf("agent:%s", flavor.GetFlavor())
	_ = c.statsd.Gauge("datadog.process.containers.host_count", numContainers, []string{agentNameTag}, 1)
	log.Debugf("collected %d containers in %s", int(numContainers), time.Since(startTime))
	return StandardRunResult(messages), nil
}

// Cleanup frees any resource held by the ContainerCheck before the agent exits
func (c *ContainerCheck) Cleanup() {}

// chunkContainers formats and chunks the ctrList into a slice of chunks using a specific number of chunks.
// containers belonging to the same pod are guaranteed to be placed in the same chunk
func chunkContainers(containers []*model.Container, chunks int) [][]*model.Container {
	if chunks <= 0 || len(containers) == 0 {
		return nil
	}

	if chunks > len(containers) {
		chunks = len(containers)
	}

	podGroups := make(map[string][]*model.Container)
	ungrouped := make([]*model.Container, 0)

	// Find container's pod ID from its tags
	const podNameTag = "pod_name:"

	for _, ctr := range containers {
		var podID string
		for _, tag := range ctr.Tags {
			if strings.HasPrefix(tag, podNameTag) {
				podID = tag
				break
			}
		}
		if podID == "" {
			ungrouped = append(ungrouped, ctr)
		} else {
			podGroups[podID] = append(podGroups[podID], ctr)
		}
	}

	chunked := make([][]*model.Container, chunks)
	chunkSizes := make([]int, chunks) // Used to track the size of each chunk

	podGroupKeys := make([]string, 0, len(podGroups))
	for podID := range podGroups {
		podGroupKeys = append(podGroupKeys, podID)
	}
	sort.Slice(podGroupKeys, func(i, j int) bool {
		return len(podGroups[podGroupKeys[i]]) > len(podGroups[podGroupKeys[j]])
	})

	findSmallestChunk := func(chunkSizes []int) int {
		smallestIdx := 0
		for i := 1; i < chunks; i++ {
			if chunkSizes[i] < chunkSizes[smallestIdx] {
				smallestIdx = i
			}
		}
		return smallestIdx
	}

	// Assign each pod group to the chunk with the least containers
	for _, podID := range podGroupKeys {
		podGroup := podGroups[podID]

		smallestIdx := findSmallestChunk(chunkSizes)
		chunked[smallestIdx] = append(chunked[smallestIdx], podGroup...)
		chunkSizes[smallestIdx] += len(podGroup)
	}

	// Distribute each ungrouped container to the smallest chunk
	for _, ctr := range ungrouped {
		smallestIdx := findSmallestChunk(chunkSizes)
		chunked[smallestIdx] = append(chunked[smallestIdx], ctr)
		chunkSizes[smallestIdx]++
	}

	// Remove any empty chunks
	result := make([][]*model.Container, 0, chunks)
	for _, chunk := range chunked {
		if len(chunk) > 0 {
			result = append(result, chunk)
		}
	}

	return result
}
