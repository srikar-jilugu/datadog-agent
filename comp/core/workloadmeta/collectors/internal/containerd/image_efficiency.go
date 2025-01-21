// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build containerd && trivy

package containerd

import (
	"context"
	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	"github.com/DataDog/datadog-agent/pkg/util/efficiency"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

func (c *collector) startEfficiencyCollection(ctx context.Context) error {

	filter := workloadmeta.NewFilterBuilder().
		SetEventType(workloadmeta.EventTypeSet).
		AddKind(workloadmeta.KindContainerImageMetadata).
		Build()

	imgEventsCh := c.store.Subscribe(
		"Efficiency collector",
		workloadmeta.NormalPriority,
		filter,
	)
	go c.handleImageEfficiencyEvents(ctx, imgEventsCh)
	return nil
}

func (c *collector) handleImageEfficiencyEvents(ctx context.Context, imgEventsCh <-chan workloadmeta.EventBundle) {
	for {
		select {
		case <-ctx.Done():
			return
		case eventBundle, ok := <-imgEventsCh:
			if !ok {
				log.Warnf("Event channel closed, exiting event handling loop.")
				return
			}
			c.handleEfficiencyEventBundle(eventBundle)
		}
	}
}

// handleEventBundle handles ContainerImageMetadata set events for which no SBOM generation attempt was done.
func (c *collector) handleEfficiencyEventBundle(eventBundle workloadmeta.EventBundle) {
	eventBundle.Acknowledge()
	log.Infof("Handling efficiency event bundle with %d events.", len(eventBundle.Events))
	for _, event := range eventBundle.Events {
		image := event.Entity.(*workloadmeta.ContainerImageMetadata)

		// If efficiency has already been calculated, skip the processing
		if image.Efficiency != nil {
			log.Infof("Skipping efficiency calculation for image %s, already calculated.", image.ID)
			continue
		}

		// Start efficiency calculation in a background goroutine
		go func() {
			if err := c.calculateEfficiencyForImage(image.ID); err != nil {
				log.Errorf("Error calculating efficiency for image %s: %v", image.ID, err)
			}
		}()
	}

	log.Infof("Finished processing efficiency event bundle with %d events.", len(eventBundle.Events))
}

func (c *collector) calculateEfficiencyForImage(imageID string) error {
	// Fetch the image from the workloadmeta store
	log.Infof("Fetching image metadata for image %s.", imageID)
	wmImage, err := c.store.GetImage(imageID)
	if err != nil {
		log.Errorf("Unable to fetch image %s: %v", imageID, err)
		return err
	}

	// Perform the efficiency calculation
	image, err := c.containerdClient.Image(wmImage.Namespace, wmImage.Name)
	if err != nil {
		log.Errorf("Error fetching image %s: %v", imageID, err)
		return err
	}
	log.Infof("Calculating efficiency for image %s.", imageID)
	report, err := efficiency.GetEfficiencyReportFromImage(image)
	if err != nil {
		log.Errorf("Error calculating efficiency for image %s: %v", imageID, err)
		return err
	}

	// Update the image with the efficiency report
	wmReport := c.convertEfficiencyReportToWorkloadMeta(report)
	c.notifyStoreWithEfficiencyForImage(imageID, wmReport)
	return nil
}

func (c *collector) convertEfficiencyReportToWorkloadMeta(report *efficiency.EfficiencyReport) *workloadmeta.Efficiency {
	if report == nil {
		return nil
	}
	return &workloadmeta.Efficiency{
		Score:               report.Score,
		TotalDiscoveredSize: report.TotalDiscoveredSize,
		TotalMinSize:        report.TotalMinSize,
	}
}

// notifyStoreWithEfficiencyForImage notifies the store with the calculated efficiency report for the image.
func (c *collector) notifyStoreWithEfficiencyForImage(imageID string, report *workloadmeta.Efficiency) {
	log.Infof("Notifying store with efficiency report for image %s.", imageID)
	if report == nil {
		log.Warnf("Efficiency report for image %s is nil, skipping notification.", imageID)
		return
	} else {
		log.Infof("Efficiency report for image %s: score=%f, totalDiscoveredSize=%d, totalMinSize=%d",
			imageID, report.Score, report.TotalDiscoveredSize, report.TotalMinSize)
	}
	c.store.Notify([]workloadmeta.CollectorEvent{
		{
			Type:   workloadmeta.EventTypeSet,
			Source: workloadmeta.SourceEfficiency,
			Entity: &workloadmeta.ContainerImageMetadata{
				EntityID: workloadmeta.EntityID{
					Kind: workloadmeta.KindContainerImageMetadata,
					ID:   imageID,
				},
				Efficiency: &workloadmeta.Efficiency{
					Score:               report.Score,
					TotalDiscoveredSize: report.TotalDiscoveredSize,
					TotalMinSize:        report.TotalMinSize,
				},
			},
		},
	})
}
