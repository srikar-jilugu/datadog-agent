// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build containerd

package efficiency

import (
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/containerd/containerd"
)

// File represents a file or directory within a container snapshot.
type File struct {
	Path string // Path to the file or directory
	Size int64  // Size of the file or directory
}

// EfficiencyData tracks file paths' efficiency (size, etc.) across snapshot layers.
type EfficiencyData struct {
	Path              string   // File path
	CumulativeSize    int64    // Total size of the file across layers
	MinDiscoveredSize int64    // Minimum size across layers (indicating potential optimization)
	Layers            []string // List of snapshot layers where the file appears
}

// EfficiencyReport is used to output the overall efficiency data.
type EfficiencyReport struct {
	Score               float64           // Efficiency score between 0 and 1
	InefficientFiles    []*EfficiencyData // List of inefficient files
	TotalDiscoveredSize int64             // Total size of all discovered files
	TotalMinSize        int64             // Total minimum size across files
}

// TrackFileEfficiency updates efficiency data for a file, accumulating size and tracking its path across layers.
func trackFileEfficiency(file *File, efficiencyMap map[string]*EfficiencyData, layerID string) {
	if _, ok := efficiencyMap[file.Path]; !ok {
		efficiencyMap[file.Path] = &EfficiencyData{
			Path:              file.Path,
			CumulativeSize:    0,
			MinDiscoveredSize: -1,
			Layers:            []string{},
		}
	}

	data := efficiencyMap[file.Path]
	data.CumulativeSize += file.Size
	if data.MinDiscoveredSize < 0 || file.Size < data.MinDiscoveredSize {
		data.MinDiscoveredSize = file.Size
	}

	// Track which layers the file appears in
	data.Layers = append(data.Layers, layerID)
}

// CalculateEfficiencyScore calculates the efficiency score based on the cumulative size vs. minimum discovered size.
func calculateEfficiencyScore(efficiencyMap map[string]*EfficiencyData) float64 {
	var totalDiscoveredSize int64
	var totalMinSize int64

	for _, data := range efficiencyMap {
		totalDiscoveredSize += data.CumulativeSize
		totalMinSize += data.MinDiscoveredSize
	}

	if totalDiscoveredSize == 0 {
		return 1.0 // Perfect efficiency if no files are discovered
	}

	return float64(totalMinSize) / float64(totalDiscoveredSize)
}

// GenerateEfficiencyReport generates a report summarizing the efficiency of files across layers.
func generateEfficiencyReport(efficiencyMap map[string]*EfficiencyData) *EfficiencyReport {
	var inefficientFiles []*EfficiencyData
	var totalDiscoveredSize int64
	var totalMinSize int64

	for _, data := range efficiencyMap {
		if len(data.Layers) > 1 { // Only files that appear in multiple layers
			inefficientFiles = append(inefficientFiles, data)
		}
		totalDiscoveredSize += data.CumulativeSize
		totalMinSize += data.MinDiscoveredSize
	}

	score := calculateEfficiencyScore(efficiencyMap)

	return &EfficiencyReport{
		Score:               score,
		InefficientFiles:    inefficientFiles,
		TotalDiscoveredSize: totalDiscoveredSize,
		TotalMinSize:        totalMinSize,
	}
}

func GetEfficiencyReportFromImage(img containerd.Image) (*EfficiencyReport, error) {
	// Extract the layer digests from the metadata
	layerDigests, err := getLayerDigestsFromImage(img)
	if err != nil {
		log.Errorf("unable to extract layer digests: %v", err)
		return nil, fmt.Errorf("unable to extract layer digests: %w", err)
	}
	log.Infof("Extracted %d layer digests", len(layerDigests))

	// Get the tarballs for each layer
	walker := NewEfficiencyFSWalker()
	for _, layerDigest := range layerDigests {
		err = walker.WalkLayerTarball(layerDigest)
		if err != nil {
			log.Errorf("unable to walk layer tarball: %v for image: %v", err, img.Name())
			return nil, fmt.Errorf("unable to walk layer tarball: %w", err)
		}
	}
	log.Infof("Successfully retrieved layer tarballs")

	report := generateEfficiencyReport(walker.EfficiencyMap)

	return report, nil
}
