// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build containerd

package efficiency

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/containerd/containerd"
	"io"
	"os"
	"strings"
)

// EfficiencyFSWalker is a custom walker for tracking file sizes and redundancies for efficiency calculation
type EfficiencyTarballWalker struct {
	EfficiencyMap map[string]*EfficiencyData
}

// NewEfficiencyFSWalker returns a new instance of the EfficiencyFSWalker
func NewEfficiencyFSWalker() *EfficiencyTarballWalker {
	return &EfficiencyTarballWalker{
		EfficiencyMap: make(map[string]*EfficiencyData), // Initialize the map
	}
}

func (w *EfficiencyTarballWalker) WalkLayerTarball(layerDigest string) error {
	// Construct the file path to access the tarball directly from the OS
	layerDigest = strings.TrimPrefix(layerDigest, "sha256:")
	filePath := fmt.Sprintf("/host/var/lib/containerd/io.containerd.content.v1.content/blobs/sha256/%s", layerDigest)
	log.Infof("Opening layer tarball at %s", filePath)

	// Open the file containing the layer tarball
	file, err := os.Open(filePath)
	if err != nil {
		log.Errorf("unable to open layer tarball file, skipping: %v", err)
		return nil
		//return fmt.Errorf("unable to open layer tarball file: %w", err)
	}
	defer file.Close()

	// Extract the tarball contents to the temporary directory
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		log.Errorf("failed to create gzip reader: %v", err)
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	tarReader := tar.NewReader(gzipReader)

	log.Infof("Started tarReader, about to enter loop")

	for {
		// Read the next file header from the tarball
		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of tarball
		}
		if err != nil {
			log.Errorf("failed to read tarball file: %v", err)
			return fmt.Errorf("failed to read tarball file: %w", err)
		}

		efficiencyFile := &File{
			Path: header.Name,
			Size: header.Size,
		}
		trackFileEfficiency(efficiencyFile, w.EfficiencyMap, header.Name)
	}
	log.Infof("Finished walking layer tarball for %s", layerDigest)
	return nil
}

// GetLayerTarballs fetches and extracts the tarballs for each layer from the content store
func walkLayerTarballs(layerDigests []string) error {
	// Process each layer's digest
	for idx, layerDigest := range layerDigests {
		layerDigest = strings.TrimPrefix(layerDigest, "sha256:")
		log.Infof("Processing layer %d with digest %s", idx+1, layerDigest)

		// Construct the file path to access the tarball directly from the OS
		filePath := fmt.Sprintf("/host/var/lib/containerd/io.containerd.content.v1.content/blobs/sha256/%s", layerDigest)
		log.Infof("Opening layer tarball at %s", filePath)

		// Open the file containing the layer tarball
		file, err := os.Open(filePath)
		if err != nil {
			log.Errorf("unable to open layer tarball file: %v", err)
			return fmt.Errorf("unable to open layer tarball file: %w", err)
		}
		defer file.Close()

		log.Infof("Successfully opened layer tarball at %s", filePath)

		// Extract the tarball contents to the temporary directory
		gzipReader, err := gzip.NewReader(file)
		if err != nil {
			log.Errorf("failed to create gzip reader: %v", err)
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		tarReader := tar.NewReader(gzipReader)
		log.Infof("Started tarReader, about to enter loop")
		totalSize := int64(0)
		for {
			// Read the next file header from the tarball
			header, err := tarReader.Next()
			if err == io.EOF {
				log.Infof("Attempting to break")
				break // End of tarball
			}
			if err != nil {
				log.Errorf("failed to read tarball file: %v", err)
				return fmt.Errorf("failed to read tarball file: %w", err)
			}

			totalSize += header.Size
		}

		log.Infof("Total size of layer %d: %d", idx+1, totalSize)
	}

	return nil
}

// Parse the image's manifest and extract the layer digests
type LayerInfo struct {
	Digest string `json:"digest"`
}

// Define a struct for the manifest
type Manifest struct {
	SchemaVersion int         `json:"schemaVersion"`
	MediaType     string      `json:"mediaType"`
	Layers        []LayerInfo `json:"layers"`
}

func getLayerDigestsFromImage(img containerd.Image) ([]string, error) {
	// Get the image metadata (manifest or config)
	log.Infof("Getting metadata for image %s", img.Name())

	// Get the metadata for the image (the manifest)
	metadata, err := getImageMetadata(img.Target().Digest.String())
	if err != nil {
		log.Errorf("unable to get image metadata: %v", err)
		return nil, fmt.Errorf("unable to get image metadata: %w", err)
	}
	log.Infof("Successfully retrieved image metadata for image %s", img.Name())

	// Now we can parse the JSON content into a struct
	var manifest Manifest

	// Unmarshal the content into the struct
	if err := json.Unmarshal(metadata, &manifest); err != nil {
		log.Errorf("unable to unmarshal metadata: %v", err)
		return nil, fmt.Errorf("unable to unmarshal metadata: %w", err)
	}

	// Extract the layer digests
	layerDigests := make([]string, 0)
	for idx, layer := range manifest.Layers {
		log.Infof("Extracted layer %d digest: %s", idx+1, layer.Digest)
		layerDigests = append(layerDigests, layer.Digest)
	}

	return layerDigests, nil
}

// Method to retrieve the image metadata (manifest)
func getImageMetadata(imgDigest string) ([]byte, error) {
	// Open the file directly from the agent's filesystem
	imgDigest = strings.TrimPrefix(imgDigest, "sha256:")
	filePath := fmt.Sprintf("/host/var/lib/containerd/io.containerd.content.v1.content/blobs/sha256/%s", imgDigest)
	log.Infof("Opening image metadata file at %s", filePath)

	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		log.Errorf("unable to open image metadata file: %v", err)
		return nil, fmt.Errorf("unable to open image metadata file: %w", err)
	}
	defer file.Close()

	// Read the file content (increase buffer size)
	content, err := io.ReadAll(file)
	if err != nil {
		log.Errorf("failed to read metadata content: %v", err)
		return nil, fmt.Errorf("failed to read metadata content: %w", err)
	}

	// Log raw content for inspection
	log.Infof("Full content length: %d", len(content))

	return content, nil
}
