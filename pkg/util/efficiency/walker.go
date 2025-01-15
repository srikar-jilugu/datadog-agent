// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build containerd

package efficiency

import (
	"archive/tar"
	"errors"
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// EfficiencyFSWalker is a custom walker for tracking file sizes and redundancies for efficiency calculation
type EfficiencyFSWalker struct {
	EfficiencyMap map[string]*EfficiencyData
}

// NewEfficiencyFSWalker returns a new instance of the EfficiencyFSWalker
func NewEfficiencyFSWalker() *EfficiencyFSWalker {
	return &EfficiencyFSWalker{
		EfficiencyMap: make(map[string]*EfficiencyData), // Initialize the map
	}
}

// Walk walks the filesystem rooted at root, calling fn for each file.
func (w *EfficiencyFSWalker) Walk(root string) error {
	// Walk the directory tree
	log.Infof("Starting file system walk at: %s", root)
	return filepath.WalkDir(root, func(filePath string, d fs.DirEntry, err error) error {
		// Error handling
		if err != nil {
			if os.IsPermission(err) || errors.Is(err, fs.ErrNotExist) {
				log.Warnf("Permission error or file does not exist: %s, skipping", filePath)
				return nil
			}
			log.Errorf("Error walking file path %s: %v", filePath, err)
			return err
		}

		// Build relative file path
		relPath, err := filepath.Rel(root, filePath)
		if err != nil {
			log.Errorf("Error getting relative path (%s): %v", filePath, err)
			return fmt.Errorf("error getting relative path (%s): %w", filePath, err)
		}
		relPath = filepath.ToSlash(relPath) // Normalize the path

		// Process every file and directory (no skipping)
		if !d.IsDir() { // Only process files (skip directories)
			info, err := d.Info()
			if err != nil {
				log.Errorf("Error getting file info for %s: %v", filePath, err)
				return fmt.Errorf("error getting file info: %w", err)
			}

			// Track file efficiency (file path, size)
			file := &File{
				Path: relPath,
				Size: info.Size(),
			}
			TrackFileEfficiency(file, w.EfficiencyMap, relPath)
		}

		return nil
	})
}

func WalkTarball(tarballPath string) error {
	// Open the tarball
	tarball, err := os.Open(tarballPath)
	if err != nil {
		return fmt.Errorf("failed to open tarball %s: %w", tarballPath, err)
	}
	defer tarball.Close()

	// Create a new tar reader
	tarReader := tar.NewReader(tarball)

	var currentLayer string

	// Walk through the files in the tarball
	for {
		// Get the next file in the tarball
		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of tarball
		}
		if err != nil {
			return fmt.Errorf("failed to read tarball file: %w", err)
		}

		layerDir := filepath.Dir(header.Name)
		if currentLayer != layerDir {
			// We've moved to a new layer
			currentLayer = layerDir
			log.Infof("Entering layer: %s", currentLayer)
		}

		// Log file details for inspection
		log.Infof("Processing file: %s in layer: %s", header.Name, currentLayer)

		// Process the file for efficiency calculation
		// For example, track file size
		// This part could use your existing `EfficiencyFSWalker`
		// fsWalker := NewEfficiencyFSWalker()
		// fsWalker.TrackFileEfficiency(header.Name, header.Size)
	}

	return nil
}
