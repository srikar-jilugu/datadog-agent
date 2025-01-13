// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build containerd

package efficiency

import (
	"errors"
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/util/log"
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

		log.Debugf("Processing file: %s", relPath)

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
			log.Debugf("Tracking file: %s with size: %d bytes", file.Path, file.Size)
			TrackFileEfficiency(file, w.EfficiencyMap, relPath)
		}

		return nil
	})
}
