// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package collector

import (
	"sync"

	checkid "github.com/DataDog/datadog-agent/pkg/collector/check/id"
)

type Error struct {
	err       string
	retryable bool
}

func (e Error) String() string {
	return e.err
}

type _loaderErrors = map[string]map[string]Error // check Name -> loader -> error
type LoaderErrors = map[string]map[string]string

// collectorErrors holds the error objects
type collectorErrors struct {
	loader _loaderErrors
	run    map[checkid.ID]string // check ID -> error
	m      sync.RWMutex
}

// newCollectorErrors returns an instance holding autoconfig errors stats
func newCollectorErrors() *collectorErrors {
	return &collectorErrors{
		loader: make(_loaderErrors),
		run:    make(map[checkid.ID]string),
	}
}

// setLoaderError will safely set the error for that check and loader to the LoaderErrorStats
func (ce *collectorErrors) setLoaderError(checkName string, loaderName string, err string, retryable bool) {
	_, found := ce.loader[checkName]
	if !found {
		ce.loader[checkName] = make(map[string]Error)
	}

	ce.loader[checkName][loaderName] = Error{err, retryable}
}

// removeLoaderErrors removes the errors for a check (usually when successfully loaded)
func (ce *collectorErrors) removeLoaderErrors(checkName string) {
	delete(ce.loader, checkName)
}

// GetLoaderErrors will safely get the errors regarding loaders
func (ce *collectorErrors) getLoaderErrors() LoaderErrors {
	ce.m.RLock()
	defer ce.m.RUnlock()

	errorsCopy := make(LoaderErrors)

	for check, loaderErrors := range ce.loader {
		errorsCopy[check] = make(map[string]string)
		for loader, loaderError := range loaderErrors {
			errorsCopy[check][loader] = loaderError.err
		}
	}

	return errorsCopy
}

// GetLoaderErrors will safely get the retryable errors regarding loaders
func (ce *collectorErrors) getRetryableLoaderErrors() LoaderErrors {
	ce.m.RLock()
	defer ce.m.RUnlock()

	errorsCopy := make(LoaderErrors)

	for check, loaderErrors := range ce.loader {
		errorsCopy[check] = make(map[string]string)
		for loader, loaderError := range loaderErrors {
			if loaderError.retryable {
				errorsCopy[check][loader] = loaderError.err
			}
		}
	}

	return errorsCopy
}

func (ce *collectorErrors) setRunError(checkID checkid.ID, err string) {
	ce.m.Lock()
	defer ce.m.Unlock()

	ce.run[checkID] = err
}

func (ce *collectorErrors) getRunErrors() map[checkid.ID]string {
	ce.m.RLock()
	defer ce.m.RUnlock()

	runCopy := make(map[checkid.ID]string)
	for k, v := range ce.run {
		runCopy[k] = v
	}

	return runCopy
}
