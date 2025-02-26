// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package packages contains the install/upgrades/uninstall logic for packages
package packages

import (
	"context"

	"github.com/DataDog/datadog-agent/pkg/fleet/installer/telemetry"
)

// postInstallHook is a function that is called after a package is installed.
type postInstallHook func(ctx InstallationContext) error

// preRemoveHook is a function that is called before a package is removed or upgraded.
type preRemoveHook func(ctx InstallationContext) error

// preRemoveHookAsync is a function that is called before a package is removed from the disk
// It can block the removal of the package files until a condition is met without blocking
// the rest of the uninstall or upgrade process.
// Today this is only useful for the dotnet tracer on windows and generally *should be avoided*.
type preRemoveHookAsync func(ctx context.Context) error

// Package represents a package that can be installed, upgraded, or removed.
type Package struct {
	preRemoveHook   preRemoveHook
	postInstallHook postInstallHook

	preRemoveHookAsync preRemoveHookAsync
}

// PreRemove calls the pre-remove hook for the package.
func (p *Package) PreRemove(ctx InstallationContext) error {
	if p.preRemoveHook != nil {
		return p.preRemoveHook(ctx)
	}
	return nil
}

// PostInstall calls the post-install hook for the package.
func (p *Package) PostInstall(ctx InstallationContext) error {
	if p.postInstallHook != nil {
		return p.postInstallHook(ctx)
	}
	return nil
}

// PreRemoveAsync calls the pre-remove hook for the package.
func (p *Package) PreRemoveAsync(ctx context.Context) error {
	if p.preRemoveHookAsync != nil {
		return p.preRemoveHookAsync(ctx)
	}
	return nil
}

// InstallationContext is the context passed to hooks during install/upgrade/uninstall.
type InstallationContext struct {
	context.Context
	Args []string
}

// StartSpan starts a new span with the given operation name.
func (c InstallationContext) StartSpan(operationName string) (*telemetry.Span, InstallationContext) {
	span, newCtx := telemetry.StartSpanFromContext(c, operationName)
	c.Context = newCtx
	return span, c
}
