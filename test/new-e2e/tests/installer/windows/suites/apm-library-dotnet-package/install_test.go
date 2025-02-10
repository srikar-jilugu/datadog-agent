// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package dotnettests

import (
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/e2e"
	winawshost "github.com/DataDog/datadog-agent/test/new-e2e/pkg/provisioners/aws/host/windows"
	installer "github.com/DataDog/datadog-agent/test/new-e2e/tests/installer/unix"
	installerwindows "github.com/DataDog/datadog-agent/test/new-e2e/tests/installer/windows"

	"testing"
)

type testDotnetLibraryInstallSuite struct {
	installerwindows.BaseSuite
}

// TestDotnetInstalls tests the usage of the Datadog installer to install the apm-library-dotnet-package package.
func TestDonetLibraryInstalls(t *testing.T) {
	e2e.Run(t, &testDotnetLibraryInstallSuite{},
		e2e.WithProvisioner(
			winawshost.ProvisionerNoAgentNoFakeIntake(
				winawshost.WithInstaller(),
			)))
}

// TestInstallAgentPackage tests installing and uninstalling the Datadog Agent using the Datadog installer.
func (s *testDotnetLibraryInstallSuite) TestInstallDotnetLibraryPackage() {
	s.Run("Install", func() {
		s.installDotnetLibrary()
		s.Run("Uninstall", s.removeDotnetLibrary)
	})
}

func (s *testDotnetLibraryInstallSuite) installDotnetLibrary() {
	// Arrange

	// Act
	output, err := s.Installer().InstallPackage("apm-library-dotnet-package",
		installer.WithVersion("40171f0416f4827adf9cb8399ecfad2b38bc2e8d"))

	// Assert
	s.Require().NoErrorf(err, "failed to install the apm-library-dotnet-package package: %s", output)
}

func (s *testDotnetLibraryInstallSuite) removeDotnetLibrary() {
	// Arrange

	// Act
	output, err := s.Installer().RemovePackage("apm-library-dotnet-package")

	// Assert
	s.Require().NoErrorf(err, "failed to remove the Datadog Agent package: %s", output)
	s.Require().Host(s.Env().RemoteHost).
		NoDirExists(installerwindows.GetStableDirFor("apm-library-dotnet-package"),
			"the package directory should be removed")
}
