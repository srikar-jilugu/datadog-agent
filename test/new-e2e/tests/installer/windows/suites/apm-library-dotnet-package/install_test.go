// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package dotnettests

import (
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/e2e"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/environments"
	winawshost "github.com/DataDog/datadog-agent/test/new-e2e/pkg/provisioners/aws/host/windows"
	installer "github.com/DataDog/datadog-agent/test/new-e2e/tests/installer/unix"
	installerwindows "github.com/DataDog/datadog-agent/test/new-e2e/tests/installer/windows"
	"github.com/DataDog/datadog-agent/test/new-e2e/tests/installer/windows/consts"
	suiteasserts "github.com/DataDog/datadog-agent/test/new-e2e/tests/installer/windows/suite-assertions"
	"github.com/DataDog/datadog-agent/test/new-e2e/tests/windows"
	"github.com/stretchr/testify/require"

	"testing"
)

type testDotnetLibraryInstallSuite struct {
	e2e.BaseSuite[environments.WindowsHost]
	Installer *installerwindows.DatadogInstaller
}

// BeforeTest creates a new Datadog Installer and sets the output logs directory for each tests
func (s *testDotnetLibraryInstallSuite) BeforeTest(suiteName, testName string) {
	s.Installer = installerwindows.NewDatadogInstaller(s.Env(), s.SessionOutputDir())
}

// Require instantiates a suiteAssertions for the current suite.
// This allows writing assertions in a "natural" way, i.e.:
//
//	suite.Require().HasAService(...).WithUserSid(...)
//
// Ideally this suite assertion would exist at a higher level of abstraction
// so that it could be shared by multiple suites, but for now it exists only
// on the Windows Datadog installer `BaseSuite` object.
func (s *testDotnetLibraryInstallSuite) Require() *suiteasserts.SuiteAssertions {
	return suiteasserts.New(s.BaseSuite.Require(), s)
}

// TestDotnetInstalls tests the usage of the Datadog installer to install the apm-library-dotnet-package package.
func TestDonetLibraryInstalls(t *testing.T) {
	t.Parallel()
	e2e.Run(t, &testDotnetLibraryInstallSuite{},
		e2e.WithProvisioner(
			winawshost.ProvisionerNoAgentNoFakeIntake(
				winawshost.WithInstaller(),
			)))
}

func (s *testDotnetLibraryInstallSuite) installIIS() {
	// Install IIS
	t := s.T()
	s.BaseSuite.SetupSuite()
	vm := s.Env().RemoteHost
	err := windows.InstallIIS(vm)
	require.NoError(t, err)
}

// TestInstallUninstallDotnetLibraryPackage tests installing and uninstalling the Datadog APM Library for .NET using the Datadog installer.
func (s *testDotnetLibraryInstallSuite) TestInstallUninstallDotnetLibraryPackage() {
	defer s.Installer.Purge()
	s.installIIS()

	// TODO remove override once image is published
	output, err := s.Installer.InstallPackage("datadog-apm-library-dotnet",
		installer.WithVersion("f74c4009ecda0ca4a1b17ff4f30d1d7ea202afe5"),
		installer.WithRegistry("installtesting.datad0g.com"),
	)
	s.Require().NoErrorf(err, "failed to install the dotnet library package: %s", output)

	output, err = s.Installer.RemovePackage("datadog-apm-library-dotnet")

	s.Require().NoErrorf(err, "failed to remove the dotnet library package: %s", output)
	s.Require().Host(s.Env().RemoteHost).
		NoDirExists(consts.GetStableDirFor("datadog-apm-library-dotnet"),
			"the package directory should be removed")
}

// TestInstallDotnetLibraryPackageWithoutIIS tests installing the Datadog APM Library for .NET using the Datadog installer without IIS installed.
func (s *testDotnetLibraryInstallSuite) TestInstallDotnetLibraryPackageWithoutIIS() {
	defer s.Installer.Purge()
	// TODO remove override once image is published
	_, err := s.Installer.InstallPackage("datadog-apm-library-dotnet",
		installer.WithVersion("f74c4009ecda0ca4a1b17ff4f30d1d7ea202afe5"),
		installer.WithRegistry("installtesting.datad0g.com"),
	)
	s.Require().Error(err, "Installing the dotnet library package without IIS should fail")
	// TODO check that the package gets deleted
	s.Require().Host(s.Env().RemoteHost).
		NoDirExists(consts.GetStableDirFor("datadog-apm-library-dotnet"),
			"the package directory should be removed")
}

// TestInstallUninstallDotnetLibraryPackage tests installing and uninstalling the Datadog APM Library for .NET using the Datadog installer.
func (s *testDotnetLibraryInstallSuite) TestReinstall() {
	defer s.Installer.Purge()
	s.installIIS()

	// TODO remove override once image is published
	output, err := s.Installer.InstallPackage("datadog-apm-library-dotnet",
		installer.WithVersion("f74c4009ecda0ca4a1b17ff4f30d1d7ea202afe5"),
		installer.WithRegistry("installtesting.datad0g.com"),
	)
	s.Require().NoErrorf(err, "failed to install the dotnet library package: %s", output)

	output, err = s.Installer.InstallPackage("datadog-apm-library-dotnet",
		installer.WithVersion("f74c4009ecda0ca4a1b17ff4f30d1d7ea202afe5"),
		installer.WithRegistry("installtesting.datad0g.com"),
	)
	s.Require().NoErrorf(err, "failed to install the dotnet library package: %s", output)
}
