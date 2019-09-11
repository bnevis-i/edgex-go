//
// Copyright (c) 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations under
// the License.
//
// SPDX-License-Identifier: Apache-2.0'
//
package fileprovider

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetectSnapEnvironment(t *testing.T) {
	// Arrange
	inSnap := os.Getenv(SnapNameEnvVar) != ""

	// Act
	snap := DetectSnapEnvironment()

	// Assert
	assert.Equal(t, inSnap, snap)
}

func TestDefaultVaultServerNoSnap(t *testing.T) {
	// Arrange
	i := SecretServiceInfo{}
	noSnap := func() bool { return false }

	// Act
	i2 := i.WithDefaults(noSnap)

	// Assert
	assert.Equal(t, DefaultVaultServer, i2.Server)
}

func TestDefaultVaultServerSnap(t *testing.T) {
	// Arrange
	i := SecretServiceInfo{}
	snap := func() bool { return true }

	// Act
	i2 := i.WithDefaults(snap)

	// Assert
	assert.Equal(t, DefaultVaultServerSnap, i2.Server)
}

func TestDefaultVaultPort(t *testing.T) {
	// Arrange
	i := SecretServiceInfo{}
	snap := func() bool { return true }

	// Act
	i2 := i.WithDefaults(snap)

	// Assert
	assert.Equal(t, DefaultVaultPort, i2.Port)
}

func TestDefaultPrivilegedTokenPath(t *testing.T) {
	// Arrange
	i := TokenFileProviderInfo{}

	// Act
	i2 := i.WithDefaults()

	// Assert
	assert.Equal(t, DefaultPrivilegedTokenPath, i2.PrivilegedTokenPath)
}

func TestDefaultConfigFile(t *testing.T) {
	// Arrange
	i := TokenFileProviderInfo{}

	// Act
	i2 := i.WithDefaults()

	// Assert
	assert.Equal(t, DefaultConfigFile, i2.ConfigFile)
}

func TestDefaultOutputDir(t *testing.T) {
	// Arrange
	i := TokenFileProviderInfo{}

	// Act
	i2 := i.WithDefaults()

	// Assert
	assert.Equal(t, DefaultOutputDir, i2.OutputDir)
}

func TestDefaultOutputFilename(t *testing.T) {
	// Arrange
	i := TokenFileProviderInfo{}

	// Act
	i2 := i.WithDefaults()

	// Assert
	assert.Equal(t, DefaultOutputFilename, i2.OutputFilename)
}
