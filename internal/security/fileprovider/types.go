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
)

type SecretServiceInfo struct {
	// URL scheme
	Scheme string
	// Host name for the Vault server (default: localhost if SNAP_NAME defined, else edgex-vault)
	Server string
	// Port number of the Vault server (default: 8200)
	Port int
	// Path to CA cert
	CaFilePath string
}

type TokenFileProviderInfo struct {
	// Path to Vault authorization token to be used by the service (default: /run/edgex/secrets/token-file-provider/secrets-token.json)
	PrivilegedTokenPath string
	// Configuration file used to control token creation (default: res/token-config.json)
	ConfigFile string
	// Base directory for token file output (default: /run/edgex/secrets)
	OutputDir string
	// File name for token file (default: secrets-token.json)
	OutputFilename string
}

func setStringDefault(s *string, dflt string) {
	if *s == "" {
		*s = dflt
	}
}

func setIntDefault(i *int, dflt int) {
	if *i == 0 {
		*i = dflt
	}
}

func DetectSnapEnvironment() bool {
	return os.Getenv(SnapNameEnvVar) != ""
}

func (info SecretServiceInfo) WithDefaults(isSnap func() bool) SecretServiceInfo {
	if isSnap() {
		setStringDefault(&info.Server, DefaultVaultServerSnap)
	} else {
		setStringDefault(&info.Server, DefaultVaultServer)
	}
	setIntDefault(&info.Port, DefaultVaultPort)
	return info
}

func (info TokenFileProviderInfo) WithDefaults() TokenFileProviderInfo {
	setStringDefault(&info.PrivilegedTokenPath, DefaultPrivilegedTokenPath)
	setStringDefault(&info.ConfigFile, DefaultConfigFile)
	setStringDefault(&info.OutputDir, DefaultOutputDir)
	setStringDefault(&info.OutputFilename, DefaultOutputFilename)
	return info
}
