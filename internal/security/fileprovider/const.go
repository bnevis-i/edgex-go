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

const (
	SnapNameEnvVar             = "SNAP_NAME"
	DefaultVaultServer         = "edgex-vault"
	DefaultVaultServerSnap     = "localhost"
	DefaultVaultPort           = 8200
	DefaultPrivilegedTokenPath = "/run/edgex/secrets/token-file-provider/secrets-token.json"
	DefaultConfigFile          = "res/token-config.json"
	DefaultOutputDir           = "/run/edgex/secrets"
	DefaultOutputFilename      = "secrets-token.json"
	VaultTokenHeader           = "X-Vault-Token"
)
