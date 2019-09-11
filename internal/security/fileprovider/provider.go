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
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/edgexfoundry/edgex-go/internal/security/authtokenreader"
	"github.com/edgexfoundry/edgex-go/internal/security/fileioperformer"
	"github.com/edgexfoundry/edgex-go/internal/security/tokenconfig"
	"github.com/edgexfoundry/edgex-go/internal/security/vaultclient"
	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"
)

// fileTokenProvider stores instance data
type fileTokenProvider struct {
	logger            logger.LoggingClient
	fileOpener        fileioperformer.FileIoPerformer
	tokenProvider     authtokenreader.AuthTokenReader
	tokenConfigParser tokenconfig.TokenConfigParser
	vaultClient       vaultclient.VaultClient
	snapDetectionFunc func() bool
	secretConfig      SecretServiceInfo
	tokenConfig       TokenFileProviderInfo
}

// NewTokenProvider creates a new TokenProvider
func NewTokenProvider(logger logger.LoggingClient,
	fileOpener fileioperformer.FileIoPerformer,
	tokenProvider authtokenreader.AuthTokenReader,
	tokenConfigParser tokenconfig.TokenConfigParser,
	vaultClient vaultclient.VaultClient) TokenProvider {
	return &fileTokenProvider{
		logger:            logger,
		fileOpener:        fileOpener,
		tokenProvider:     tokenProvider,
		tokenConfigParser: tokenConfigParser,
		vaultClient:       vaultClient,
		snapDetectionFunc: DetectSnapEnvironment,
	}
}

// Set configuration
func (p *fileTokenProvider) SetConfiguration(secretConfig SecretServiceInfo, tokenConfig TokenFileProviderInfo) {
	p.secretConfig = secretConfig.WithDefaults(p.snapDetectionFunc)
	p.tokenConfig = tokenConfig.WithDefaults()
}

// Unit testing hook for detecting a snap environment
func (p *fileTokenProvider) setSnapDetector(isSnap func() bool) {
	p.snapDetectionFunc = isSnap
}

// Do whatever is needed
func (p *fileTokenProvider) Run() error {
	p.logger.Info("Generating Vault tokens")

	err := p.tokenProvider.Load(p.tokenConfig.PrivilegedTokenPath)
	if err != nil {
		p.logger.Error(fmt.Sprintf("failed to read privileged access token: %s", err.Error()))
		return err
	}

	err = p.tokenConfigParser.Load(p.tokenConfig.ConfigFile)
	if err != nil {
		p.logger.Error(fmt.Sprintf("failed to read token configuration file %s: %s", p.tokenConfig.ConfigFile, err.Error()))
		return err
	}

	serviceList := p.tokenConfigParser.ServiceKeys()
	for _, serviceName := range serviceList {

		p.logger.Info(fmt.Sprintf("generating policy/token defaults for service %s", serviceName))

		serviceConfig := p.tokenConfigParser.GetServiceConfig(serviceName)
		servicePolicy := make(map[string]interface{})
		createTokenParameters := make(map[string]interface{})

		if serviceConfig.UseDefaults {
			p.logger.Info(fmt.Sprintf("using policy/token defaults for service %s", serviceName))
			servicePolicy = makeDefaultTokenPolicy(serviceName)
			createTokenParameters = makeDefaultTokenParameters(serviceName)
		}

		if serviceConfig.CustomPolicy != nil {
			customPolicy := serviceConfig.CustomPolicy
			if customPolicy["path"] != nil {
				customPaths := customPolicy["path"].(map[string]interface{})
				if servicePolicy["path"] == nil {
					servicePolicy["path"] = make(map[string]interface{})
				}
				for k, v := range customPaths {
					(servicePolicy["path"]).(map[string]interface{})[k] = v
				}
			}
		}

		if serviceConfig.CustomTokenParameters != nil {
			// Custom token parameters override the defaults
			createTokenParameters = mergeMaps(createTokenParameters, serviceConfig.CustomTokenParameters)
		}

		// Set a meta property that consuming serices can use to automatically scope secret queries
		meta := make(map[string]interface{})
		meta["edgex-service-name"] = serviceName
		createTokenParameters["meta"] = meta

		// Always create a policy with this name
		policyName := "edgex-service-" + serviceName

		policyBytes, err := json.Marshal(servicePolicy)
		if err != nil {
			p.logger.Error(fmt.Sprintf("failed encode service policy for %s: %s", serviceName, err.Error()))
			return err
		}

		code, err := p.vaultClient.InstallPolicy(p.tokenProvider, policyName, string(policyBytes))
		if code != http.StatusNoContent {
			p.logger.Error(fmt.Sprintf("failed to install policy %s: %d", policyName, code))
			return err
		}

		var createTokenResponse interface{}
		code, err = p.vaultClient.CreateToken(p.tokenProvider, createTokenParameters, &createTokenResponse)
		if code != http.StatusOK {
			p.logger.Error(fmt.Sprintf("failed to create vault token for service %s: %d", serviceName, code))
			return err
		}

		outputTokenDir := filepath.Join(p.tokenConfig.OutputDir, serviceName)
		outputTokenFilename := filepath.Join(outputTokenDir, p.tokenConfig.OutputFilename)
		err = p.fileOpener.MkdirAll(outputTokenDir, os.FileMode(0700))
		if err != nil {
			p.logger.Error(fmt.Sprintf("failed to create base directory path(s) %s: %s", outputTokenDir, err.Error()))
			return err
		}
		writeCloser, err := p.fileOpener.OpenFileWriter(outputTokenFilename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(0600))
		if err != nil {
			p.logger.Error(fmt.Sprintf("failed open token file for writing %s: %s", outputTokenFilename, err.Error()))
			return err
		}
		defer writeCloser.Close()

		json.NewEncoder(writeCloser).Encode(createTokenResponse) // Write resulting token
	}

	return nil
}
