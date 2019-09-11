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
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	. "github.com/edgexfoundry/edgex-go/internal/security/authtokenreader/mocks"
	. "github.com/edgexfoundry/edgex-go/internal/security/fileioperformer/mocks"
	"github.com/edgexfoundry/edgex-go/internal/security/tokenconfig"
	. "github.com/edgexfoundry/edgex-go/internal/security/tokenconfig/mocks"
	. "github.com/edgexfoundry/edgex-go/internal/security/vaultclient/mocks"
	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

/*
Test cases:

1. Create multiple service tokens with no defaults
2. Create a service with no defaults and custom policy
3. Create a service with no defaults and custom token parameters
4. Create a service with defaults for policy and token parameters
*/

// TestMultipleTokensWithNoDefaults
func TestMultipleTokensWithNoDefaults(t *testing.T) {
	// Arrange
	privilegedTokenPath := "/dummy/privileged/token.json"
	configFile := "token-config.json"
	outputDir := "/outputdir"
	outputFilename := "secrets-token.json"

	mockLogger := logger.MockLogger{}

	mockFileIoPerformer := &MockFileIoPerformer{}
	expectedService1Dir := filepath.Join(outputDir, "service1")
	expectedService1File := filepath.Join(expectedService1Dir, outputFilename)
	service1Buffer := new(bytes.Buffer)
	mockFileIoPerformer.On("MkdirAll", expectedService1Dir, os.FileMode(0700)).Return(nil)
	mockFileIoPerformer.On("OpenFileWriter", expectedService1File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(0600)).Return(&writeCloserBuffer{service1Buffer}, nil)
	expectedService2Dir := filepath.Join(outputDir, "service2")
	expectedService2File := filepath.Join(expectedService2Dir, outputFilename)
	service2Buffer := new(bytes.Buffer)
	mockFileIoPerformer.On("MkdirAll", expectedService2Dir, os.FileMode(0700)).Return(nil)
	mockFileIoPerformer.On("OpenFileWriter", expectedService2File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(0600)).Return(&writeCloserBuffer{service2Buffer}, nil)

	mockAuthTokenReader := &MockAuthTokenReader{}
	mockAuthTokenReader.On("Load", privilegedTokenPath).Return(nil)

	mockTokenConfigParser := &MockTokenConfigParser{}
	mockTokenConfigParser.On("Load", configFile).Return(nil)
	mockTokenConfigParser.On("ServiceKeys").Return([]string{"service1", "service2"})
	mockTokenConfigParser.On("GetServiceConfig", "service1").Return(tokenconfig.ServiceKey{})
	mockTokenConfigParser.On("GetServiceConfig", "service2").Return(tokenconfig.ServiceKey{})

	expectedService1Policy := "{}"
	expectedService2Policy := "{}"
	expectedService1Parameters := makeMetaServiceName("service1")
	expectedService2Parameters := makeMetaServiceName("service2")
	mockVaultClient := &MockVaultClient{}
	mockVaultClient.On("InstallPolicy", mock.Anything, "edgex-service-service1", expectedService1Policy).Return(http.StatusNoContent, nil)
	mockVaultClient.On("InstallPolicy", mock.Anything, "edgex-service-service2", expectedService2Policy).Return(http.StatusNoContent, nil)
	mockVaultClient.On("CreateToken", mock.Anything, expectedService1Parameters, mock.Anything).
		Run(func(args mock.Arguments) {
			setCreateTokenResponse("service1", args.Get(2).(*interface{}))
		}).
		Return(http.StatusOK, nil)
	mockVaultClient.On("CreateToken", mock.Anything, expectedService2Parameters, mock.Anything).
		Run(func(args mock.Arguments) {
			setCreateTokenResponse("service2", args.Get(2).(*interface{}))
		}).
		Return(http.StatusOK, nil)

	p := NewTokenProvider(mockLogger, mockFileIoPerformer, mockAuthTokenReader, mockTokenConfigParser, mockVaultClient)
	p.(*fileTokenProvider).setSnapDetector(func() bool { return false })
	p.SetConfiguration(SecretServiceInfo{}, TokenFileProviderInfo{
		PrivilegedTokenPath: privilegedTokenPath,
		ConfigFile:          configFile,
		OutputDir:           outputDir,
		OutputFilename:      outputFilename,
	})

	// Act
	err := p.Run()

	// Assert
	// - {OutputDir}/service1/{OutputFilename} w/proper contents
	// - {OutputDir}/service2/{OutputFilename} w/proper contents
	// - Correct policy for service1
	// - Correct policy for service2
	// - All other expectations met
	assert.Nil(t, err)
	mockFileIoPerformer.AssertExpectations(t)
	mockAuthTokenReader.AssertExpectations(t)
	mockTokenConfigParser.AssertExpectations(t)
	mockVaultClient.AssertExpectations(t)
	assert.Equal(t, expectedTokenFile("service1"), service1Buffer.Bytes())
	assert.Equal(t, expectedTokenFile("service2"), service2Buffer.Bytes())
}

func setCreateTokenResponse(serviceName string, retval *interface{}) {
	t := make(map[string]interface{})
	t["request_id"] = "f00341c1-fad5-f6e6-13fd-235617f858a1"
	t["auth"] = make(map[string]interface{})
	t["auth"].(map[string]interface{})["client_token"] = "s.wOrq9dO9kzOcuvB06CMviJhZ"
	t["auth"].(map[string]interface{})["accessor"] = "B6oixijqmeR4bsLOJH88Ska9"
	(*retval) = t
}

func makeMetaServiceName(serviceName string) map[string]interface{} {
	createTokenParameters := make(map[string]interface{})
	meta := make(map[string]interface{})
	meta["edgex-service-name"] = serviceName
	createTokenParameters["meta"] = meta
	return createTokenParameters
}

func expectedTokenFile(serviceName string) []byte {
	var tokenResponse interface{}
	setCreateTokenResponse(serviceName, &tokenResponse)
	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(tokenResponse)
	// Debugging note: take care to not write out the buffer or it will disturb the read pointer
	return b.Bytes()
}

// TestNoDefaultsCustomPolicy
func TestNoDefaultsCustomPolicy(t *testing.T) {
	// Arrange
	privilegedTokenPath := "/dummy/privileged/token.json"
	configFile := "token-config.json"
	outputDir := "/outputdir"
	outputFilename := "secrets-token.json"

	mockLogger := logger.MockLogger{}

	mockFileIoPerformer := &MockFileIoPerformer{}
	expectedService1Dir := filepath.Join(outputDir, "myservice")
	expectedService1File := filepath.Join(expectedService1Dir, outputFilename)
	service1Buffer := new(bytes.Buffer)
	mockFileIoPerformer.On("MkdirAll", expectedService1Dir, os.FileMode(0700)).Return(nil)
	mockFileIoPerformer.On("OpenFileWriter", expectedService1File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(0600)).Return(&writeCloserBuffer{service1Buffer}, nil)

	mockAuthTokenReader := &MockAuthTokenReader{}
	mockAuthTokenReader.On("Load", privilegedTokenPath).Return(nil)

	mockTokenConfigParser := &MockTokenConfigParser{}
	mockTokenConfigParser.On("Load", configFile).Return(nil)
	mockTokenConfigParser.On("ServiceKeys").Return([]string{"myservice"})
	mockTokenConfigParser.On("GetServiceConfig", "myservice").Return(tokenconfig.ServiceKey{
		CustomPolicy: makeCustomTokenPolicy(),
	})

	expectedService1Policy := `{"path":{"secret/non/standard/location/*":{"capabilities":["list","read"]}}}`
	expectedService1Parameters := makeMetaServiceName("myservice")
	mockVaultClient := &MockVaultClient{}
	mockVaultClient.On("InstallPolicy", mock.Anything, "edgex-service-myservice", expectedService1Policy).Return(http.StatusNoContent, nil)
	mockVaultClient.On("CreateToken", mock.Anything, expectedService1Parameters, mock.Anything).
		Run(func(args mock.Arguments) {
			setCreateTokenResponse("myservice", args.Get(2).(*interface{}))
		}).
		Return(http.StatusOK, nil)

	p := NewTokenProvider(mockLogger, mockFileIoPerformer, mockAuthTokenReader, mockTokenConfigParser, mockVaultClient)
	p.(*fileTokenProvider).setSnapDetector(func() bool { return false })
	p.SetConfiguration(SecretServiceInfo{}, TokenFileProviderInfo{
		PrivilegedTokenPath: privilegedTokenPath,
		ConfigFile:          configFile,
		OutputDir:           outputDir,
		OutputFilename:      outputFilename,
	})

	// Act
	err := p.Run()

	// Assert
	// - {OutputDir}/myservice/{OutputFilename} w/proper contents
	// - Correct policy for myservice
	// - All other expectations met
	assert.Nil(t, err)
	mockFileIoPerformer.AssertExpectations(t)
	mockAuthTokenReader.AssertExpectations(t)
	mockTokenConfigParser.AssertExpectations(t)
	mockVaultClient.AssertExpectations(t)
	assert.Equal(t, expectedTokenFile("myservice"), service1Buffer.Bytes())
}

func makeCustomTokenPolicy() map[string]interface{} {
	entry := struct {
		Path interface{} `json:"path"`
	}{
		Path: map[string]interface{}{"secret/non/standard/location/*": struct {
			Capabilities []string `json:"capabilities"`
		}{
			Capabilities: []string{"list", "read"},
		}},
	}

	// Marshal the data and then unmarshal it again to turn it into an opaque data structure

	bytes, _ := json.Marshal(entry)

	retval := make(map[string]interface{})
	json.Unmarshal(bytes, &retval)
	return retval
}

// TestNoDefaultsCustomTokenParameters
func TestNoDefaultsCustomTokenParameters(t *testing.T) {
	// Arrange
	privilegedTokenPath := "/dummy/privileged/token.json"
	configFile := "token-config.json"
	outputDir := "/outputdir"
	outputFilename := "secrets-token.json"

	mockLogger := logger.MockLogger{}

	mockFileIoPerformer := &MockFileIoPerformer{}
	expectedService1Dir := filepath.Join(outputDir, "myservice")
	expectedService1File := filepath.Join(expectedService1Dir, outputFilename)
	service1Buffer := new(bytes.Buffer)
	mockFileIoPerformer.On("MkdirAll", expectedService1Dir, os.FileMode(0700)).Return(nil)
	mockFileIoPerformer.On("OpenFileWriter", expectedService1File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(0600)).Return(&writeCloserBuffer{service1Buffer}, nil)

	mockAuthTokenReader := &MockAuthTokenReader{}
	mockAuthTokenReader.On("Load", privilegedTokenPath).Return(nil)

	mockTokenConfigParser := &MockTokenConfigParser{}
	mockTokenConfigParser.On("Load", configFile).Return(nil)
	mockTokenConfigParser.On("ServiceKeys").Return([]string{"myservice"})
	mockTokenConfigParser.On("GetServiceConfig", "myservice").Return(tokenconfig.ServiceKey{
		CustomTokenParameters: makeCustomTokenParameters(),
	})

	expectedService1Policy := "{}"
	expectedService1Parameters := makeCustomTokenParameters()
	expectedService1Parameters["meta"] = makeMetaServiceName("myservice")["meta"]
	mockVaultClient := &MockVaultClient{}
	mockVaultClient.On("InstallPolicy", mock.Anything, "edgex-service-myservice", expectedService1Policy).Return(http.StatusNoContent, nil)
	mockVaultClient.On("CreateToken", mock.Anything, expectedService1Parameters, mock.Anything).
		Run(func(args mock.Arguments) {
			setCreateTokenResponse("myservice", args.Get(2).(*interface{}))
		}).
		Return(http.StatusOK, nil)

	p := NewTokenProvider(mockLogger, mockFileIoPerformer, mockAuthTokenReader, mockTokenConfigParser, mockVaultClient)
	p.(*fileTokenProvider).setSnapDetector(func() bool { return false })
	p.SetConfiguration(SecretServiceInfo{}, TokenFileProviderInfo{
		PrivilegedTokenPath: privilegedTokenPath,
		ConfigFile:          configFile,
		OutputDir:           outputDir,
		OutputFilename:      outputFilename,
	})

	// Act
	err := p.Run()

	// Assert
	// - {OutputDir}/myservice/{OutputFilename} w/proper contents
	// - Correct token parameters for myservice
	// - All other expectations met
	assert.Nil(t, err)
	mockFileIoPerformer.AssertExpectations(t)
	mockAuthTokenReader.AssertExpectations(t)
	mockTokenConfigParser.AssertExpectations(t)
	mockVaultClient.AssertExpectations(t)
	assert.Equal(t, expectedTokenFile("myservice"), service1Buffer.Bytes())
}

func makeCustomTokenParameters() map[string]interface{} {
	retval := make(map[string]interface{})
	retval["key1"] = "value1"
	return retval
}

// TestTokenUsingDefaults
func TestTokenUsingDefaults(t *testing.T) {
	// Arrange
	privilegedTokenPath := "/dummy/privileged/token.json"
	configFile := "token-config.json"
	outputDir := "/outputdir"
	outputFilename := "secrets-token.json"

	mockLogger := logger.MockLogger{}

	mockFileIoPerformer := &MockFileIoPerformer{}
	expectedService1Dir := filepath.Join(outputDir, "myservice")
	expectedService1File := filepath.Join(expectedService1Dir, outputFilename)
	service1Buffer := new(bytes.Buffer)
	mockFileIoPerformer.On("MkdirAll", expectedService1Dir, os.FileMode(0700)).Return(nil)
	mockFileIoPerformer.On("OpenFileWriter", expectedService1File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(0600)).Return(&writeCloserBuffer{service1Buffer}, nil)

	mockAuthTokenReader := &MockAuthTokenReader{}
	mockAuthTokenReader.On("Load", privilegedTokenPath).Return(nil)

	mockTokenConfigParser := &MockTokenConfigParser{}
	mockTokenConfigParser.On("Load", configFile).Return(nil)
	mockTokenConfigParser.On("ServiceKeys").Return([]string{"myservice"})
	mockTokenConfigParser.On("GetServiceConfig", "myservice").Return(tokenconfig.ServiceKey{
		UseDefaults: true,
	})

	expectedService1Policy := `{"path":{"secret/edgex/myservice/*":{"capabilities":["create","update","delete","list","read"]}}}`
	expectedService1Parameters := makeDefaultTokenParameters("myservice")
	expectedService1Parameters["meta"] = makeMetaServiceName("myservice")["meta"]
	mockVaultClient := &MockVaultClient{}
	mockVaultClient.On("InstallPolicy", mock.Anything, "edgex-service-myservice", expectedService1Policy).Return(http.StatusNoContent, nil)
	mockVaultClient.On("CreateToken", mock.Anything, expectedService1Parameters, mock.Anything).
		Run(func(args mock.Arguments) {
			setCreateTokenResponse("myservice", args.Get(2).(*interface{}))
		}).
		Return(http.StatusOK, nil)

	p := NewTokenProvider(mockLogger, mockFileIoPerformer, mockAuthTokenReader, mockTokenConfigParser, mockVaultClient)
	p.(*fileTokenProvider).setSnapDetector(func() bool { return false })
	p.SetConfiguration(SecretServiceInfo{}, TokenFileProviderInfo{
		PrivilegedTokenPath: privilegedTokenPath,
		ConfigFile:          configFile,
		OutputDir:           outputDir,
		OutputFilename:      outputFilename,
	})

	// Act
	err := p.Run()

	// Assert
	// - {OutputDir}/myservice/{OutputFilename} w/proper contents
	// - Correct token parameters for myservice
	// - All other expectations met
	assert.Nil(t, err)
	mockFileIoPerformer.AssertExpectations(t)
	mockAuthTokenReader.AssertExpectations(t)
	mockTokenConfigParser.AssertExpectations(t)
	mockVaultClient.AssertExpectations(t)
	assert.Equal(t, expectedTokenFile("myservice"), service1Buffer.Bytes())
}

//
// mocks
//

type writeCloserBuffer struct {
	*bytes.Buffer
}

func (wcb *writeCloserBuffer) Close() error {
	return nil
}
