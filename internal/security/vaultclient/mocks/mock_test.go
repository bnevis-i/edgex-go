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

package mocks

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/edgexfoundry/edgex-go/internal/security/authtokenreader"
	. "github.com/edgexfoundry/edgex-go/internal/security/vaultclient"
	"github.com/stretchr/testify/assert"
)

func TestMockInterfaceType(t *testing.T) {
	// Typecast will fail if doesn't implement interface properly
	var iface VaultClient = &MockVaultClient{}
	assert.NotNil(t, iface)
}

func TestMockHealthCheck(t *testing.T) {
	mockClient := &MockVaultClient{}
	mockClient.On("HealthCheck").Return(http.StatusOK, nil)

	rc, err := mockClient.HealthCheck()
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, rc)
	mockClient.AssertExpectations(t)
}

func TestMockInit(t *testing.T) {
	config := SecretServiceInfo{}
	scratchBuffer := new(bytes.Buffer)
	mockClient := &MockVaultClient{}
	mockClient.On("Init", config, scratchBuffer).Return(http.StatusOK, nil)

	rc, err := mockClient.Init(config, scratchBuffer)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, rc)
	mockClient.AssertExpectations(t)
}

func TestMockUnseal(t *testing.T) {
	config := SecretServiceInfo{}
	scratchBuffer := new(bytes.Buffer)
	mockClient := &MockVaultClient{}
	mockClient.On("Unseal", config, scratchBuffer).Return(http.StatusOK, nil)

	rc, err := mockClient.Unseal(config, scratchBuffer)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, rc)
	mockClient.AssertExpectations(t)
}

func TestMockInstallPolicy(t *testing.T) {
	mockClient := &MockVaultClient{}
	mockClient.On("InstallPolicy", (authtokenreader.AuthTokenReader)(nil), "foo", "bar").Return(http.StatusOK, nil)

	rc, err := mockClient.InstallPolicy((authtokenreader.AuthTokenReader)(nil), "foo", "bar")
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, rc)
	mockClient.AssertExpectations(t)
}

func TestMockCreateToken(t *testing.T) {
	params := make(map[string]interface{})
	response := make(map[string]interface{})
	mockClient := &MockVaultClient{}
	mockClient.On("CreateToken", (authtokenreader.AuthTokenReader)(nil), params, response).Return(http.StatusOK, nil)

	rc, err := mockClient.CreateToken((authtokenreader.AuthTokenReader)(nil), params, response)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, rc)
	mockClient.AssertExpectations(t)
}
