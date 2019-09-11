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
package tokenconfig

import (
	"os"
	"strings"
	"testing"

	. "github.com/edgexfoundry/edgex-go/internal/security/fileioperformer/mocks"

	"github.com/stretchr/testify/assert"
)

const sampleJSON = `{
	"service-name": {
	  "edgex_use_defaults": true,
	  "custom_policy": {
		"path": {
		  "secret/non/standard/location/*": {
		    "capabilities": [ "list", "read" ]
		  }
		}
	  },
	  "custom_token_parameters": { "custom_option": "custom_vaule" }
	}
  }`

func TestTokenConfigParser(t *testing.T) {
	stringReader := strings.NewReader(sampleJSON)
	mockFileIoPerformer := &MockFileIoPerformer{}
	mockFileIoPerformer.On("OpenFileReader", "/dev/null", os.O_RDONLY, os.FileMode(0400)).Return(stringReader, nil)

	p := NewTokenConfigParser(mockFileIoPerformer)

	err := p.Load("/dev/null")
	assert.Nil(t, err)

	serviceKeys := p.ServiceKeys()
	assert.Equal(t, []string{"service-name"}, serviceKeys)

	aService := p.GetServiceConfig("service-name")

	assert.Equal(t, true, aService.UseDefaults)
	assert.Contains(t, aService.CustomPolicy, "path")
	var path = aService.CustomPolicy["path"].(map[string]interface{})
	assert.Contains(t, path, "secret/non/standard/location/*")
	// Don't need to go further down the type assertion rabbit hole to prove that this is working
	assert.Contains(t, aService.CustomTokenParameters, "custom_option")
}
