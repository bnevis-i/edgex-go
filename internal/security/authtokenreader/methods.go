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

package authtokenreader

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/edgexfoundry/edgex-go/internal/security/fileioperformer"
)

type tokenProvider struct {
	fileOpener fileioperformer.FileIoPerformer
	authToken  string
}

// NewAuthTokenReader creates a new TokenParser
func NewAuthTokenReader(opener fileioperformer.FileIoPerformer) AuthTokenReader {
	return &tokenProvider{fileOpener: opener}
}

func (p *tokenProvider) Load(path string) error {
	reader, err := p.fileOpener.OpenFileReader(path, os.O_RDONLY, 0400)
	if err != nil {
		return err
	}
	readCloser := fileioperformer.MakeReadCloser(reader)
	fileContents, err := ioutil.ReadAll(readCloser)
	if err != nil {
		return err
	}
	defer readCloser.Close()

	var parsedContents vaultTokenFile
	err = json.Unmarshal(fileContents, &parsedContents)
	if err != nil {
		return err
	}

	// Look for token first in "auth"/"client_token"
	// and then in "root_token"
	// and fail if no token is found at all
	p.authToken = parsedContents.Auth.ClientToken
	if p.authToken == "" {
		p.authToken = parsedContents.RootToken
	}
	if p.authToken == "" {
		return fmt.Errorf("Unable to find authentication token in %s", path)
	}
	return nil
}

func (p *tokenProvider) AuthToken() string {
	return p.authToken
}
