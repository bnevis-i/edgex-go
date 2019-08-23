/*******************************************************************************
 * Copyright 2019 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.

 *******************************************************************************/

package secretstore

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"
)

func TestHealthCheck(t *testing.T) {
	LoggingClient = logger.MockLogger{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if r.Method != "GET" {
			t.Errorf("expected GET request, got %s instead", r.Method)
		}

		if r.URL.EscapedPath() != fmt.Sprintf("%s", VaultHealthAPI) {
			t.Errorf("expected request to /%s, got %s instead", VaultHealthAPI, r.URL.EscapedPath())
		}
	}))
	defer ts.Close()

	host := strings.Replace(ts.URL, "https://", "", -1)
	vc := NewVaultClient(newMockPipedHexReader(), NewRequestor(true), "https", host)
	code, _ := vc.HealthCheck()

	if code != http.StatusOK {
		t.Errorf("incorrect vault health check status.")
	}
}

func TestInit(t *testing.T) {
	LoggingClient = logger.MockLogger{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"keys": [
			  "66c45ff15d7cf08275a0cbcb78f22d25256bd429f1805ff7e082715be55d194d"
			],
			"keys_base64": [
			  "NjZjNDVmZjE1ZDdjZjA4Mjc1YTBjYmNiNzhmMjJkMjUyNTZiZDQyOWYxODA1ZmY3ZTA4MjcxNWJlNTVkMTk0ZA=="
			],
			"root_token": "s.83AOgsQcSyqhp5OlfMYNj1bh"
		}
		`))
		if r.Method != "POST" {
			t.Errorf("expected POST request, got %s instead", r.Method)
		}

		if r.URL.EscapedPath() != fmt.Sprintf("%s", VaultInitAPI) {
			t.Errorf("expected request to /%s, got %s instead", VaultInitAPI, r.URL.EscapedPath())
		}
	}))
	defer ts.Close()

	Configuration = &ConfigurationStruct{}
	Configuration.SecretService = SecretServiceInfo{
		TokenFolderPath: "testdata",
		TokenFile:       "test-resp-init.json",
	}

	host := strings.Replace(ts.URL, "https://", "", -1)
	vc := NewVaultClient(newMockPipedHexReader(), NewRequestor(true), "https", host)
	code, _ := vc.Init()
	if code != http.StatusOK {
		t.Errorf("incorrect vault init status. The returned code is %d", code)
	}
}

func TestUnseal(t *testing.T) {
	LoggingClient = logger.MockLogger{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"sealed": false, "t": 1, "n": 1, "progress": 100}`))
		if r.Method != "POST" {
			t.Errorf("expected POST request, got %s instead", r.Method)
		}

		if r.URL.EscapedPath() != fmt.Sprintf("%s", VaultUnsealAPI) {
			t.Errorf("expected request to /%s, got %s instead", VaultUnsealAPI, r.URL.EscapedPath())
		}
	}))
	defer ts.Close()

	Configuration = &ConfigurationStruct{}
	Configuration.SecretService = SecretServiceInfo{
		TokenFolderPath:   "testdata",
		TokenFile:         "test-resp-init.json",
		VaultSecretShares: 1,
	}

	host := strings.Replace(ts.URL, "https://", "", -1)
	vc := NewVaultClient(newMockPipedHexReader(), NewRequestor(true), "https", host)
	code, err := vc.Unseal()
	if code != http.StatusOK {
		t.Errorf("incorrect vault unseal status. The returned code is %d, %s", code, err.Error())
	}
}

//
// Test mocks
//

type mockPipedHexReader struct{}

func newMockPipedHexReader() *mockPipedHexReader {
	return &mockPipedHexReader{}
}

func (*mockPipedHexReader) ReadHexBytesFromExe(executable string, args []string) ([]byte, error) {
	return make([]byte, 32), nil
}
