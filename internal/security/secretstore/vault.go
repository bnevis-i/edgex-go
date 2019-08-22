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
 *
 * @author: Tingyu Zeng, Dell / Alain Pulluelo, ForgeRock AS
 * @version: 1.1.0
 *******************************************************************************/
package secretstore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path/filepath"
)

// InitRequest contains a Vault init request regarding the Shamir Secret Sharing (SSS) parameters
type InitRequest struct {
	SecretShares    int `json:"secret_shares"`
	SecretThreshold int `json:"secret_threshold"`
}

// InitResponse contains a Vault init response
type InitResponse struct {
	Keys       []string `json:"keys"`
	KeysBase64 []string `json:"keys_base64"`
	RootToken  string   `json:"root_token"`
}

// UnsealRequest contains a Vault unseal request
type UnsealRequest struct {
	Key   string `json:"key"`
	Reset bool   `json:"reset"`
}

// UnsealResponse contains a Vault unseal response
type UnsealResponse struct {
	Sealed   bool `json:"sealed"`
	T        int  `json:"t"`
	N        int  `json:"n"`
	Progress int  `json:"progress"`
}

type VaultClient struct {
	client Requestor
	scheme string
	host   string
}

func NewVaultClient(r Requestor, s string, h string) VaultClient {
	return VaultClient{
		client: r,
		scheme: s,
		host:   h,
	}
}

func (vc *VaultClient) HealthCheck() (statusCode int, err error) {
	url := &url.URL{
		Scheme: vc.scheme,
		Host:   vc.host,
		Path:   VaultHealthAPI,
	}
	jsonBlock := []byte(`{}`)
	req, err := http.NewRequest(http.MethodGet, url.String(), bytes.NewBuffer(jsonBlock))
	req.Header.Set("Content-Type", JsonContentType)
	resp, err := vc.client.Do(req)
	if err != nil {
		LoggingClient.Error(fmt.Sprintf("failed on checking status of secret store: %s", err.Error()))
		return 0, err
	}
	defer resp.Body.Close()
	LoggingClient.Info(fmt.Sprintf("vault health check HTTP status: %s (StatusCode: %d)", resp.Status, resp.StatusCode))
	return resp.StatusCode, nil
}

func (vc *VaultClient) Init() (statusCode int, err error) {
	initRequest := InitRequest{
		SecretShares:    Configuration.SecretService.VaultSecretShares,
		SecretThreshold: Configuration.SecretService.VaultSecretThreshold,
	}

	LoggingClient.Info(fmt.Sprintf("vault init strategy (SSS parameters): shares=%d threshold=%d", initRequest.SecretShares, initRequest.SecretThreshold))
	url := &url.URL{
		Scheme: vc.scheme,
		Host:   vc.host,
		Path:   VaultInitAPI,
	}
	jsonBlock, err := json.Marshal(&initRequest)
	if err != nil {
		LoggingClient.Error(fmt.Sprintf("failed to build the Vault init request (SSS parameters): %s", err.Error()))
		return 0, err
	}
	req, err := http.NewRequest(http.MethodPost, url.String(), bytes.NewBuffer(jsonBlock))
	req.Header.Set("Content-Type", JsonContentType)
	resp, err := vc.client.Do(req)
	if err != nil {
		LoggingClient.Error(fmt.Sprintf("failed to send Vault init request: %s", err.Error()))
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		LoggingClient.Error(fmt.Sprintf("vault init request failed with status: %s", resp.Status))
		return resp.StatusCode, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		LoggingClient.Error(fmt.Sprintf("failed to fetch the Vault init request response body: %s", err.Error()))
		return 0, err
	}

	initResp := InitResponse{}
	if err = json.Unmarshal(body, &initResp); err != nil {
		LoggingClient.Error(fmt.Sprintf("failed to build the JSON structure from the init request response body: %s", err.Error()))
		return 0, err
	}

	err = ioutil.WriteFile(filepath.Join(Configuration.SecretService.TokenFolderPath, Configuration.SecretService.TokenFile), body, 0600)
	if err != nil {
		LoggingClient.Error(fmt.Sprintf("failed to create Vault init response %s file, HTTP status: %s", Configuration.SecretService.TokenFolderPath+"/"+Configuration.SecretService.TokenFile, err.Error()))
		return 0, err
	}

	LoggingClient.Info("Vault initialization complete.")
	return resp.StatusCode, nil
}

func (vc *VaultClient) Unseal() (statusCode int, err error) {
	LoggingClient.Info(fmt.Sprintf("Vault unsealing Process. Applying key shares."))
	initResp := InitResponse{}
	rawBytes, err := ioutil.ReadFile(filepath.Join(Configuration.SecretService.TokenFolderPath, Configuration.SecretService.TokenFile))
	if err != nil {
		LoggingClient.Error(fmt.Sprintf("failed to read the Vault JSON response init file: %s", err.Error()))
		return 0, err
	}

	if err = json.Unmarshal(rawBytes, &initResp); err != nil {
		LoggingClient.Error(fmt.Sprintf("failed to build the JSON structure from the init response body: %s", err.Error()))
		return 0, err
	}

	url := &url.URL{
		Scheme: vc.scheme,
		Host:   vc.host,
		Path:   VaultUnsealAPI,
	}

	keyCounter := 1
	for _, key := range initResp.KeysBase64 {
		unsealRequest := UnsealRequest{
			Key: key,
		}
		jsonBlock, err := json.Marshal(&unsealRequest)
		if err != nil {
			LoggingClient.Error(fmt.Sprintf("failed to build the Vault unseal request (key shares parameter): %s", err.Error()))
			return 0, err
		}
		req, err := http.NewRequest(http.MethodPost, url.String(), bytes.NewBuffer(jsonBlock))
		req.Header.Set("Content-Type", JsonContentType)
		resp, err := vc.client.Do(req)
		if err != nil {
			LoggingClient.Error(fmt.Sprintf("failed to send the Vault init request: %s", err.Error()))
			return 0, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			LoggingClient.Error(fmt.Sprintf("vault unseal request failed with status code: %s", resp.Status))
			return resp.StatusCode, err
		}

		unsealedBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			LoggingClient.Error(fmt.Sprintf("failed to fetch the Vault unseal request response body: %s", err.Error()))
			return 0, err
		}
		unsealResponse := UnsealResponse{}
		if err = json.Unmarshal(unsealedBody, &unsealResponse); err != nil {
			LoggingClient.Error(fmt.Sprintf("failed to build the JSON structure from the unseal request response body: %s", err.Error()))
			return 0, err
		}

		LoggingClient.Info(fmt.Sprintf("Vault key share %d/%d successfully applied.", keyCounter, Configuration.SecretService.VaultSecretShares))
		if !unsealResponse.Sealed {
			LoggingClient.Info("Vault key share threshold reached. Unsealing complete.")
			return resp.StatusCode, nil
		}
		keyCounter++
	}
	return 0, fmt.Errorf("%d", 1)
}
