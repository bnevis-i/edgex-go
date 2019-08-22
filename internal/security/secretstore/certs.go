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
 * @author: Tingyu Zeng, Dell
 * @version: 1.1.0
 *******************************************************************************/
package secretstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/dghubble/sling"
)

type Certs struct {
	client    Requestor
	certPath  string
	tokenPath string
}

func NewCerts(r Requestor, certPath string, tokenPath string) Certs {
	return Certs{client: r, certPath: certPath, tokenPath: tokenPath}
}

type CertCollect struct {
	Pair CertPair `json:"data"`
}

type CertPair struct {
	Cert string `json:"cert,omitempty"`
	Key  string `json:"key,omitempty"`
}

type auth struct {
	Token string `json:"root_token"`
}

func (cs *Certs) retrieve(t string) (*CertPair, error) {
	s := sling.New().Set(VaultToken, t)
	req, err := s.New().Base(Configuration.SecretService.GetSecretSvcBaseURL()).Get(cs.certPath).Request()
	if err != nil {
		e := fmt.Sprintf("failed to retrieve the cert pair on path %s with error %s", cs.certPath, err.Error())
		LoggingClient.Error(e)
		return nil, err
	}
	resp, err := cs.client.Do(req)
	if err != nil {
		e := fmt.Sprintf("failed to retrieve the proxy cert on path %s with error %s", cs.certPath, err.Error())
		LoggingClient.Error(e)
		return nil, err
	}
	defer resp.Body.Close()

	cc := CertCollect{}
	switch resp.StatusCode {
	case http.StatusOK:
		if err = json.NewDecoder(resp.Body).Decode(&cc); err != nil {
			return nil, err
		}
		break
	case http.StatusNotFound:
		e := fmt.Sprintf("proxy cert pair NOT found in secret store @/%s, status: %s", cs.certPath, resp.Status)
		LoggingClient.Info(e)
	default:
		e := fmt.Sprintf("failed to retrieve the proxy cert pair on path %s with error code %d", cs.certPath, resp.StatusCode)
		LoggingClient.Error(e)
		return nil, err
	}
	return &cc.Pair, nil
}

func (cs *Certs) AlreadyinStore() (bool, error) {
	cp, err := cs.getCertPair()
	if err != nil {
		return false, err
	}
	if len(cp.Cert) > 0 && len(cp.Key) > 0 {
		return true, nil
	}
	return false, nil
}

func (cs *Certs) getCertPair() (*CertPair, error) {
	t, err := GetAccessToken(cs.tokenPath)
	if err != nil {
		return &CertPair{"", ""}, err
	}
	cp, err := cs.retrieve(t)
	if err != nil {
		return &CertPair{"", ""}, err
	}
	return cp, nil
}

func (cs *Certs) ReadFrom(certPath string, keyPath string) (*CertPair, error) {
	cp := CertPair{}
	certPEMBlock, err := ioutil.ReadFile(certPath)
	if err != nil {
		return &cp, err
	}
	cert := string(certPEMBlock[:])

	keyPEMBlock, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return &cp, err
	}
	key := string(keyPEMBlock[:])
	cp.Cert = cert
	cp.Key = key
	return &cp, nil
}

/* UploadToStore implements the curl command as below:
curl --header "X-Vault-Token: ${_ROOT_TOKEN}" \
            --header "Content-Type: application/json" \
            --request POST \
            --data @${_PAYLOAD_KONG} \
			http://localhost:8200/v1/secret/edgex/pki/tls/edgex-kong
*/
func (cs *Certs) UploadToStore(cp *CertPair) (bool, error) {
	t, err := GetAccessToken(cs.tokenPath)
	if err != nil {
		return false, err
	}

	LoggingClient.Info("trying to upload the proxy cert pair into secret store")
	body := &CertPair{
		Cert: cp.Cert,
		Key:  cp.Key,
	}
	s := sling.New().Set(VaultToken, t)
	req, err := s.New().Base(Configuration.SecretService.GetSecretSvcBaseURL()).Post(cs.certPath).BodyJSON(body).Request()
	if err != nil {
		e := fmt.Sprintf("failed to upload the proxy cert pair on path %s with error %s", cs.certPath, err.Error())
		LoggingClient.Error(e)
		return false, err
	}
	resp, err := cs.client.Do(req)
	if err != nil {
		e := fmt.Sprintf("failed to upload the proxy cert pair on path %s with error %s", cs.certPath, err.Error())
		LoggingClient.Error(e)
		return false, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent:
		LoggingClient.Info("successful on uploading the proxy cert pair into secret store")
		break
	default:
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return false, err
		}
		e := fmt.Sprintf("failed to load the proxy cert pair to the secret store: %s,%s.", resp.Status, string(b))
		LoggingClient.Error(e)
		return false, errors.New(e)
	}
	return true, nil
}

func GetAccessToken(filename string) (string, error) {
	a := auth{}
	raw, err := ioutil.ReadFile(filename)
	if err != nil {
		return a.Token, err
	}
	err = json.Unmarshal(raw, &a)
	return a.Token, err
}
