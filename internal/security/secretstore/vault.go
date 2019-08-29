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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/edgexfoundry/edgex-go/internal/security/pipedhexreader"
)

// InitRequest contains a Vault init request regarding the Shamir Secret Sharing (SSS) parameters
type InitRequest struct {
	SecretShares    int `json:"secret_shares"`
	SecretThreshold int `json:"secret_threshold"`
}

// InitResponse contains a Vault init response
type InitResponse struct {
	Keys          []string `json:"keys"`
	KeysBase64    []string `json:"keys_base64"`
	EncryptedKeys []string `json:"encrypted_keys"`
	Nonces        []string `json:"nonces"`
	Ivs           []string `json:"ivs"`
	RootToken     string   `json:"root_token"`
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
	pipedhexreader pipedhexreader.PipedHexReader
	client         Requestor
	scheme         string
	host           string
}

func NewVaultClient(phr pipedhexreader.PipedHexReader, r Requestor, s string, h string) VaultClient {
	return VaultClient{
		pipedhexreader: phr,
		client:         r,
		scheme:         s,
		host:           h,
	}
}

func (vc *VaultClient) setPipedHexHeader(pipedhexreader pipedhexreader.PipedHexReader) {
	vc.pipedhexreader = pipedhexreader
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

	err = vc.encryptVaultMasterKeyCTR(&initResp)
	if err != nil {
		LoggingClient.Error(fmt.Sprintf("failed encrypt vault master key %s", err.Error()))
		return 0, err
	}

	remarshaledBody, err := json.Marshal(initResp)
	if err != nil {
		LoggingClient.Error(fmt.Sprintf("failed remarshal Vault init response %s", err.Error()))
		return 0, err
	}

	err = ioutil.WriteFile(filepath.Join(Configuration.SecretService.TokenFolderPath, Configuration.SecretService.TokenFile), remarshaledBody, 0600)
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

	var encryptedConfig = (initResp.KeysBase64 == nil)

	if encryptedConfig {
		err = vc.decryptVaultMasterKeyCTR(&initResp)
		if err != nil {
			LoggingClient.Error(fmt.Sprintf("failed decrypt vault master key %s", err.Error()))
			return 0, err
		}
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

// UpgradeVaultMasterKeyEncryption checks to see if the existing vault master key
// is encrypted, and if found unencrypted, will encrypt and save it.
func (vc *VaultClient) UpgradeVaultMasterKeyEncryption() (err error) {
	LoggingClient.Info(fmt.Sprintf("Checking for unencrypted vault master key (will upgrade)"))

	initResp := InitResponse{}
	vmkPath := filepath.Join(Configuration.SecretService.TokenFolderPath, Configuration.SecretService.TokenFile)
	rawBytes, err := ioutil.ReadFile(vmkPath)
	if err != nil {
		LoggingClient.Info(fmt.Sprintf("Vault master key not found; nothing to do: %s", vmkPath))
		return nil //no error
	}

	if err = json.Unmarshal(rawBytes, &initResp); err != nil {
		LoggingClient.Error(fmt.Sprintf("failed to build the JSON structure from the init response body: %s", err.Error()))
		return err
	}

	var encryptedConfig = (initResp.KeysBase64 == nil)

	if encryptedConfig {
		LoggingClient.Info(fmt.Sprintf("Vault master key already encrypted; nothing to do: %s", vmkPath))
		return nil //no error
	}

	err = vc.encryptVaultMasterKeyCTR(&initResp)
	if err != nil {
		LoggingClient.Error(fmt.Sprintf("failed encrypt vault master key %s", err.Error()))
		return err
	}

	remarshaledBody, err := json.Marshal(initResp)
	if err != nil {
		LoggingClient.Error(fmt.Sprintf("failed remarshal JSON body %s", err.Error()))
		return err
	}

	err = ioutil.WriteFile(vmkPath, remarshaledBody, 0600)
	if err != nil {
		LoggingClient.Error(fmt.Sprintf("failed to save %s file, Error is: %s", vmkPath, err.Error()))
		return err
	}

	LoggingClient.Info("Vault master key encryption upgrade complete.")
	return nil
}

func wipeKey(key []byte) {
	blank := make([]byte, len(key))
	copy(key, blank)
}

// Use a derived key to encrypt Keys and save as EncryptedKeysBase64
func (vc *VaultClient) encryptVaultMasterKeyCTR(initResp *InitResponse) error {

	key, err := vc.obtainAESKey()
	if err != nil {
		LoggingClient.Error(fmt.Sprintf("failed to obtain encryption key %s", err.Error()))
		return err
	}
	defer wipeKey(key)

	newKeys := make([]string, len(initResp.Keys))
	newIvs := make([]string, len(initResp.Keys))

	for i, hexPlaintext := range initResp.Keys {

		block, err := aes.NewCipher(key)
		if err != nil {
			LoggingClient.Error(fmt.Sprintf("failed to initialize block cipher %s", err.Error()))
			return err
		}

		iv := make([]byte, block.BlockSize())
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			LoggingClient.Error(fmt.Sprintf("failed to initialize random IV %s", err.Error()))
			return err
		}

		plaintext, err := hex.DecodeString(hexPlaintext)
		if err != nil {
			LoggingClient.Error(fmt.Sprintf("failed to decode hex bytes of keyshare (details omitted)"))
			return err
		}

		ciphertext := make([]byte, len(plaintext))
		stream := cipher.NewCTR(block, iv) // will panic if error
		stream.XORKeyStream(ciphertext, plaintext)

		newKeys[i] = hex.EncodeToString(ciphertext)
		newIvs[i] = hex.EncodeToString(iv)
	}

	initResp.EncryptedKeys = newKeys
	initResp.Ivs = newIvs
	initResp.Keys = nil       // strings are immutable, must wait for GC
	initResp.KeysBase64 = nil // strings are immutable, must wait for GC
	return nil
}

// Use a derived key to decrypt EncryptedKeysBase64 and resore Keys and
// EncryptedKeysBase64 to be fed back to the Vault unseal API
func (vc *VaultClient) decryptVaultMasterKeyCTR(initResp *InitResponse) error {

	key, err := vc.obtainAESKey()
	if err != nil {
		LoggingClient.Error(fmt.Sprintf("failed to obtain decryption key %s", err.Error()))
		return err
	}
	defer wipeKey(key)

	newKeys := make([]string, len(initResp.EncryptedKeys))
	newKeysBase64 := make([]string, len(initResp.EncryptedKeys))

	for i, hexCiphertext := range initResp.EncryptedKeys {

		block, err := aes.NewCipher(key)
		if err != nil {
			LoggingClient.Error(fmt.Sprintf("failed to initialize block cipher %s", err.Error()))
			return err
		}

		hexIv := initResp.Ivs[i]
		iv, err := hex.DecodeString(hexIv)
		if err != nil {
			LoggingClient.Error(fmt.Sprintf("failed to decode hex bytes of IV %s", err.Error()))
			return err
		}

		ciphertext, err := hex.DecodeString(hexCiphertext)
		if err != nil {
			LoggingClient.Error(fmt.Sprintf("failed to decode hex bytes of ciphertext"))
			return err
		}

		plaintext := make([]byte, len(ciphertext))
		stream := cipher.NewCTR(block, iv) // will panic if error
		stream.XORKeyStream(plaintext, ciphertext)

		newKeys[i] = hex.EncodeToString(plaintext)
		newKeysBase64[i] = base64.StdEncoding.EncodeToString(plaintext)
	}

	initResp.Keys = newKeys
	initResp.KeysBase64 = newKeysBase64
	initResp.EncryptedKeys = nil
	initResp.Ivs = nil
	return nil
}

// Use a derived key to encrypt Keys and save as EncryptedKeysBase64
func (vc *VaultClient) encryptVaultMasterKeyGCM(initResp *InitResponse) error {

	key, err := vc.obtainAESKey()
	if err != nil {
		LoggingClient.Error(fmt.Sprintf("failed to obtain encryption key %s", err.Error()))
		return err
	}
	defer wipeKey(key)

	newKeys := make([]string, len(initResp.Keys))
	newNonces := make([]string, len(initResp.Keys))

	for i, hexPlaintext := range initResp.Keys {

		block, err := aes.NewCipher(key)
		if err != nil {
			LoggingClient.Error(fmt.Sprintf("failed to initialize block cipher %s", err.Error()))
			return err
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			LoggingClient.Error(fmt.Sprintf("failed to initialize AES cipher %s", err.Error()))
			return err
		}

		nonce := make([]byte, aesgcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			LoggingClient.Error(fmt.Sprintf("failed to initialize random nonce %s", err.Error()))
			return err
		}

		plaintext, err := hex.DecodeString(hexPlaintext)
		if err != nil {
			LoggingClient.Error(fmt.Sprintf("failed to decode hex bytes of keyshare (details omitted)"))
			return err
		}

		ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

		newKeys[i] = hex.EncodeToString(ciphertext)
		newNonces[i] = hex.EncodeToString(nonce)
	}

	initResp.EncryptedKeys = newKeys
	initResp.Nonces = newNonces
	initResp.Keys = nil       // strings are immutable, must wait for GC
	initResp.KeysBase64 = nil // strings are immutable, must wait for GC
	return nil
}

// Use a derived key to decrypt EncryptedKeysBase64 and resore Keys and
// EncryptedKeysBase64 to be fed back to the Vault unseal API
func (vc *VaultClient) decryptVaultMasterKeyGCM(initResp *InitResponse) error {

	key, err := vc.obtainAESKey()
	if err != nil {
		LoggingClient.Error(fmt.Sprintf("failed to obtain decryption key %s", err.Error()))
		return err
	}
	defer wipeKey(key)

	newKeys := make([]string, len(initResp.EncryptedKeys))
	newKeysBase64 := make([]string, len(initResp.EncryptedKeys))

	for i, hexCiphertext := range initResp.EncryptedKeys {

		block, err := aes.NewCipher(key)
		if err != nil {
			LoggingClient.Error(fmt.Sprintf("failed to initialize block cipher %s", err.Error()))
			return err
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			LoggingClient.Error(fmt.Sprintf("failed to initialize AES cipher %s", err.Error()))
			return err
		}

		hexNonce := initResp.Nonces[i]
		nonce, err := hex.DecodeString(hexNonce)
		if err != nil {
			LoggingClient.Error(fmt.Sprintf("failed to decode hex bytes of nonce %s", err.Error()))
			return err
		}

		ciphertext, err := hex.DecodeString(hexCiphertext)
		if err != nil {
			LoggingClient.Error(fmt.Sprintf("failed to decode hex bytes of ciphertext"))
			return err
		}

		plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)

		newKeys[i] = hex.EncodeToString(plaintext)
		newKeysBase64[i] = base64.StdEncoding.EncodeToString(plaintext)
	}

	initResp.Keys = newKeys
	initResp.KeysBase64 = newKeysBase64
	initResp.EncryptedKeys = nil
	initResp.Nonces = nil
	return nil
}

// obtainAESKey obtain AES encryption key from KDF or returns error
func (vc *VaultClient) obtainAESKey() ([]byte, error) {
	kdfBin := vc.getKdfBin()
	persistDir := Configuration.SecretService.TokenFolderPath
	key, err := vc.pipedhexreader.ReadHexBytesFromExe(kdfBin, []string{PersistDirKdfOption, persistDir})
	return key, err
}

// getKdfBin returns which KDF to run
func (vc *VaultClient) getKdfBin() string {
	kdfBin := os.Getenv("KDF_HOOK")
	if kdfBin == "" {
		kdfBin = defaultKdfExecutable
	}
	return kdfBin
}
