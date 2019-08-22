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
package kdf

import (
	"crypto/rand"
	"hash"
	"io"
	"os"
	"path"

	"golang.org/x/crypto/hkdf"
)

const saltLength = 32
const saltFile string = "kdf-salt.dat"

// file implements a unit testing hook for file IO
type file interface {
	io.Reader
	io.Closer
	io.WriterAt
}

// defaultKdf stores instance data for the default KDF
type defaultKdf struct {
	fileOpener      func(name string, flag int, perm os.FileMode) (file, error)
	persistencePath string
	hashConstructor func() hash.Hash
}

// NewDefaultKdf creates a new KeyDeriver
func NewDefaultKdf(persistencePath string, hashConstructor func() hash.Hash) KeyDeriver {
	return &defaultKdf{defaultFileOpener, persistencePath, hashConstructor}
}

// defaultFileOpener just opens the file using normal IO
func defaultFileOpener(name string, flag int, perm os.FileMode) (file, error) {
	return os.OpenFile(name, flag, perm)
}

// setFileOpener is a test/DI hook to avoid real IO during unit testing
func (kdf *defaultKdf) setFileOpener(fileOpener func(name string, flag int, perm os.FileMode) (file, error)) {
	kdf.fileOpener = fileOpener
}

// DeriveKey returns derived key material of specified length
func (kdf *defaultKdf) DeriveKey(ikm []byte, keyLen uint, info string) ([]byte, error) {
	salt, err := kdf.initializeSalt()
	if err != nil {
		return nil, err
	}
	infoBytes := []byte(info)
	kdfreader := hkdf.New(kdf.hashConstructor, ikm, salt, infoBytes)
	key := make([]byte, keyLen)
	kdfreader.Read(key)
	return key, nil
}

// initializeSalt recovers the KDF salt value from a file
// or installs a new salt
func (kdf *defaultKdf) initializeSalt() ([]byte, error) {
	salt := make([]byte, saltLength)
	saltPath := path.Join(kdf.persistencePath, saltFile)
	saltFile, err := kdf.fileOpener(saltPath, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	defer saltFile.Close()
	nbytes, err := saltFile.Read(salt)
	if nbytes == 0 || nbytes != saltLength {
		_, err := rand.Read(salt)
		if err != nil {
			return nil, err
		}
		nwritten, err := saltFile.WriteAt(salt, 0)
		if err != nil || nwritten != len(salt) {
			return nil, err
		}
	}
	return salt, nil
}
