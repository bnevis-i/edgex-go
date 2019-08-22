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
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestDefaultKdf tests the default implementation
func TestDefaultKdf(t *testing.T) {
	// Arrange
	keyDeriver := NewDefaultKdf(".", sha256.New)
	(keyDeriver.(*defaultKdf)).setFileOpener(mockFileOpener) // internal method
	expected, _ := hex.DecodeString("1060e4e72054653bf46623844033f5ccc9cff596a4a680e074ef4fd06aae60df")

	// Act
	key, err := keyDeriver.DeriveKey(make([]byte, 32), 32, "info")

	// Assert
	assert.Nil(t, err)
	assert.Equal(t, expected, key)
}

//
// Mock opening and reading of the seed file
//

func mockFileOpener(name string, flag int, perm os.FileMode) (file, error) {
	return &mockSeedFile{}, nil
}

type mockSeedFile struct{}

func (*mockSeedFile) Close() error {
	return nil
}

func (*mockSeedFile) Read(b []byte) (n int, err error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}

func (*mockSeedFile) WriteAt(p []byte, off int64) (n int, err error) {
	return 32, nil
}
