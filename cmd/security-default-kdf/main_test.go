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
package main

import (
	"bytes"
	"encoding/hex"
	"io"
	"os"
	"testing"

	"github.com/edgexfoundry/edgex-go/internal/security/default-kdf/kdf"
	"github.com/edgexfoundry/edgex-go/internal/security/pipedhexreader"
	"github.com/stretchr/testify/assert"
)

func setupTest(t *testing.T) func(t *testing.T, args []string) {
	exitInstance = newTestExit()
	return func(t *testing.T, args []string) {
		// reset after each test
		os.Args = args
	}
}

type testExitCode struct {
	testStatusCode int
}

func newTestExit() exit {
	return &testExitCode{}
}

func (testExit *testExitCode) callExit(statusCode int) {
	testExit.testStatusCode = statusCode
}

func (testExit *testExitCode) getStatusCode() int {
	return testExit.testStatusCode
}

func TestNoOption(t *testing.T) {
	tearDown := setupTest(t)
	origArgs := os.Args
	defer tearDown(t, origArgs)
	assert := assert.New(t)

	oldStdout := os.Stdout
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	r2, w2, _ := os.Pipe()
	os.Stdout = w
	os.Stderr = w2

	os.Args = []string{"cmd"}
	main()

	os.Stdout = oldStdout
	os.Stderr = oldStderr
	w.Close()
	w2.Close()

	assert.Equal(1, (exitInstance.(*testExitCode)).getStatusCode())

	var stdoutCapture, stderrCapture bytes.Buffer
	io.Copy(&stdoutCapture, r)
	io.Copy(&stderrCapture, r2)
	assert.Equal("ERROR: -pstoredir is a required option\n", stderrCapture.String())
}

func TestBadHalg(t *testing.T) {
	tearDown := setupTest(t)
	origArgs := os.Args
	defer tearDown(t, origArgs)
	assert := assert.New(t)

	oldStdout := os.Stdout
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	r2, w2, _ := os.Pipe()
	os.Stdout = w
	os.Stderr = w2

	os.Args = []string{"cmd", "-pstoredir", ".", "-halg", "sha1"}
	main()

	os.Stdout = oldStdout
	os.Stderr = oldStderr
	w.Close()
	w2.Close()

	assert.Equal(1, (exitInstance.(*testExitCode)).getStatusCode())

	var stdoutCapture, stderrCapture bytes.Buffer
	io.Copy(&stdoutCapture, r)
	io.Copy(&stderrCapture, r2)
	assert.Equal("ERROR: -halg must be \"sha256\"\n", stderrCapture.String())
}

func TestNoInfo(t *testing.T) {
	tearDown := setupTest(t)
	origArgs := os.Args
	defer tearDown(t, origArgs)
	assert := assert.New(t)

	oldStdout := os.Stdout
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	r2, w2, _ := os.Pipe()
	os.Stdout = w
	os.Stderr = w2

	os.Args = []string{"cmd", "-pstoredir", ".", "-halg", "sha256"}
	main()

	os.Stdout = oldStdout
	os.Stderr = oldStderr
	w.Close()
	w2.Close()

	assert.Equal(1, (exitInstance.(*testExitCode)).getStatusCode())

	var stdoutCapture, stderrCapture bytes.Buffer
	io.Copy(&stdoutCapture, r)
	io.Copy(&stderrCapture, r2)
	assert.Equal("ERROR: An \"info\" argument is required as input to the KDF\n", stderrCapture.String())
}

// TestNoError runs a mocked IKM and mocked KDF and
// just makes sure submain() calls the right stuff
func TestNoError(t *testing.T) {
	tearDown := setupTest(t)
	origArgs := os.Args
	defer tearDown(t, origArgs)
	assert := assert.New(t)

	r, w, _ := os.Pipe()

	exitCode, err := submain(newMockPipedHexReader(t), newMockKeyDeriver(t), "", 32, w, "info")

	w.Close()

	assert.Nil(err)
	assert.Equal(0, exitCode)

	var stdoutCapture bytes.Buffer
	io.Copy(&stdoutCapture, r)
	assert.Equal("1060e4e72054653bf46623844033f5ccc9cff596a4a680e074ef4fd06aae60df", stdoutCapture.String())
}

//
// testing mocks - eliminate dependency on IKM_HOOK
//

type mockStringWriter struct {
	t *testing.T
}

func newMockStringWriter(t *testing.T) io.StringWriter {
	return &mockStringWriter{t}
}

func (wc *mockStringWriter) WriteString(s string) (n int, err error) {
	assert.Equal(wc.t, "1060e4e72054653bf46623844033f5ccc9cff596a4a680e074ef4fd06aae60df", s)
	return len(s), nil
}

func (wc *mockStringWriter) Close() error {
	return nil
}

type mockPipedHexReader struct {
	t *testing.T
}

func newMockPipedHexReader(t *testing.T) pipedhexreader.PipedHexReader {
	return &mockPipedHexReader{t}
}

// ReadHexBytesFromExe see interface.go
func (phr *mockPipedHexReader) ReadHexBytesFromExe(executable string, args []string) ([]byte, error) {
	return make([]byte, 32), nil
}

type mockKeyDeriver struct {
	t *testing.T
}

func newMockKeyDeriver(t *testing.T) kdf.KeyDeriver {
	return &mockKeyDeriver{t}
}

func (kdf *mockKeyDeriver) DeriveKey(ikm []byte, keylen uint, info string) ([]byte, error) {
	assert.Equal(kdf.t, uint(32), keylen)
	assert.Equal(kdf.t, make([]byte, 32), ikm)
	assert.Equal(kdf.t, "info", info)
	bytes, _ := hex.DecodeString("1060e4e72054653bf46623844033f5ccc9cff596a4a680e074ef4fd06aae60df")
	return bytes, nil
}
