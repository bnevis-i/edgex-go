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
	//"github.com/stretchr/testify/mock"
)

const exectedInfo = "info"
const expectedKeyLen = 32
const expectedOutputKey = "1060e4e72054653bf46623844033f5ccc9cff596a4a680e074ef4fd06aae60df"

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

var oldArgs []string
var oldStdout, oldStderr *os.File
var stdoutReader, stdoutWriter *os.File
var stderrReader, stderrWriter *os.File
var stdoutCapture, stderrCapture bytes.Buffer

func setUp(t *testing.T) {
	exitInstance = newTestExit()
	oldArgs, oldStdout, oldStderr = os.Args, os.Stdout, os.Stderr
	stdoutReader, stdoutWriter, _ = os.Pipe()
	stderrReader, stderrWriter, _ = os.Pipe()
	os.Stdout, os.Stderr = stdoutWriter, stderrWriter
	stdoutCapture.Reset()
	stderrCapture.Reset()
}

func tearDown(t *testing.T) {
	stdoutWriter.Close()
	stderrWriter.Close()
	io.Copy(&stdoutCapture, stdoutReader)
	io.Copy(&stderrCapture, stderrReader)
	os.Args, os.Stdout, os.Stderr = oldArgs, oldStdout, oldStderr
}

func TestNoOption(t *testing.T) {
	assert := assert.New(t)

	setUp(t)

	os.Args = []string{"cmd"}
	main()

	tearDown(t)

	assert.Equal(1, (exitInstance.(*testExitCode)).getStatusCode())
	assert.Equal("ERROR: -persistdir is a required option\n", stderrCapture.String())
}

func TestBadHalg(t *testing.T) {
	assert := assert.New(t)

	setUp(t)

	os.Args = []string{"cmd", "-persistdir", ".", "-hashalg", "sha1"}
	main()

	tearDown(t)

	assert.Equal(1, (exitInstance.(*testExitCode)).getStatusCode())
	assert.Equal("ERROR: -hashalg must be \"sha256\"\n", stderrCapture.String())
}

func TestNoInfo(t *testing.T) {
	assert := assert.New(t)

	setUp(t)

	os.Args = []string{"cmd", "-persistdir", ".", "-hashalg", "sha256"}
	main()

	tearDown(t)

	assert.Equal(1, (exitInstance.(*testExitCode)).getStatusCode())
	assert.Equal("ERROR: An \"info\" argument is required as input to the KDF\n", stderrCapture.String())
}

// TestNoError runs a mocked IKM and mocked KDF and
// just makes sure submain() calls the right stuff
func TestNoError(t *testing.T) {
	assert := assert.New(t)

	setUp(t)

	err := kdfExecutorArgs{newMockPipedHexReader(t), newMockKeyDeriver(t), "", expectedKeyLen, exectedInfo}.outputDerivedKey(os.Stdout)

	tearDown(t)

	assert.Nil(err)
	assert.Equal(expectedOutputKey, stdoutCapture.String())
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

func (kdf *mockKeyDeriver) DeriveKey(ikm []byte, keyLen uint, info string) ([]byte, error) {
	assert.Equal(kdf.t, uint(expectedKeyLen), keyLen)
	assert.Equal(kdf.t, make([]byte, 32), ikm)
	assert.Equal(kdf.t, exectedInfo, info)
	bytes, _ := hex.DecodeString(expectedOutputKey)
	return bytes, nil
}
