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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const expectedInfo = "info"
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

// WcaptureWrapper wraps a lambda function to preseve os.Args and capture (and return stdin and stdout)
func captureWrapper(t *testing.T, delegate func(t *testing.T) error) (bytes.Buffer, bytes.Buffer, error) {
	var oldArgs []string
	var oldStdout, oldStderr *os.File
	var stdoutReader, stdoutWriter *os.File
	var stderrReader, stderrWriter *os.File
	var stdoutCapture, stderrCapture bytes.Buffer

	var preFunc = func(t *testing.T) {
		exitInstance = newTestExit()
		oldArgs, oldStdout, oldStderr = os.Args, os.Stdout, os.Stderr
		stdoutReader, stdoutWriter, _ = os.Pipe()
		stderrReader, stderrWriter, _ = os.Pipe()
		os.Stdout, os.Stderr = stdoutWriter, stderrWriter
		stdoutCapture.Reset()
		stderrCapture.Reset()
	}
	var postFunc = func(t *testing.T) {
		stdoutWriter.Close()
		stderrWriter.Close()
		io.Copy(&stdoutCapture, stdoutReader)
		io.Copy(&stderrCapture, stderrReader)
		os.Args, os.Stdout, os.Stderr = oldArgs, oldStdout, oldStderr
	}

	lambda := func(t *testing.T) error {
		preFunc(t)
		defer postFunc(t)
		err := delegate(t)
		return err
	}

	err := lambda(t)
	return stdoutCapture, stderrCapture, err
}

func TestNoOption(t *testing.T) {
	assert := assert.New(t)

	_, stderrCapture, err := captureWrapper(t, func(t *testing.T) error {
		os.Args = []string{"cmd"}
		main()
		return nil
	})

	assert.Nil(err)
	assert.Equal(1, (exitInstance.(*testExitCode)).getStatusCode())
	assert.Equal("ERROR: -persistdir is a required option\n", stderrCapture.String())
}

func TestBadHalg(t *testing.T) {
	assert := assert.New(t)

	_, stderrCapture, err := captureWrapper(t, func(t *testing.T) error {
		os.Args = []string{"cmd", "-persistdir", ".", "-hashalg", "sha1"}
		main()
		return nil
	})

	assert.Nil(err)
	assert.Equal(1, (exitInstance.(*testExitCode)).getStatusCode())
	assert.Equal("ERROR: -hashalg must be \"sha256\"\n", stderrCapture.String())
}

func TestNoInfo(t *testing.T) {
	assert := assert.New(t)

	_, stderrCapture, err := captureWrapper(t, func(t *testing.T) error {
		os.Args = []string{"cmd", "-persistdir", ".", "-hashalg", "sha256"}
		main()
		return nil
	})

	assert.Nil(err)
	assert.Equal(1, (exitInstance.(*testExitCode)).getStatusCode())
	assert.Equal("ERROR: An \"info\" argument is required as input to the KDF\n", stderrCapture.String())
}

// TestNoError runs a mocked IKM and mocked KDF and
// just makes sure submain() calls the right stuff
func TestNoError(t *testing.T) {
	assert := assert.New(t)

	mockedHexReader := &mockPipedHexReader{}
	mockedKeyDeriver := &mockKeyDeriver{}
	mockedHexReader.On("ReadHexBytesFromExe", "", []string{}).Return(make([]byte, 32), nil)
	mockedKeyDeriver.On("DeriveKey", make([]byte, 32), uint(expectedKeyLen), expectedInfo).Return(hex.DecodeString(expectedOutputKey))

	stdoutCapture, _, err := captureWrapper(t, func(t *testing.T) error {
		err := kdfExecutorArgs{mockedHexReader, mockedKeyDeriver, "", expectedKeyLen, expectedInfo}.outputDerivedKey(os.Stdout)
		return err
	})

	assert.Nil(err)
	mockedHexReader.AssertExpectations(t)
	mockedKeyDeriver.AssertExpectations(t)
	assert.Equal(expectedOutputKey, stdoutCapture.String())
}

//
// testing mocks - eliminate dependency on IKM_HOOK
//

type mockPipedHexReader struct {
	mock.Mock
}

// ReadHexBytesFromExe see interface.go
func (phr *mockPipedHexReader) ReadHexBytesFromExe(executable string, args []string) ([]byte, error) {
	// Boilerplate that returns whatever Mock.On().Returns() is configured for
	arguments := phr.Called(executable, args)
	return arguments.Get(0).([]byte), arguments.Error(1)
}

type mockKeyDeriver struct {
	mock.Mock
}

func (kdf *mockKeyDeriver) DeriveKey(ikm []byte, keyLen uint, info string) ([]byte, error) {
	// Boilerplate that returns whatever Mock.On().Returns() is configured for
	arguments := kdf.Called(ikm, keyLen, info)
	return arguments.Get(0).([]byte), arguments.Error(1)
}
