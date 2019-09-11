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
	"io"
	"os"
	"testing"

	"github.com/edgexfoundry/edgex-go/internal/security/fileprovider"
	. "github.com/edgexfoundry/edgex-go/internal/security/fileprovider/mocks"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

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

// WcaptureWrapper wraps a lambda function to preserve os.Args and capture (and return) stdin and stdout
func captureWrapper(t *testing.T, delegate func(t *testing.T) error) (bytes.Buffer, bytes.Buffer, error) {
	var oldArgs []string
	var oldStdout, oldStderr *os.File
	var oldFileProvider fileprovider.TokenProvider
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
		fileProvider = oldFileProvider
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

	mockTokenProvider := &MockTokenProvider{}
	mockTokenProvider.On("Run").Return(nil)
	mockTokenProvider.On("SetConfiguration", mock.Anything, mock.Anything).Once()

	_, stderrCapture, err := captureWrapper(t, func(t *testing.T) error {
		os.Args = []string{"cmd"}
		fileProvider = mockTokenProvider // fileProvider is global in main.go
		main()
		return nil
	})

	assert.Nil(err)
	mockTokenProvider.AssertExpectations(t)
	assert.Equal(0, (exitInstance.(*testExitCode)).getStatusCode())
	assert.Equal("", stderrCapture.String())
}
