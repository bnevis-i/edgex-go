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
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

const thirtyTwoZeroes string = "0000000000000000000000000000000000000000000000000000000000000000"

func TestNoOption(t *testing.T) {
	tearDown := setupTest(t)
	origArgs := os.Args
	defer tearDown(t, origArgs)
	assert := assert.New(t)

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	runWithNoOption()

	os.Stdout = oldStdout
	w.Close()
	var capture bytes.Buffer
	io.Copy(&capture, r)
	assert.Equal(thirtyTwoZeroes, capture.String())
	assert.Equal(0, (exitInstance.(*testExitCode)).getStatusCode())
}

func setupTest(t *testing.T) func(t *testing.T, args []string) {
	exitInstance = newTestExit()
	return func(t *testing.T, args []string) {
		// reset after each test
		os.Args = args
	}
}

func runWithNoOption() {
	// case 1: no option given
	os.Args = []string{"cmd"}
	main()
}

type testExitCode struct {
	testStatusCode int
}

func newTestExit() exit {
	return &testExitCode{}
}

func (testExit *testExitCode) callExit(statusCode int) {
	fmt.Printf("In test: exitCode = %d\n", statusCode)
	testExit.testStatusCode = statusCode
}

func (testExit *testExitCode) getStatusCode() int {
	return testExit.testStatusCode
}
