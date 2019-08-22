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
package pipedhexreader

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// pipedHexReader stores instance data for the pipedhexreader
type pipedHexReader struct{}

// NewPipedHexReader creates a new PipedHexReader
func NewPipedHexReader() PipedHexReader {
	return &pipedHexReader{}
}

// ReadHexBytesFromExe see interface.go
func (phr *pipedHexReader) ReadHexBytesFromExe(executable string, args []string) ([]byte, error) {
	sanitizedExecutable, err := exec.LookPath(executable)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(sanitizedExecutable, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(stdout)
	// We don't WANT a newline, but code defensively
	hexbytes, _ := reader.ReadString('\n')
	// Readstring returns non-nil error if delim is not present: ignore this
	// StdoutPipe usage is to Wait at the end of the reading logic
	// because it closes the readers automatically
	if err := cmd.Wait(); err != nil {
		return nil, err
	}
	// Remove newline if present, the decode hex bytes
	hexbytes = strings.TrimSuffix(hexbytes, "\n")
	bytes, err := hex.DecodeString(hexbytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return nil, err
	}
	return bytes, nil
}
