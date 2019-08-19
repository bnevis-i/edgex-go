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
	"encoding/hex"
	"os"

	"github.com/edgexfoundry/edgex-go/internal/security/default-ikm/ikm"
)

var exitInstance = newExit()
var defaultIkm = ikm.NewDefaultIkm()

func main() {

	ikm := defaultIkm.Ikm()
	ikmOctets := hex.EncodeToString(ikm)
	os.Stdout.WriteString(ikmOctets)
	os.Stdout.Close()

	exitInstance.callExit(0)
}

type ikmProducer interface {
	Ikm() []byte
}

type exit interface {
	callExit(int)
}

type exitCode struct{}

func newExit() exit {
	return &exitCode{}
}

func (*exitCode) callExit(statusCode int) {
	os.Exit(statusCode)
}
