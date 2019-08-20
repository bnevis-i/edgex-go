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
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/edgexfoundry/edgex-go/internal/security/default-kdf/kdf"
	"github.com/edgexfoundry/edgex-go/internal/security/pipedhexreader"
)

const defaultKeylen uint = 32
const defaultIkmHook string = "security-default-ikm"

var exitInstance = newExit()
var hashConstructor = sha256.New
var helpOpt bool
var persistencePath string
var hashAlg string
var keylen uint
var info string

func init() {
	// define and register command line flags:
	flag.BoolVar(&helpOpt, "h", false, "help message")
	flag.BoolVar(&helpOpt, "help", false, "help message")
	flag.StringVar(&persistencePath, "pstoredir", "", "Path for storing data to be preserved across reboots")
	flag.StringVar(&hashAlg, "halg", "sha256", "Hash algorithm to be used in key derivation function (\"sha256\")")
	flag.UintVar(&keylen, "l", defaultKeylen, "Length of output key in octets")
}

func submain(ikmHandler pipedhexreader.PipedHexReader,
	kdf kdf.KeyDeriver,
	ikmHook string,
	keylen uint,
	stdout io.StringWriter,
	info string) (int, error) {

	ikm, err := ikmHandler.ReadHexBytesFromExe(ikmHook, []string{})
	if err != nil {
		return 1, err
	}
	key, err := kdf.DeriveKey(ikm, keylen, info)
	if err != nil {
		return 1, err
	}
	keyOctets := hex.EncodeToString(key)
	stdout.WriteString(keyOctets)
	return 0, nil
}

func main() {
	flag.Parse()
	info = flag.Arg(0)

	var ikmHook = os.Getenv("IKM_HOOK")
	if ikmHook == "" {
		ikmHook = defaultIkmHook
	}
	if helpOpt {
		flag.Usage()
		exitInstance.callExit(0)
		return
	}
	if persistencePath == "" {
		fmt.Fprintln(os.Stderr, "ERROR: -pstoredir is a required option")
		exitInstance.callExit(1)
		return
	}
	if hashAlg != "sha256" {
		fmt.Fprintln(os.Stderr, "ERROR: -halg must be \"sha256\"")
		exitInstance.callExit(1)
		return
	}
	if info == "" {
		fmt.Fprintln(os.Stderr, "ERROR: An \"info\" argument is required as input to the KDF")
		exitInstance.callExit(1)
		return
	}

	pipedHexReader := pipedhexreader.NewPipedHexReader()
	defaultKdf := kdf.NewDefaultKdf(persistencePath, hashConstructor)
	exitcode, err := submain(pipedHexReader, defaultKdf, ikmHook, keylen, os.Stdout, info)
	os.Stdout.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	exitInstance.callExit(exitcode)
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
