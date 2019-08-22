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

// Constants

const defaultkeyLen uint = 32
const defaultShaAlgorithm string = "sha256"
const defaultIkmHook string = "security-default-ikm"

// Dependencies

var exitInstance = newExit()
var hashConstructor = sha256.New

// Flag variables

var helpOpt bool
var persistencePath string
var hashAlg string
var keyLen uint
var info string

// define and register command line flags
func init() {
	flag.BoolVar(&helpOpt, "h", false, "help message")
	flag.BoolVar(&helpOpt, "help", false, "help message")
	flag.StringVar(&persistencePath, "persistdir", "", "Path for storing data to be preserved across reboots")
	flag.StringVar(&hashAlg, "hashalg", "sha256", "Hash algorithm to be used in key derivation function (\"sha256\")")
	flag.UintVar(&keyLen, "length", defaultkeyLen, "Length of output key in octets")
}

type kdfExecutorArgs struct {
	ikmHandler pipedhexreader.PipedHexReader
	kdf        kdf.KeyDeriver
	ikmHook    string
	keyLen     uint
	info       string
}

func (arg kdfExecutorArgs) outputDerivedKey(writer io.StringWriter) error {

	ikm, err := arg.ikmHandler.ReadHexBytesFromExe(arg.ikmHook, []string{})
	if err != nil {
		return err
	}
	key, err := arg.kdf.DeriveKey(ikm, arg.keyLen, arg.info)
	if err != nil {
		return err
	}
	keyOctets := hex.EncodeToString(key)
	writer.WriteString(keyOctets)
	return nil
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
		fmt.Fprintln(os.Stderr, "ERROR: -persistdir is a required option")
		exitInstance.callExit(1)
		return
	}
	if hashAlg != defaultShaAlgorithm {
		fmt.Fprintln(os.Stderr, "ERROR: -hashalg must be \"sha256\"")
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

	err := kdfExecutorArgs{pipedHexReader, defaultKdf, ikmHook, keyLen, info}.outputDerivedKey(os.Stdout)

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		exitInstance.callExit(1)
		return
	}

	exitInstance.callExit(0)
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
