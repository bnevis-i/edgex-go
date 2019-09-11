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
	"flag"
	"fmt"
	"os"

	"github.com/edgexfoundry/edgex-go/internal"
	"github.com/edgexfoundry/edgex-go/internal/pkg/startup"
	"github.com/edgexfoundry/edgex-go/internal/security/authtokenreader"
	"github.com/edgexfoundry/edgex-go/internal/security/fileioperformer"
	"github.com/edgexfoundry/edgex-go/internal/security/fileprovider"
	"github.com/edgexfoundry/edgex-go/internal/security/tokenconfig"
	"github.com/edgexfoundry/edgex-go/internal/security/vaultclient"
	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"
	"github.com/edgexfoundry/go-mod-core-contracts/models"
)

// Constants

// Dependencies

var exitInstance = newExit()
var fileProvider fileprovider.TokenProvider

// Flag variables

var helpOpt bool
var useProfile string
var useRegistry bool

// define and register command line flags
func init() {
	flag.BoolVar(&helpOpt, "h", false, "help message")
	flag.BoolVar(&helpOpt, "help", false, "help message")
	flag.BoolVar(&useRegistry, "registry", false, "Indicates the service should use registry service.")
	flag.BoolVar(&useRegistry, "r", false, "Indicates the service should use registry service.")
	flag.StringVar(&useProfile, "profile", "", "Specify a profile other than default.")
	flag.StringVar(&useProfile, "p", "", "Specify a profile other than default.")
}

func main() {
	flag.Parse()

	params := startup.BootParams{UseRegistry: useRegistry, UseProfile: useProfile, BootTimeout: internal.BootTimeoutDefault}
	startup.Bootstrap(params, fileprovider.Retry, logBeforeInit)

	if helpOpt {
		flag.Usage()
		exitInstance.callExit(0)
		return
	}

	cfg := fileprovider.Configuration     // Global variable initialized in fileprovider.Retry
	logging := fileprovider.LoggingClient // Global variable initialized in fileprovider.Retry

	fileOpener := fileioperformer.NewDefaultFileIoPerformer()
	tokenProvider := authtokenreader.NewAuthTokenReader(fileOpener)
	tokenConfigParser := tokenconfig.NewTokenConfigParser(fileOpener)

	var req vaultclient.Requestor
	if caFilePath := cfg.SecretService.CaFilePath; caFilePath != "" {
		logging.Info("using certificate verification for secret store connection")
		caReader, err := fileOpener.OpenFileReader(caFilePath, os.O_RDONLY, 0400)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			exitInstance.callExit(1)
			return
		}
		req = vaultclient.NewRequestor(logging).WithCaCert(caReader)
	} else {
		logging.Info("bypassing certificate verification for secret store connection")
		req = vaultclient.NewRequestor(logging).Insecure()
	}
	vaultScheme := cfg.SecretService.Scheme
	vaultHost := fmt.Sprintf("%s:%v", cfg.SecretService.Server, cfg.SecretService.Port)
	vaultClient := vaultclient.NewVaultClient(logging, req, vaultScheme, vaultHost)

	if fileProvider == nil {
		// main_test.go has injected a testing mock if fileProvider != nil
		fileProvider = fileprovider.NewTokenProvider(logging, fileOpener, tokenProvider, tokenConfigParser, vaultClient)
	}

	fileProvider.SetConfiguration(cfg.SecretService, cfg.TokenFileProvider)
	err := fileProvider.Run()

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		exitInstance.callExit(1)
		return
	}

	exitInstance.callExit(0)
}

func logBeforeInit(err error) {
	l := logger.NewClient("security-proxy-setup", false, "", models.InfoLog)
	l.Error(err.Error())
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
