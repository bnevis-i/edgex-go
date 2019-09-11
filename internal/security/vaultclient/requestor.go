/*******************************************************************************
 * Copyright 2019 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 * @author: Tingyu Zeng, Dell
 * @version: 1.1.0
 *******************************************************************************/
package vaultclient

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/edgexfoundry/edgex-go/internal/security/fileioperformer"
	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"
)

type Requestor interface {
	Do(req *http.Request) (*http.Response, error)
}

type FluentRequestor interface {
	Insecure() Requestor
	WithCaCert(io.Reader) Requestor
}

type fluentRequestor struct {
	logger logger.LoggingClient
}

func NewRequestor(logger logger.LoggingClient) FluentRequestor {
	return &fluentRequestor{logger}
}

func (r *fluentRequestor) Insecure() Requestor {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: tr}
}

func (r *fluentRequestor) WithCaCert(caReader io.Reader) Requestor {
	readCloser := fileioperformer.MakeReadCloser(caReader)
	caCert, err := ioutil.ReadAll(readCloser)
	defer readCloser.Close()
	if err != nil {
		r.logger.Error("failed to load rootCA certificate.")
		return nil
	}
	r.logger.Info("successful loading the rootCA certificate.")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:            caCertPool,
			InsecureSkipVerify: false,
		},
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: tr}
}
