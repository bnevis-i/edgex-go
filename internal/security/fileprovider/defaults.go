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

package fileprovider

import (
	"encoding/json"
)

func makeDefaultTokenPolicy(serviceName string) map[string]interface{} {
	protectedPath := "secret/edgex/" + serviceName + "/*"
	capabilities := []string{"create", "update", "delete", "list", "read"}
	acl := struct {
		Capabilities []string `json:"capabilities"`
	}{
		Capabilities: capabilities,
	}
	pathObject := map[string]interface{}{protectedPath: acl}
	entry := struct {
		Path interface{} `json:"path"`
	}{
		Path: pathObject,
	}

	// Marshal the data and then unmarshal it again to turn it into an opaque data structure

	bytes, err := json.Marshal(entry)
	if err != nil {
		panic(err) // We are in control; should never happen
	}

	retval := make(map[string]interface{})
	json.Unmarshal(bytes, &retval)
	return retval

	/*
		{
			"path": {
			  "secret/edgex/service-name/*": {
				"capabilities": [ "create", "update", "delete", "list", "read" ]
			  }
			}
		  }
	*/
}

func makeDefaultTokenParameters(serviceName string) map[string]interface{} {
	policyName := "edgex-service-" + serviceName
	data := struct {
		DisplayName string   `json:"display_name"`
		NoParent    bool     `json:"no_parent"`
		Policies    []string `json:"policies"`
	}{
		DisplayName: serviceName,
		NoParent:    true,
		Policies:    []string{policyName},
	}

	// Marshal the data and then unmarshal it again to turn it into an opaque data structure

	bytes, err := json.Marshal(data)
	if err != nil {
		panic(err) // We are in control; should never happen
	}

	var retval map[string]interface{}
	json.Unmarshal(bytes, &retval)
	return retval
}
