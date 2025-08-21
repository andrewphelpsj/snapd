// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package client_test

import (
	"encoding/json"
	"time"

	"gopkg.in/check.v1"

	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/asserts/assertstest"
	"github.com/snapcore/snapd/client"
)

func (cs *clientSuite) TestClientClusterAssemble(c *check.C) {
	cs.status = 202
	cs.rsp = `{
		"type": "async",
		"status-code": 202,
		"change": "42"
	}`

	opts := client.ClusterAssembleOptions{
		Secret:       "test-secret-123",
		Address:      "192.168.1.100:8080",
		ExpectedSize: 3,
	}

	changeID, err := cs.cli.ClusterAssemble(opts)
	c.Assert(err, check.IsNil)
	c.Check(changeID, check.Equals, "42")

	// verify the request
	c.Check(cs.req.Method, check.Equals, "POST")
	c.Check(cs.req.URL.Path, check.Equals, "/v2/cluster")
	c.Check(cs.req.Header.Get("Content-Type"), check.Equals, "application/json")

	var reqBody map[string]interface{}
	err = json.NewDecoder(cs.req.Body).Decode(&reqBody)
	c.Assert(err, check.IsNil)
	c.Check(reqBody["action"], check.Equals, "assemble")
	c.Check(reqBody["secret"], check.Equals, "test-secret-123")
	c.Check(reqBody["address"], check.Equals, "192.168.1.100:8080")
	c.Check(reqBody["expected-size"], check.Equals, float64(3))
}

func (cs *clientSuite) TestClientClusterAssembleNoExpectedSize(c *check.C) {
	cs.status = 202
	cs.rsp = `{
		"type": "async",
		"status-code": 202,
		"change": "43"
	}`

	opts := client.ClusterAssembleOptions{
		Secret:  "test-secret-456",
		Address: "10.0.0.1:9090",
		// ExpectedSize defaults to 0
	}

	changeID, err := cs.cli.ClusterAssemble(opts)
	c.Assert(err, check.IsNil)
	c.Check(changeID, check.Equals, "43")

	var reqBody map[string]interface{}
	err = json.NewDecoder(cs.req.Body).Decode(&reqBody)
	c.Assert(err, check.IsNil)
	c.Check(reqBody["action"], check.Equals, "assemble")
	c.Check(reqBody["secret"], check.Equals, "test-secret-456")
	c.Check(reqBody["address"], check.Equals, "10.0.0.1:9090")
	// expected-size should be omitted when 0
	c.Check(reqBody["expected-size"], check.IsNil)
}

func (cs *clientSuite) TestClientClusterAssembleError(c *check.C) {
	cs.status = 400
	cs.rsp = `{
		"type": "error",
		"result": {
			"message": "invalid address format"
		}
	}`

	opts := client.ClusterAssembleOptions{
		Secret:  "test-secret",
		Address: "invalid-address",
	}

	_, err := cs.cli.ClusterAssemble(opts)
	c.Assert(err, check.ErrorMatches, "invalid address format")
}

func (cs *clientSuite) TestClientGetClusterUncommittedHeaders(c *check.C) {
	cs.status = 200
	cs.rsp = `{
		"type": "sync",
		"result": {
			"type": "cluster",
			"cluster-id": "test-cluster-123",
			"sequence": "1",
			"devices": [
				{
					"id": "1",
					"brand-id": "canonical",
					"model": "ubuntu-core-24-amd64",
					"serial": "device-1",
					"addresses": ["192.168.1.10"]
				}
			],
			"subclusters": [
				{
					"name": "default",
					"devices": ["1"]
				}
			],
			"timestamp": "2024-01-15T10:30:00Z"
		}
	}`

	headers, err := cs.cli.GetClusterUncommittedHeaders()
	c.Assert(err, check.IsNil)
	c.Check(headers["type"], check.Equals, "cluster")
	c.Check(headers["cluster-id"], check.Equals, "test-cluster-123")
	c.Check(headers["sequence"], check.Equals, "1")
	c.Check(headers["timestamp"], check.Equals, "2024-01-15T10:30:00Z")

	// verify the request
	c.Check(cs.req.Method, check.Equals, "GET")
	c.Check(cs.req.URL.Path, check.Equals, "/v2/cluster/uncommitted")
}

func (cs *clientSuite) TestClientCommitClusterAssertion(c *check.C) {
	cs.status = 200
	cs.rsp = `{
		"type": "sync",
		"result": null
	}`

	// create a test cluster assertion
	privKey, _ := assertstest.GenerateKey(752)
	storeStack := assertstest.NewStoreStack("canonical", nil)

	db, err := asserts.OpenDatabase(&asserts.DatabaseConfig{
		Backstore: asserts.NewMemoryBackstore(),
		Trusted:   storeStack.Trusted,
	})
	c.Assert(err, check.IsNil)

	err = db.Add(storeStack.StoreAccountKey(""))
	c.Assert(err, check.IsNil)

	account := assertstest.NewAccount(storeStack, "test-account", map[string]any{
		"validation": "verified",
	}, "")
	err = db.Add(account)
	c.Assert(err, check.IsNil)

	accountKey := assertstest.NewAccountKey(storeStack, account, nil, privKey.PublicKey(), "")
	err = db.Add(accountKey)
	c.Assert(err, check.IsNil)

	headers := map[string]any{
		"type":         "cluster",
		"authority-id": account.AccountID(),
		"cluster-id":   "test-cluster-456",
		"sequence":     "1",
		"devices": []any{
			map[string]any{
				"id":        "1",
				"brand-id":  "canonical",
				"model":     "ubuntu-core-24-amd64",
				"serial":    "device-1",
				"addresses": []any{"192.168.1.10"},
			},
		},
		"subclusters": []any{
			map[string]any{
				"name":    "default",
				"devices": []any{"1"},
			},
		},
		"timestamp": time.Now().Format(time.RFC3339),
	}

	signingDB := assertstest.NewSigningDB(account.AccountID(), privKey)
	clusterAssert, err := signingDB.Sign(asserts.ClusterType, headers, nil, "")
	c.Assert(err, check.IsNil)

	// test the commit
	err = cs.cli.CommitClusterAssertion(clusterAssert.(*asserts.Cluster))
	c.Assert(err, check.IsNil)

	// verify the request
	c.Check(cs.req.Method, check.Equals, "POST")
	c.Check(cs.req.URL.Path, check.Equals, "/v2/cluster/uncommitted")
	c.Check(cs.req.Header.Get("Content-Type"), check.Equals, "application/json")

	var reqBody map[string]interface{}
	err = json.NewDecoder(cs.req.Body).Decode(&reqBody)
	c.Assert(err, check.IsNil)
	c.Check(reqBody["assertion"], check.NotNil)
	// verify it's a valid assertion string
	assertionStr, ok := reqBody["assertion"].(string)
	c.Assert(ok, check.Equals, true)
	decoded, err := asserts.Decode([]byte(assertionStr))
	c.Assert(err, check.IsNil)
	c.Check(decoded.Type().Name, check.Equals, "cluster")
}
