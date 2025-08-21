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

package main

import (
	"encoding/json"
	"fmt"

	"github.com/jessevdk/go-flags"

	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/asserts/signtool"
	"github.com/snapcore/snapd/i18n"
)

type cmdClusterCommit struct {
	clientMixin
	KeyName keyName `long:"key-name" required:"yes"`
}

var shortClusterCommitHelp = i18n.G("Commit a signed cluster assertion")
var longClusterCommitHelp = i18n.G(`
The cluster commit command retrieves the uncommitted cluster state,
signs it with the specified key, and commits the signed assertion.

This command should be run after cluster assembly has completed successfully.
The specified key must be available in your GPG keyring or external key manager,
and its corresponding account-key assertion must already be acked in the system.

Example:
  snap cluster commit --key-name=my-signing-key
`)

func init() {
	addClusterCommand("commit", shortClusterCommitHelp, longClusterCommitHelp, func() flags.Commander {
		return &cmdClusterCommit{}
	}, map[string]string{
		// TRANSLATORS: This should not start with a lowercase letter.
		"key-name": i18n.G("Name of the key to use for signing"),
	}, nil)
}

func (x *cmdClusterCommit) Execute(args []string) error {
	if len(args) > 0 {
		return ErrExtraArgs
	}

	// get uncommitted cluster headers
	headers, err := x.client.GetClusterUncommittedHeaders()
	if err != nil {
		return fmt.Errorf("cannot get uncommitted cluster headers: %v", err)
	}

	// get the keypair manager
	keypairMgr, err := signtool.GetKeypairManager()
	if err != nil {
		return err
	}

	// get the private key
	privKey, err := keypairMgr.GetByName(string(x.KeyName))
	if err != nil {
		// TRANSLATORS: %q is the key name, %v the error message
		return fmt.Errorf(i18n.G("cannot use %q key: %v"), x.KeyName, err)
	}

	// add authority-id to headers (required for signing)
	// the account-key assertion should already be acked, so we just need
	// to set the authority-id to the key's account
	headers["authority-id"] = privKey.PublicKey().ID()

	// convert headers to JSON for signing
	statement, err := json.Marshal(headers)
	if err != nil {
		return fmt.Errorf("cannot marshal headers: %v", err)
	}

	// sign the assertion
	signOpts := signtool.Options{
		KeyID:     privKey.PublicKey().ID(),
		Statement: statement,
	}

	encodedAssert, err := signtool.Sign(&signOpts, keypairMgr)
	if err != nil {
		return fmt.Errorf("cannot sign cluster assertion: %v", err)
	}

	// decode the signed assertion to get the cluster type
	decoded, err := asserts.Decode(encodedAssert)
	if err != nil {
		return fmt.Errorf("cannot decode signed assertion: %v", err)
	}

	clusterAssert, ok := decoded.(*asserts.Cluster)
	if !ok {
		return fmt.Errorf("internal error: signed assertion is not a cluster assertion")
	}

	// commit the signed assertion
	if err := x.client.CommitClusterAssertion(clusterAssert); err != nil {
		return fmt.Errorf("cannot commit cluster assertion: %v", err)
	}

	fmt.Fprintf(Stdout, i18n.G("Cluster assertion committed successfully.\n"))
	return nil
}