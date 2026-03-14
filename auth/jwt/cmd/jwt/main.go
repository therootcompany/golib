// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

// Command jwt is a CLI tool for signing, verifying, inspecting, and
// generating JSON Web Tokens and Keys.
//
// Usage:
//
//	jwt sign    --key <key> <claims>     sign claims into a compact JWT
//	jwt inspect [token]                  decode and display token details
//	jwt verify  --key <key> [token]      verify signature and validate claims
//	jwt keygen  [--alg EdDSA]            generate a fresh private key
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "sign":
		err = cmdSign(os.Args[2:])
	case "inspect":
		err = cmdInspect(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "keygen":
		err = cmdKeygen(os.Args[2:])
	case "-h", "--help", "help":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: jwt <command> [options]

Commands:
  sign      Sign claims into a compact JWT
  inspect   Decode and display token details
  verify    Verify signature and validate claims
  keygen    Generate a fresh private key (JWK)

Run 'jwt <command> --help' for details on each command.
`)
}
