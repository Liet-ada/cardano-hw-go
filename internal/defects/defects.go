// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package defects lists the defects of cardano-hw-cli that cardano-hw-go
// does not copy.
//
// cardano-hw-go prints, writes and returns what cardano-hw-cli
// 1.20.0-beta.4 does, quirks included. A defect is an input cardano-hw-cli
// mishandles: it crashes with a JavaScript error instead of giving the
// error it has for the case, or it goes on with a value it should refuse
// and fails later, at the device or not at all. There cardano-hw-go does
// what cardano-hw-cli means to do.
//
// The code that departs from cardano-hw-cli for a defect says so in a
// comment, "cardano-hw-cli defect <id>". The tests that compare
// cardano-hw-go with recordings of cardano-hw-cli expect the correction
// where a recording shows a defect, and internal/cli tests every defect.
package defects

import "regexp"

// Defect is a way cardano-hw-cli mishandles an input.
type Defect struct {
	ID    string
	HWCLI string // what cardano-hw-cli does
	Here  string // what cardano-hw-go does instead
	// Shows matches the error cardano-hw-cli prints for the defect, when
	// it prints one of its own, and Says is what cardano-hw-go prints in
	// its place.
	Shows *regexp.Regexp
	Says  string
}

// All are the known defects.
var All = []Defect{
	{
		ID:    "transform-tagged-witnesses",
		HWCLI: "transaction transform, on a transaction with fixable issues whose vkey or bootstrap witnesses are a set tagged 258, crashes: it spreads the set as an array",
		Here:  "the error cardano-hw-cli has for a signed transaction it cannot transform",
		Shows: regexp.MustCompile(`Error: (shelley|byron)Witnesses is not iterable`),
		Says:  "Error: Transaction contains vkey witnesses, transformation would invalidate them",
	},
	{
		ID:    "testnet-magic-missing",
		HWCLI: "--testnet-magic given without a number leaves the network undefined, and the command crashes when it reads it",
		Here:  "the error cardano-hw-cli has for a missing protocol magic",
		Shows: regexp.MustCompile(`Error: Cannot read properties of undefined \(reading 'networkId'\)`),
		Says:  "Error: Testnet protocol magic is missing",
	},
	{
		ID:    "native-script-fractional-slot",
		HWCLI: "a native script file whose slot is not an integer passes its check and crashes when the slot is converted to a BigInt",
		Here:  "the error for an invalid native script file",
		Shows: regexp.MustCompile(`Error: The number \S+ cannot be converted to a BigInt because it is not an integer`),
		Says:  "Error: Invalid native script file",
	},
	{
		ID:    "native-script-fractional-required",
		HWCLI: "a native script file whose required count is not an integer is taken, and the script is encoded with a float",
		Here:  "the error for an invalid native script file",
	},
	{
		ID:    "cost-model-fractional",
		HWCLI: "cost models whose values are not integers are taken, and the script data hash is computed over floats",
		Here:  "the error for cost model values that are not an array of numbers",
	},
	{
		ID:    "mainnet-value",
		HWCLI: "--mainnet takes an optional value with no type function, so --mainnet x keeps the string x as the network",
		Here:  "an error for the value",
	},
	{
		ID:    "testnet-magic-not-number",
		HWCLI: "a protocol magic that is not a number, or not one of 32 bits, is taken as NaN or as is, and fails at the device",
		Here:  "an error for the protocol magic",
	},
	{
		ID:    "path-part-out-of-range",
		HWCLI: "a derivation path with a part beyond 32 bits is taken, and fails at the device",
		Here:  "the error for a path that cannot be parsed",
	},
	{
		ID:    "trezor-message-hex-odd-length",
		HWCLI: "message sign with a Trezor passes on a message hex of an odd number of digits, which trezor-connect lets through, and asks the device for a message of a fractional size",
		Here:  "trezor-connect's error for a message that is not hex",
	},
	{
		ID:    "number-out-of-range",
		HWCLI: "a number given on the command line that is negative or beyond 64 bits is taken as a BigInt, and fails at the device",
		Here:  "an error that names the option",
	},
}

// Correct returns what cardano-hw-go prints on stderr where cardano-hw-cli
// printed stderr: the same, with the error of every defect it shows
// replaced.
func Correct(stderr string) string {
	for _, d := range All {
		if d.Shows != nil {
			stderr = d.Shows.ReplaceAllLiteralString(stderr, d.Says)
		}
	}
	return stderr
}

// Find returns the defect with the given ID.
func Find(id string) (Defect, bool) {
	for _, d := range All {
		if d.ID == id {
			return d, true
		}
	}
	return Defect{}, false
}
