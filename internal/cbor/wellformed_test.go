// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cbor

import (
	"bufio"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// TestWellFormedAgainstNodeCBOR compares with what the cbor package of
// Node (8.1.0, cardano-hw-cli's) decodes, on random bytes listed in
// testdata, or in CBOR_WELLFORMED_CASES (lines of "hex 1|0").
func TestWellFormedAgainstNodeCBOR(t *testing.T) {
	path := os.Getenv("CBOR_WELLFORMED_CASES")
	if path == "" {
		path = "testdata/node-cbor-wellformed.txt"
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n, bad := 0, 0
	for sc.Scan() {
		h, want, _ := strings.Cut(sc.Text(), " ")
		b, _ := hex.DecodeString(h)
		got := "0"
		if WellFormed(b) == nil {
			got = "1"
		}
		n++
		if got != want {
			bad++
			if bad <= 20 {
				t.Errorf("%s: got %s, want %s", h, got, want)
			}
		}
	}
	t.Logf("%d cases, %d differ", n, bad)
}

// TestWellFormedOneByteArguments covers the heads with a one-byte
// argument, which the random cases above hardly reach: integers take any
// value there, even one that fits in the initial byte, and only simple
// values must be 32 or more.
func TestWellFormedOneByteArguments(t *testing.T) {
	for _, c := range []struct {
		hex  string
		want bool
	}{
		{"1818", true}, {"181e", true}, {"181f", true}, {"1820", true},
		{"1802", true}, {"3818", true}, {"381f", true}, {"3800", true},
		{"8218191818", true},
		{"f818", false}, {"f81f", false}, {"f820", true}, {"f8ff", true},
	} {
		b, _ := hex.DecodeString(c.hex)
		if got := WellFormed(b) == nil; got != c.want {
			t.Errorf("WellFormed(%s) = %v, want %v", c.hex, got, c.want)
		}
	}
}
