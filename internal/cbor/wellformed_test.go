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
