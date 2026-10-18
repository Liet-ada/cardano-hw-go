// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cbor

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

var fuzzSeeds = []string{
	"00", "17", "1818", "181f", "1820", "20", "3818", "3bffffffffffffffff", "40", "60", "80", "a0",
	"a262696407646e616d6563616263", "d90102820102", "c249010000000000000000", "c24101", "c34100",
	"f4", "f5", "f6", "f7", "f820", "f93c00", "f97e00", "fa47c35000", "fb3ff8000000000000",
	"9f01ff", "bf6161f5ff", "5f4101ff", "7f6161ff", "7f62c3a9ff", "a21903e800616100",
	"818181818181818181818181818181818101", "8218191818", "d81843a10102", "7f61c361a9ff",
}

// addTxSeeds adds the transactions of internal/cli/testdata/txs.
func addTxSeeds(f *testing.F) {
	files, err := filepath.Glob("../cli/testdata/txs/inputs/*.json")
	if err != nil {
		f.Fatal(err)
	}
	for _, name := range files {
		b, err := os.ReadFile(name)
		if err != nil {
			f.Fatal(err)
		}
		var e struct{ CBORHex string }
		if json.Unmarshal(b, &e) != nil || e.CBORHex == "" {
			continue
		}
		raw, err := hex.DecodeString(e.CBORHex)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
}

// duplicateKey returns a key that is twice in a map of v, comparing every
// pair of keys by their canonical forms.
func duplicateKey(v Value) *Value {
	for i, e := range v.Entries {
		for _, f := range v.Entries[:i] {
			if Equal(e.Key, f.Key) {
				return &e.Key
			}
		}
		if d := duplicateKey(e.Key); d != nil {
			return d
		}
		if d := duplicateKey(e.Value); d != nil {
			return d
		}
	}
	for _, it := range v.Items {
		if d := duplicateKey(it); d != nil {
			return d
		}
	}
	return nil
}

// FuzzDecode checks that no input makes Decode or WellFormed panic, that
// what Decode accepts is well-formed, and that encoding keeps what was
// decoded: the canonical encoding decodes to itself, and the plain one to
// an equal value.
func FuzzDecode(f *testing.F) {
	for _, s := range fuzzSeeds {
		b, _ := hex.DecodeString(s)
		f.Add(b)
	}
	addTxSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		wf := WellFormed(data)
		v, err := Decode(data)
		if err != nil {
			return
		}
		if wf != nil {
			t.Fatalf("Decode takes %x, which is not well-formed", data)
		}
		if dup := duplicateKey(v); dup != nil {
			t.Fatalf("Decode takes %x, whose key %x is twice in a map", data, EncodeCanonical(*dup))
		}
		c := EncodeCanonical(v)
		w, err := Decode(c)
		if err != nil {
			t.Fatalf("canonical encoding %x of %x does not decode: %v", c, data, err)
		}
		if again := EncodeCanonical(w); !bytes.Equal(again, c) {
			t.Fatalf("canonical encoding of %x is %x, then %x", data, c, again)
		}
		e := Encode(v)
		u, err := Decode(e)
		if err != nil {
			t.Fatalf("encoding %x of %x does not decode: %v", e, data, err)
		}
		if !Equal(u, v) {
			t.Fatalf("encoding %x of %x decodes to another value", e, data)
		}
		if v.Kind == Array {
			items, err := ArrayItems(data)
			if err != nil || len(items) != len(v.Items) {
				t.Fatalf("ArrayItems of %x: %d items, %v; Decode: %d", data, len(items), err, len(v.Items))
			}
			for i, it := range items {
				d, err := Decode(it)
				if err != nil || !Equal(d, v.Items[i]) {
					t.Fatalf("ArrayItems of %x: item %d is %x", data, i, it)
				}
			}
		}
	})
}
