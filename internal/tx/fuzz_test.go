// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tx

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// FuzzTransaction checks that no input makes validation or transformation
// panic, and that what transform writes has no fixable issue left and
// transforms to itself.
func FuzzTransaction(f *testing.F) {
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
	f.Fuzz(func(t *testing.T, data []byte) {
		if _, err := Validate(data); err != nil {
			return
		}
		d, err := Decode(data)
		if err != nil {
			t.Fatalf("%x validates but does not decode: %v", data, err)
		}
		tt, err := TransformTx(d.Tx, nil, nil)
		if err != nil {
			return // a script data hash needs cost models
		}
		out := Encode(&tt)
		issues, err := Validate(out)
		if err != nil {
			t.Fatalf("transform of %x gives %x, which does not validate: %v", data, out, err)
		}
		for _, i := range issues {
			if i.Fixable {
				t.Fatalf("transform of %x gives %x, which still has %s", data, out, i)
			}
		}
		d2, err := Decode(out)
		if err != nil {
			t.Fatal(err)
		}
		again, err := TransformTx(d2.Tx, nil, nil)
		if err != nil {
			t.Fatalf("transform of %x does not transform again: %v", out, err)
		}
		if b := Encode(&again); !bytes.Equal(b, out) {
			t.Fatalf("transform of %x gives %x, then %x", data, out, b)
		}
	})
}
