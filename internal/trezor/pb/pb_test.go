// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package pb

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

type inner struct {
	A uint32 `pb:"1"`
	B []byte `pb:"2"`
}

type sample struct {
	Path     []uint32 `pb:"1"`
	Show     *bool    `pb:"2"`
	Kind     uint32   `pb:"3"`
	Name     *string  `pb:"4"`
	Data     []byte   `pb:"5"`
	Mint     *int64   `pb:"6,zigzag"`
	Inner    *inner   `pb:"7"`
	Inners   []inner  `pb:"8"`
	Required uint64   `pb:"9"`
	Neg      int32    `pb:"10"`
}

func ptr[T any](v T) *T { return &v }

func TestMarshalKnown(t *testing.T) {
	m := sample{
		Path: []uint32{0x8000073c, 0x80000717, 0x80000000},
		Show: ptr(true),
		Kind: 2,
		Mint: ptr(int64(-5)),
	}
	got, err := Marshal(&m)
	if err != nil {
		t.Fatal(err)
	}
	// 08 bc8e8080 08 | 08 978e8080 08 | 08 80808080 08 | 10 01 | 18 02 | 30 09 | 48 00 | 50 00
	want := "08bc8e80800808978e8080080880808080081001180230094800" + "5000"
	if hex.EncodeToString(got) != want {
		t.Errorf("got %x, want %s", got, want)
	}
}

func TestRoundTrip(t *testing.T) {
	m := sample{
		Path:     []uint32{1, 2, 3},
		Name:     ptr("addr_test1"),
		Data:     []byte{},
		Mint:     ptr(int64(-9223372036854775808)),
		Inner:    &inner{A: 7, B: []byte{1, 2}},
		Inners:   []inner{{A: 1}, {A: 2, B: []byte{9}}},
		Required: 1<<64 - 1,
		Neg:      -3,
	}
	b, err := Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var got sample
	if err := Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, m) {
		t.Errorf("got %+v, want %+v", got, m)
	}
}

func TestPackedAndUnknown(t *testing.T) {
	// field 1 packed [1, 300], unknown field 99 (varint), unknown field 98
	// (bytes), field 3 = 5
	data, _ := hex.DecodeString("0a0301ac02" + "98060a" + "92060201" + "02" + "1805")
	var got sample
	if err := Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Path, []uint32{1, 300}) || got.Kind != 5 {
		t.Errorf("got %+v", got)
	}
}

func TestTruncated(t *testing.T) {
	for _, h := range []string{"08", "0a05010203", "2a", "0d0102"} {
		data, _ := hex.DecodeString(h)
		var s sample
		if err := Unmarshal(data, &s); err == nil {
			t.Errorf("%s decoded", h)
		}
	}
}

func FuzzUnmarshal(f *testing.F) {
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		var s sample
		if err := Unmarshal(data, &s); err != nil {
			return
		}
		b, err := Marshal(&s)
		if err != nil {
			t.Fatal(err)
		}
		var s2 sample
		if err := Unmarshal(b, &s2); err != nil {
			t.Fatalf("re-decode: %v", err)
		}
		b2, _ := Marshal(&s2)
		if !bytes.Equal(b, b2) {
			t.Fatalf("unstable: %x %x", b, b2)
		}
	})
}
