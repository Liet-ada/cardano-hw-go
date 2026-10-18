// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package oracle compares internal/cbor with fxamacker/cbor, an
// independent implementation of RFC 8949, on fuzzed input.
//
// It is a separate module so that fxamacker/cbor never enters
// cardano-hw-go's module graph. Run it with `make fuzz`.
package oracle

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"unicode/utf8"

	fx "github.com/fxamacker/cbor/v2"

	"github.com/Liet-ada/cardano-hw-go/internal/cbor"
)

// What fxamacker/cbor does the way node-cbor and internal/cbor do: duplicate
// keys are allowed by WellFormed and refused by Decode, the canonical form
// sorts map keys by their encoded bytes, as node-cbor, and a bignum that
// fits in 64 bits is encoded as an integer.
var (
	wellFormed = mustDec(fx.DecOptions{
		DupMapKey:        fx.DupMapKeyQuiet,
		IndefLength:      fx.IndefLengthAllowed,
		TagsMd:           fx.TagsAllowed,
		MaxNestedLevels:  10001,
		MaxArrayElements: 1<<31 - 1,
		MaxMapPairs:      1<<31 - 1,
	})
	decode = mustDec(fx.DecOptions{
		DupMapKey:        fx.DupMapKeyEnforcedAPF,
		IndefLength:      fx.IndefLengthAllowed,
		TagsMd:           fx.TagsAllowed,
		MaxNestedLevels:  cbor.MaxDepth + 1,
		MaxArrayElements: 1<<31 - 1,
		MaxMapPairs:      1<<31 - 1,
		MapKeyByteString: fx.MapKeyByteStringAllowed,
		DefaultMapType:   reflect.TypeOf(map[any]any(nil)),
	})
	canonical = mustEnc()
)

func mustDec(o fx.DecOptions) fx.DecMode {
	m, err := o.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}

func mustEnc() fx.EncMode {
	o := fx.CoreDetEncOptions()
	o.TagsMd = fx.TagsAllowed
	o.BigIntConvert = fx.BigIntConvertShortest
	m, err := o.EncMode()
	if err != nil {
		panic(err)
	}
	return m
}

// comparable reports whether fxamacker/cbor can give v back as node-cbor
// would: floats are JavaScript numbers to node-cbor, so an integral one is
// encoded as an integer; fxamacker/cbor decodes the undefined value as
// nil, which it encodes as null, and the date and time of tags 0 and 1 as
// a time, which it encodes without the tag.
func comparable(v cbor.Value) bool {
	switch v.Kind {
	case cbor.Float:
		return false
	case cbor.Simple:
		return v.Uint != cbor.SimpleUndefined
	case cbor.Tag:
		if v.Uint == 0 || v.Uint == 1 {
			return false
		}
	}
	for _, it := range v.Items {
		if !comparable(it) {
			return false
		}
	}
	for _, e := range v.Entries {
		if !comparable(e.Key) || !comparable(e.Value) {
			return false
		}
	}
	return true
}

// validTexts reports whether every text string of data, which is
// well-formed, is UTF-8, and every chunk of an indefinite length one.
func validTexts(data []byte) bool {
	ok := true
	var item func(i int) int
	item = func(i int) int {
		major, info := data[i]>>5, data[i]&0x1f
		i++
		if info == 31 {
			for data[i] != 0xff {
				i = item(i)
			}
			return i + 1
		}
		var arg uint64
		if info < 24 {
			arg = uint64(info)
		} else {
			n := 1 << (info - 24)
			for _, c := range data[i : i+n] {
				arg = arg<<8 | uint64(c)
			}
			i += n
		}
		switch major {
		case 2:
			return i + int(arg)
		case 3:
			ok = ok && utf8.Valid(data[i:i+int(arg)])
			return i + int(arg)
		case 4, 5:
			if major == 5 {
				arg *= 2
			}
			for k := uint64(0); k < arg; k++ {
				i = item(i)
			}
		case 6:
			return item(i)
		}
		return i
	}
	item(0)
	return ok
}

// FuzzAgainstFxamacker checks that both libraries tell well-formed CBOR
// from not alike, and that what both decode has the same canonical form.
func FuzzAgainstFxamacker(f *testing.F) {
	for _, s := range []string{
		"00", "1818", "3818", "40", "60", "80", "a0", "9f01ff", "bf6161f5ff", "5f4101ff", "7f6161ff",
		"7f61c361a9ff", "c24101", "c249010000000000000000", "d90102820102", "a21903e800616100",
		"a20100180100", "f6", "f7", "f820", "f93c00", "8218191818", "d81843a10102",
		"c11b3030303030303030", "62ec30",
	} {
		b, _ := hex.DecodeString(s)
		f.Add(b)
	}
	files, err := filepath.Glob("../../internal/cli/testdata/txs/inputs/*.json")
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
		// fxamacker/cbor's Wellformed does not check that texts are UTF-8,
		// which node-cbor does, each chunk of an indefinite one on its own
		hwErr, fxErr := cbor.WellFormed(data), wellFormed.Wellformed(data)
		fxOK := fxErr == nil && validTexts(data)
		if (hwErr == nil) != fxOK {
			t.Fatalf("%x: WellFormed %v, fxamacker/cbor %v with texts UTF-8 %v", data, hwErr, fxErr, fxOK)
		}
		v, err := cbor.Decode(data)
		var w any
		fxErr = decode.Unmarshal(data, &w)
		if err != nil || fxErr != nil {
			// what either refuses is not compared: fxamacker/cbor cannot
			// hold a map whose key is an array or a map in a Go map
			return
		}
		if !comparable(v) {
			return
		}
		want, err := canonical.Marshal(w)
		if err != nil {
			t.Fatalf("%x: fxamacker/cbor does not encode what it decoded: %v", data, err)
		}
		if got := cbor.EncodeCanonical(v); !bytes.Equal(got, want) {
			t.Fatalf("%x: canonical form %x, fxamacker/cbor %x", data, got, want)
		}
	})
}
