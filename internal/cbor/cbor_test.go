// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cbor

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Canonical items from RFC 8949, appendix A, decode and encode back to the
// same bytes.
func TestRoundTripCanonical(t *testing.T) {
	for _, h := range []string{
		"00", "01", "0a", "17", "1818", "1819", "1864", "1903e8", "1a000f4240",
		"1b000000e8d4a51000", "1bffffffffffffffff", "20", "29", "3863", "3903e7",
		"3bffffffffffffffff", "c249010000000000000000", "c349010000000000000000",
		"f90001", "f90400", "fa7f7fffff",
		"fb3ff199999999999a", "fb7e37e43c8800759c", "fbc010666666666666",
		"f4", "f5", "f6", "f7", "f0", "f8ff", "c11a514b67b0", "d74401020304",
		"40", "4401020304", "60", "6161", "6449455446", "62225c", "63e6b0b4",
		"80", "83010203", "8301820203820405", "a0", "a201020304",
		"a26161016162820203", "826161a161626163", "d818456449455446",
		"d9010282820102820304",
	} {
		in := unhex(t, h)
		v, err := Decode(in)
		if err != nil {
			t.Fatalf("%s: %v", h, err)
		}
		if got := EncodeCanonical(v); !bytes.Equal(got, in) {
			t.Errorf("%s: canonical %x", h, got)
		}
	}
}

// Encodings that decode but are not canonical, with their canonical form.
func TestCanonicalForm(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"1800", "00"},                                         // long head
		{"1a00000017", "17"},                                   // long head
		{"5f42010243030405ff", "450102030405"},                 // indefinite bytes
		{"7f657374726561646d696e67ff", "6973747265616d696e67"}, // indefinite text
		{"9f018202039f0405ffff", "8301820203820405"},           // indefinite arrays
		{"bf61610161629f0203ffff", "a26161016162820203"},       // indefinite map
		{"c24100", "00"},                                       // small bignum
		{"c249000000000000000001", "01"},                       // bignum with leading zeros
		{"c349000000000000000001", "21"},                       // negative bignum
		{"c24b0000010000000000000000", "c249010000000000000000"},
		{"fb3ff0000000000000", "01"}, // 1.0 is the integer 1
		{"fa3fc00000", "f93e00"},     // 1.5 fits a half
		{"fb4000000000000000", "02"},
	} {
		in := unhex(t, c.in)
		v, err := Decode(in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if got := hex.EncodeToString(EncodeCanonical(v)); got != c.want {
			t.Errorf("%s: canonical %s, want %s", c.in, got, c.want)
		}
	}
}

func TestMapKeyOrder(t *testing.T) {
	// keys 10, 100, -1, "z", "aa", h'00', [100], false: sorted by encoded bytes
	v := NewMap(
		Entry{NewBool(false), NewUint(0)},
		Entry{NewArray(NewUint(100)), NewUint(0)},
		Entry{NewBytes([]byte{0}), NewUint(0)},
		Entry{NewText("aa"), NewUint(0)},
		Entry{NewText("z"), NewUint(0)},
		Entry{NewInt(-1), NewUint(0)},
		Entry{NewUint(100), NewUint(0)},
		Entry{NewUint(10), NewUint(0)},
	)
	want := "a8" + "0a00" + "186400" + "2000" + "410000" + "617a00" + "62616100" + "81186400" + "f400"
	if got := hex.EncodeToString(EncodeCanonical(v)); got != want {
		t.Errorf("got %s, want %s", got, want)
	}
	// Encode keeps the order
	if got := Encode(v); got[1] != 0xf4 {
		t.Errorf("Encode reordered the map: %x", got)
	}
}

func TestDecodeErrors(t *testing.T) {
	for _, c := range []struct{ in, msg string }{
		{"", "unexpected end"},
		{"18", "unexpected end"},
		{"1c", "reserved"},
		{"5a00000005", "longer than the input"},
		{"9b00000000ffffffff00", "longer than the input"},
		{"a201000100", "duplicate map key"},
		{"a2410001410002", "duplicate map key"},
		{"62c328", "invalid UTF-8"},
		{"5f4101610200ff", "invalid chunk"},
		{"5f5f4101ffff", "invalid chunk"},
		{"ff", "unexpected break"},
		{"f800", "two-byte form"},
		{"c26161", "bignum"},
		{"1f", "indefinite length integer"},
		{"df00", "indefinite length tag"},
		{"9f01", "unexpected end"},
	} {
		_, err := Decode(unhex(t, c.in))
		if err == nil || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%q: error %v, want %q", c.in, err, c.msg)
		}
	}
	if _, err := Decode(unhex(t, "0000")); !errors.Is(err, ErrTrailingBytes) {
		t.Errorf("trailing bytes: %v", err)
	}
}

func TestDepthLimit(t *testing.T) {
	deep := append(bytes.Repeat([]byte{0x81}, MaxDepth), 0x00)
	if _, err := Decode(deep); err != nil {
		t.Fatalf("depth %d: %v", MaxDepth, err)
	}
	if _, err := Decode(append([]byte{0x81}, deep...)); err == nil {
		t.Fatal("depth past the limit decoded")
	}
}

func TestArrayItems(t *testing.T) {
	items, err := ArrayItems(unhex(t, "84a10001f6820102d90102814100"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a10001", "f6", "820102", "d90102814100"}
	if len(items) != len(want) {
		t.Fatalf("items %x", items)
	}
	for i := range want {
		if hex.EncodeToString(items[i]) != want[i] {
			t.Errorf("item %d: %x", i, items[i])
		}
	}
	if _, err := ArrayItems(unhex(t, "9f0102ff")); err != nil {
		t.Errorf("indefinite: %v", err)
	}
	if _, err := ArrayItems(unhex(t, "a0")); err == nil {
		t.Error("map split as an array")
	}
	if _, err := ArrayItems(unhex(t, "830102")); err == nil {
		t.Error("short array split")
	}
}

func TestBigInt(t *testing.T) {
	for h, want := range map[string]string{
		"00":                     "0",
		"3bffffffffffffffff":     "-18446744073709551616",
		"c249010000000000000000": "18446744073709551616",
		"c349010000000000000000": "-18446744073709551617",
	} {
		v, err := Decode(unhex(t, h))
		if err != nil {
			t.Fatal(err)
		}
		if !v.IsInt() || v.BigInt().String() != want {
			t.Errorf("%s: %v", h, v.BigInt())
		}
	}
}

func TestHalf(t *testing.T) {
	for _, f := range []float64{0, 1, -2, 65504, 5.960464477539063e-08, 0.00006103515625, 0.5, 1.5} {
		h, ok := floatToHalf(f)
		if !ok || halfToFloat(h) != f {
			t.Errorf("%v: %x %v", f, h, ok)
		}
	}
	for _, f := range []float64{65536, 1.1, 1e-9, math.Inf(1)} {
		if _, ok := floatToHalf(f); ok {
			t.Errorf("%v fit a half", f)
		}
	}
}

func FuzzDecode(f *testing.F) {
	for _, s := range []string{"00", "a26161016162820203", "9f018202039f0405ffff", "c249010000000000000000"} {
		b, _ := hex.DecodeString(s)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := Decode(data)
		if err != nil {
			return
		}
		canon := EncodeCanonical(v)
		w, err := Decode(canon)
		if err != nil {
			t.Fatalf("canonical form does not decode: %x: %v", canon, err)
		}
		if !bytes.Equal(EncodeCanonical(w), canon) {
			t.Fatalf("canonical form is not stable: %x", canon)
		}
	})
}
