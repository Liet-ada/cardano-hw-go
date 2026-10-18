// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cbor

import (
	"bytes"
	"encoding/binary"
	"math"
	"math/big"
	"sort"
)

// EncodeCanonical encodes v in canonical form.
func EncodeCanonical(v Value) []byte {
	return appendValue(nil, v, true)
}

// Encode encodes v with definite lengths and the shortest heads, keeping map
// entries in their order.
func Encode(v Value) []byte {
	return appendValue(nil, v, false)
}

func appendHead(b []byte, major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return append(b, m|byte(n))
	case n <= math.MaxUint8:
		return append(b, m|24, byte(n))
	case n <= math.MaxUint16:
		return binary.BigEndian.AppendUint16(append(b, m|25), uint16(n))
	case n <= math.MaxUint32:
		return binary.BigEndian.AppendUint32(append(b, m|26), uint32(n))
	}
	return binary.BigEndian.AppendUint64(append(b, m|27), n)
}

func appendValue(b []byte, v Value, canonical bool) []byte {
	switch v.Kind {
	case Uint:
		return appendHead(b, majorUint, v.Uint)
	case NegInt:
		return appendHead(b, majorNegInt, v.Uint)
	case Bytes:
		return append(appendHead(b, majorBytes, uint64(len(v.Bytes))), v.Bytes...)
	case Text:
		return append(appendHead(b, majorText, uint64(len(v.Bytes))), v.Bytes...)
	case Array:
		b = appendHead(b, majorArray, uint64(len(v.Items)))
		for _, it := range v.Items {
			b = appendValue(b, it, canonical)
		}
		return b
	case Map:
		b = appendHead(b, majorMap, uint64(len(v.Entries)))
		if !canonical {
			for _, e := range v.Entries {
				b = appendValue(appendValue(b, e.Key, false), e.Value, false)
			}
			return b
		}
		type kv struct{ k, v []byte }
		enc := make([]kv, len(v.Entries))
		for i, e := range v.Entries {
			enc[i] = kv{appendValue(nil, e.Key, true), appendValue(nil, e.Value, true)}
		}
		sort.SliceStable(enc, func(i, j int) bool { return bytes.Compare(enc[i].k, enc[j].k) < 0 })
		for _, e := range enc {
			b = append(append(b, e.k...), e.v...)
		}
		return b
	case Tag:
		if canonical && (v.Uint == TagPosBignum || v.Uint == TagNegBignum) && v.Items[0].Kind == Bytes {
			return appendBignum(b, v.Uint == TagNegBignum, v.Items[0].Bytes)
		}
		return appendValue(appendHead(b, majorTag, v.Uint), v.Items[0], canonical)
	case Simple:
		if v.Uint < 24 {
			return append(b, majorSimple<<5|byte(v.Uint))
		}
		return append(b, majorSimple<<5|24, byte(v.Uint))
	case Float:
		return appendFloat(b, v.Float, canonical)
	}
	panic("cbor: encoding a value of unknown kind")
}

// appendBignum encodes a bignum the way node-cbor's canonical encoder does:
// as a plain integer when it fits in 64 bits, else without leading zeros.
func appendBignum(b []byte, negative bool, content []byte) []byte {
	n := new(big.Int).SetBytes(content)
	if n.IsUint64() {
		major := byte(majorUint)
		if negative {
			major = majorNegInt
		}
		return appendHead(b, major, n.Uint64())
	}
	tag := uint64(TagPosBignum)
	if negative {
		tag = TagNegBignum
	}
	mag := n.Bytes()
	b = appendHead(b, majorTag, tag)
	return append(appendHead(b, majorBytes, uint64(len(mag))), mag...)
}

// appendFloat encodes f. In canonical form it follows node-cbor, which only
// has JavaScript numbers: integral values become integers, and the rest take
// the shortest of half, single and double precision that keeps the value.
func appendFloat(b []byte, f float64, canonical bool) []byte {
	if canonical {
		switch {
		case math.IsNaN(f):
			return append(b, 0xf9, 0x7e, 0x00)
		case math.IsInf(f, 1):
			return append(b, 0xf9, 0x7c, 0x00)
		case math.IsInf(f, -1):
			return append(b, 0xf9, 0xfc, 0x00)
		case f == 0 && math.Signbit(f):
			return append(b, 0xf9, 0x80, 0x00)
		case isIntegral(f) && math.Abs(f) <= maxSafeInteger:
			if f < 0 {
				return appendHead(b, majorNegInt, uint64(-f)-1)
			}
			return appendHead(b, majorUint, uint64(f))
		}
		if h, ok := floatToHalf(f); ok {
			return binary.BigEndian.AppendUint16(append(b, 0xf9), h)
		}
	}
	if float64(float32(f)) == f {
		return binary.BigEndian.AppendUint32(append(b, 0xfa), math.Float32bits(float32(f)))
	}
	return binary.BigEndian.AppendUint64(append(b, 0xfb), math.Float64bits(f))
}

const maxSafeInteger = 1<<53 - 1

// floatToHalf returns the half precision bits of f when f is exactly
// representable in half precision.
func floatToHalf(f float64) (uint16, bool) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	bits := math.Float32bits(float32(f))
	if float64(math.Float32frombits(bits)) != f {
		return 0, false
	}
	sign := uint16(bits>>16) & 0x8000
	exp := int(bits>>23&0xff) - 127
	mant := bits & 0x7fffff
	switch {
	case f == 0:
		return sign, true
	case exp >= -14 && exp <= 15:
		if mant&0x1fff != 0 {
			return 0, false
		}
		return sign | uint16(exp+15)<<10 | uint16(mant>>13), true
	case exp >= -24 && exp < -14:
		// subnormal half: value = m * 2^-24 with m < 1024
		full := mant | 0x800000
		shift := uint(-exp - 14 + 13)
		if full&(1<<shift-1) != 0 {
			return 0, false
		}
		return sign | uint16(full>>shift), true
	}
	return 0, false
}
