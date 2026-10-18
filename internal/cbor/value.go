// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package cbor decodes CBOR into a generic value tree and encodes it back in
// canonical form.
//
// Canonical form follows what cardano-hw-cli checks through node-cbor's
// canonical encoder (CIP-21): definite lengths, the shortest integer and
// float encodings, bignums that fit in 64 bits collapsed into integers, and
// map entries sorted by the bytes of their encoded keys.
package cbor

import (
	"bytes"
	"fmt"
	"math"
	"math/big"
)

// Kind is the type of a CBOR value.
type Kind uint8

const (
	Uint   Kind = iota // non-negative integer, in Value.Uint
	NegInt             // negative integer -1-Value.Uint
	Bytes              // byte string, in Value.Bytes
	Text               // UTF-8 text string, in Value.Bytes
	Array              // array, in Value.Items
	Map                // map, in Value.Entries, in the order read
	Tag                // tag Value.Uint over Value.Items[0]
	Simple             // simple value Value.Uint (false, true, null, undefined...)
	Float              // floating point number, in Value.Float
)

// Simple values.
const (
	SimpleFalse     = 20
	SimpleTrue      = 21
	SimpleNull      = 22
	SimpleUndefined = 23
)

// Well-known tags.
const (
	TagPosBignum   = 2
	TagNegBignum   = 3
	TagEncodedCBOR = 24
	TagRational    = 30
	TagSet         = 258
)

// Value is a decoded CBOR data item.
type Value struct {
	Kind    Kind
	Uint    uint64
	Bytes   []byte
	Items   []Value
	Entries []Entry
	Float   float64
}

// Entry is a key-value pair of a map.
type Entry struct {
	Key, Value Value
}

// NewUint returns an unsigned integer.
func NewUint(n uint64) Value { return Value{Kind: Uint, Uint: n} }

// NewInt returns an integer, negative or not.
func NewInt(n int64) Value {
	if n < 0 {
		return Value{Kind: NegInt, Uint: uint64(-(n + 1))}
	}
	return Value{Kind: Uint, Uint: uint64(n)}
}

// NewBytes returns a byte string.
func NewBytes(b []byte) Value { return Value{Kind: Bytes, Bytes: b} }

// NewText returns a text string.
func NewText(s string) Value { return Value{Kind: Text, Bytes: []byte(s)} }

// NewArray returns an array.
func NewArray(items ...Value) Value {
	if items == nil {
		items = []Value{}
	}
	return Value{Kind: Array, Items: items}
}

// NewMap returns a map with the entries in the given order.
func NewMap(entries ...Entry) Value {
	if entries == nil {
		entries = []Entry{}
	}
	return Value{Kind: Map, Entries: entries}
}

// NewTag returns content tagged with tag.
func NewTag(tag uint64, content Value) Value {
	return Value{Kind: Tag, Uint: tag, Items: []Value{content}}
}

// Null is the CBOR null.
var Null = Value{Kind: Simple, Uint: SimpleNull}

// NewBool returns true or false.
func NewBool(b bool) Value {
	if b {
		return Value{Kind: Simple, Uint: SimpleTrue}
	}
	return Value{Kind: Simple, Uint: SimpleFalse}
}

// IsNull reports whether v is null.
func (v Value) IsNull() bool { return v.Kind == Simple && v.Uint == SimpleNull }

// IsInt reports whether v is an integer: Uint, NegInt or a bignum tag.
func (v Value) IsInt() bool {
	switch v.Kind {
	case Uint, NegInt:
		return true
	case Tag:
		return (v.Uint == TagPosBignum || v.Uint == TagNegBignum) && v.Items[0].Kind == Bytes
	}
	return false
}

// BigInt returns the integer value of v, which must satisfy IsInt.
func (v Value) BigInt() *big.Int {
	switch v.Kind {
	case Uint:
		return new(big.Int).SetUint64(v.Uint)
	case NegInt:
		n := new(big.Int).SetUint64(v.Uint)
		return n.Neg(n.Add(n, big.NewInt(1)))
	case Tag:
		n := new(big.Int).SetBytes(v.Items[0].Bytes)
		if v.Uint == TagNegBignum {
			n.Neg(n.Add(n, big.NewInt(1)))
		}
		return n
	}
	panic("cbor: BigInt of a value that is not an integer")
}

// Content returns the tagged content of a Tag value.
func (v Value) Content() Value { return v.Items[0] }

// Get returns the value of the map entry whose key is the unsigned integer k.
func (v Value) Get(k uint64) (Value, bool) {
	for _, e := range v.Entries {
		if e.Key.Kind == Uint && e.Key.Uint == k {
			return e.Value, true
		}
	}
	return Value{}, false
}

// Equal reports whether a and b encode to the same canonical bytes.
func Equal(a, b Value) bool {
	return bytes.Equal(EncodeCanonical(a), EncodeCanonical(b))
}

func (k Kind) String() string {
	switch k {
	case Uint:
		return "unsigned integer"
	case NegInt:
		return "negative integer"
	case Bytes:
		return "byte string"
	case Text:
		return "text string"
	case Array:
		return "array"
	case Map:
		return "map"
	case Tag:
		return "tag"
	case Simple:
		return "simple value"
	case Float:
		return "float"
	}
	return fmt.Sprintf("kind(%d)", uint8(k))
}

// isIntegral reports whether f has no fractional part and fits the integers
// a JavaScript number encodes as such.
func isIntegral(f float64) bool {
	return !math.IsInf(f, 0) && !math.IsNaN(f) && f == math.Round(f)
}
