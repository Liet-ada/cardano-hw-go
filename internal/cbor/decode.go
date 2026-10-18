// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cbor

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/maphash"
	"math"
	"slices"
	"unicode/utf8"
)

// MaxDepth bounds the nesting of arrays, maps and tags. Plutus data nests,
// but no transaction of a few tens of kilobytes needs more.
const MaxDepth = 512

// ErrTrailingBytes reports bytes left after the data item.
var ErrTrailingBytes = errors.New("cbor: trailing bytes after the data item")

// DecodeError reports malformed input at a byte offset.
type DecodeError struct {
	Offset int
	Msg    string
}

func (e *DecodeError) Error() string {
	return fmt.Sprintf("cbor: %s at byte %d", e.Msg, e.Offset)
}

// Decode decodes data, which must hold exactly one data item.
func Decode(data []byte) (Value, error) {
	d := decoder{data: data}
	v, err := d.value(0)
	if err != nil {
		return Value{}, err
	}
	if d.pos != len(data) {
		return Value{}, ErrTrailingBytes
	}
	return v, nil
}

// ArrayItems splits data, which must hold exactly one definite or indefinite
// array, into the raw bytes of its items. Each item is fully validated.
func ArrayItems(data []byte) ([][]byte, error) {
	d := decoder{data: data}
	major, info, err := d.head()
	if err != nil {
		return nil, err
	}
	if major != majorArray {
		return nil, &DecodeError{0, "not an array"}
	}
	var items [][]byte
	next := func() error {
		start := d.pos
		if _, err := d.value(1); err != nil {
			return err
		}
		items = append(items, data[start:d.pos])
		return nil
	}
	if info == infoIndefinite {
		for !d.atBreak() {
			if err := next(); err != nil {
				return nil, err
			}
		}
		d.pos++
	} else {
		n, err := d.argument(info)
		if err != nil {
			return nil, err
		}
		if n > uint64(len(data)) {
			return nil, &DecodeError{d.pos, "array longer than the input"}
		}
		for i := uint64(0); i < n; i++ {
			if err := next(); err != nil {
				return nil, err
			}
		}
	}
	if d.pos != len(data) {
		return nil, ErrTrailingBytes
	}
	return items, nil
}

const (
	majorUint   = 0
	majorNegInt = 1
	majorBytes  = 2
	majorText   = 3
	majorArray  = 4
	majorMap    = 5
	majorTag    = 6
	majorSimple = 7

	infoIndefinite = 31
)

type decoder struct {
	data []byte
	pos  int
	// sum is the hash of the canonical form of the value decoded last,
	// built from those of its items, so that a duplicate map key is found
	// without encoding every key again at each level of nesting
	sum uint64
}

var sumSeed = maphash.MakeSeed()

// value decodes a data item and sets d.sum. Values with the same canonical
// form get the same sum.
func (d *decoder) value(depth int) (Value, error) {
	v, err := d.item(depth)
	if err == nil && !(v.Kind == Array || v.Kind == Map || v.Kind == Tag && !v.IsInt()) {
		d.sum = maphash.Bytes(sumSeed, EncodeCanonical(v))
	}
	return v, err
}

// containerSum is the sum of an array, map or tag of the given kind, size
// or tag number and item sums.
func containerSum(kind Kind, n uint64, sums ...uint64) uint64 {
	var h maphash.Hash
	h.SetSeed(sumSeed)
	var b [8]byte
	h.WriteByte(byte(kind))
	h.Write(binary.LittleEndian.AppendUint64(b[:0], n))
	for _, s := range sums {
		h.Write(binary.LittleEndian.AppendUint64(b[:0], s))
	}
	return h.Sum64()
}

func (d *decoder) fail(msg string) error { return &DecodeError{d.pos, msg} }

func (d *decoder) atBreak() bool { return d.pos < len(d.data) && d.data[d.pos] == 0xff }

// head reads the initial byte of a data item.
func (d *decoder) head() (major, info byte, err error) {
	if d.pos >= len(d.data) {
		return 0, 0, d.fail("unexpected end of input")
	}
	b := d.data[d.pos]
	d.pos++
	return b >> 5, b & 0x1f, nil
}

// argument reads the argument that follows a head with additional info info.
func (d *decoder) argument(info byte) (uint64, error) {
	var n int
	switch {
	case info < 24:
		return uint64(info), nil
	case info == 24:
		n = 1
	case info == 25:
		n = 2
	case info == 26:
		n = 4
	case info == 27:
		n = 8
	default:
		return 0, d.fail("reserved additional information")
	}
	if len(d.data)-d.pos < n {
		return 0, d.fail("unexpected end of input")
	}
	b := d.data[d.pos : d.pos+n]
	d.pos += n
	switch n {
	case 1:
		return uint64(b[0]), nil
	case 2:
		return uint64(binary.BigEndian.Uint16(b)), nil
	case 4:
		return uint64(binary.BigEndian.Uint32(b)), nil
	}
	return binary.BigEndian.Uint64(b), nil
}

// count reads the length of a definite container, bounded by the input left:
// every element takes at least one byte.
func (d *decoder) count(info byte, perItem int) (int, error) {
	n, err := d.argument(info)
	if err != nil {
		return 0, err
	}
	if n > uint64(len(d.data)-d.pos)/uint64(perItem) {
		return 0, d.fail("container longer than the input")
	}
	return int(n), nil
}

// item decodes a data item, and sets d.sum if it is an array, a map or a
// tag other than a bignum.
func (d *decoder) item(depth int) (Value, error) {
	if depth > MaxDepth {
		return Value{}, d.fail("nesting too deep")
	}
	start := d.pos
	major, info, err := d.head()
	if err != nil {
		return Value{}, err
	}
	switch major {
	case majorUint, majorNegInt:
		if info == infoIndefinite {
			return Value{}, &DecodeError{start, "indefinite length integer"}
		}
		n, err := d.argument(info)
		if err != nil {
			return Value{}, err
		}
		k := Uint
		if major == majorNegInt {
			k = NegInt
		}
		return Value{Kind: k, Uint: n}, nil

	case majorBytes, majorText:
		b, err := d.stringBytes(major, info)
		if err != nil {
			return Value{}, err
		}
		if major == majorText {
			if !utf8.Valid(b) {
				return Value{}, &DecodeError{start, "invalid UTF-8 in text string"}
			}
			return Value{Kind: Text, Bytes: b}, nil
		}
		return Value{Kind: Bytes, Bytes: b}, nil

	case majorArray:
		items := []Value{}
		var sums []uint64
		if info == infoIndefinite {
			for !d.atBreak() {
				v, err := d.value(depth + 1)
				if err != nil {
					return Value{}, err
				}
				items = append(items, v)
				sums = append(sums, d.sum)
			}
			d.pos++
		} else {
			n, err := d.count(info, 1)
			if err != nil {
				return Value{}, err
			}
			items = make([]Value, 0, n)
			sums = make([]uint64, 0, n)
			for i := 0; i < n; i++ {
				v, err := d.value(depth + 1)
				if err != nil {
					return Value{}, err
				}
				items = append(items, v)
				sums = append(sums, d.sum)
			}
		}
		d.sum = containerSum(Array, uint64(len(items)), sums...)
		return Value{Kind: Array, Items: items}, nil

	case majorMap:
		entries := []Entry{}
		var sums [][2]uint64
		seen := map[uint64][]int{} // entries by the sum of their key
		add := func() error {
			keyAt := d.pos
			k, err := d.value(depth + 1)
			if err != nil {
				return err
			}
			ks := d.sum
			// keys with the same sum are compared for real
			for _, i := range seen[ks] {
				if Equal(entries[i].Key, k) {
					return &DecodeError{keyAt, "duplicate map key"}
				}
			}
			v, err := d.value(depth + 1)
			if err != nil {
				return err
			}
			seen[ks] = append(seen[ks], len(entries))
			entries = append(entries, Entry{k, v})
			sums = append(sums, [2]uint64{ks, d.sum})
			return nil
		}
		if info == infoIndefinite {
			for !d.atBreak() {
				if err := add(); err != nil {
					return Value{}, err
				}
			}
			d.pos++
		} else {
			n, err := d.count(info, 2)
			if err != nil {
				return Value{}, err
			}
			entries = make([]Entry, 0, n)
			for i := 0; i < n; i++ {
				if err := add(); err != nil {
					return Value{}, err
				}
			}
		}
		// the canonical form sorts the entries, so the sum does not
		// depend on their order
		slices.SortFunc(sums, func(a, b [2]uint64) int {
			return cmp.Or(cmp.Compare(a[0], b[0]), cmp.Compare(a[1], b[1]))
		})
		flat := make([]uint64, 0, 2*len(sums))
		for _, s := range sums {
			flat = append(flat, s[0], s[1])
		}
		d.sum = containerSum(Map, uint64(len(entries)), flat...)
		return Value{Kind: Map, Entries: entries}, nil

	case majorTag:
		if info == infoIndefinite {
			return Value{}, &DecodeError{start, "indefinite length tag"}
		}
		tag, err := d.argument(info)
		if err != nil {
			return Value{}, err
		}
		content, err := d.value(depth + 1)
		if err != nil {
			return Value{}, err
		}
		if (tag == TagPosBignum || tag == TagNegBignum) && content.Kind != Bytes {
			return Value{}, &DecodeError{start, "bignum whose content is not a byte string"}
		}
		d.sum = containerSum(Tag, tag, d.sum) // value takes a bignum's from its encoding
		return NewTag(tag, content), nil
	}

	// major type 7: simple values and floats
	switch {
	case info < 24:
		return Value{Kind: Simple, Uint: uint64(info)}, nil
	case info == 24:
		if d.pos >= len(d.data) {
			return Value{}, d.fail("unexpected end of input")
		}
		s := d.data[d.pos]
		d.pos++
		if s < 32 {
			return Value{}, &DecodeError{start, "simple value in the two-byte form below 32"}
		}
		return Value{Kind: Simple, Uint: uint64(s)}, nil
	case info == 25:
		bits, err := d.argument(info)
		if err != nil {
			return Value{}, err
		}
		return Value{Kind: Float, Float: halfToFloat(uint16(bits))}, nil
	case info == 26:
		bits, err := d.argument(info)
		if err != nil {
			return Value{}, err
		}
		return Value{Kind: Float, Float: float64(math.Float32frombits(uint32(bits)))}, nil
	case info == 27:
		bits, err := d.argument(info)
		if err != nil {
			return Value{}, err
		}
		return Value{Kind: Float, Float: math.Float64frombits(bits)}, nil
	case info == infoIndefinite:
		return Value{}, &DecodeError{start, "unexpected break"}
	}
	return Value{}, &DecodeError{start, "reserved additional information"}
}

// stringBytes reads a byte or text string, joining the chunks of an
// indefinite length one.
func (d *decoder) stringBytes(major, info byte) ([]byte, error) {
	if info != infoIndefinite {
		n, err := d.count(info, 1)
		if err != nil {
			return nil, err
		}
		b := d.data[d.pos : d.pos+n]
		d.pos += n
		return bytes.Clone(b), nil
	}
	out := []byte{}
	for !d.atBreak() {
		chunkAt := d.pos
		m, ci, err := d.head()
		if err != nil {
			return nil, err
		}
		if m != major || ci == infoIndefinite {
			return nil, &DecodeError{chunkAt, "invalid chunk in an indefinite length string"}
		}
		n, err := d.count(ci, 1)
		if err != nil {
			return nil, err
		}
		chunk := d.data[d.pos : d.pos+n]
		// a character cannot be split between chunks (RFC 8949, 3.2.3)
		if major == majorText && !utf8.Valid(chunk) {
			return nil, &DecodeError{chunkAt, "invalid UTF-8 in text string"}
		}
		out = append(out, chunk...)
		d.pos += n
	}
	d.pos++
	return out, nil
}

func halfToFloat(h uint16) float64 {
	sign := 1.0
	if h&0x8000 != 0 {
		sign = -1
	}
	exp := int(h>>10) & 0x1f
	frac := float64(h & 0x3ff)
	switch exp {
	case 0:
		return sign * math.Ldexp(frac, -24)
	case 31:
		if frac == 0 {
			return math.Inf(int(sign))
		}
		return math.NaN()
	}
	return sign * math.Ldexp(frac+1024, exp-25)
}
