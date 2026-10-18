// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package pb encodes and decodes the protocol buffers (proto2) messages of
// Trezor. Messages are Go structs whose fields carry a `pb:"N"` tag with the
// field number:
//
//   - integers, bools and named integer types (enums) are varints;
//     `pb:"N,zigzag"` marks a sint32 or sint64;
//   - string and []byte are length-delimited;
//   - structs and pointers to structs are embedded messages;
//   - slices are repeated fields (decoded packed or not);
//   - pointers to scalars and nil []byte are optional and left out when nil;
//     other scalars are always written.
package pb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
)

// Message is a protocol buffers message with its wire type number.
type Message interface {
	MessageType() uint16
}

const (
	wireVarint = 0
	wireI64    = 1
	wireBytes  = 2
	wireI32    = 5
)

type fieldInfo struct {
	num    uint64
	index  int
	zigzag bool
}

func fields(t reflect.Type) ([]fieldInfo, error) {
	var out []fieldInfo
	for i := 0; i < t.NumField(); i++ {
		tag, ok := t.Field(i).Tag.Lookup("pb")
		if !ok {
			continue
		}
		parts := strings.Split(tag, ",")
		n, err := strconv.ParseUint(parts[0], 10, 32)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("pb: bad tag %q on %s.%s", tag, t.Name(), t.Field(i).Name)
		}
		f := fieldInfo{num: n, index: i}
		for _, p := range parts[1:] {
			if p == "zigzag" {
				f.zigzag = true
			}
		}
		out = append(out, f)
	}
	return out, nil
}

// Marshal encodes a message.
func Marshal(m any) ([]byte, error) {
	v := reflect.ValueOf(m)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	return appendMessage(nil, v)
}

func appendMessage(b []byte, v reflect.Value) ([]byte, error) {
	fs, err := fields(v.Type())
	if err != nil {
		return nil, err
	}
	for _, f := range fs {
		fv := v.Field(f.index)
		if fv.Kind() == reflect.Slice && fv.Type().Elem().Kind() != reflect.Uint8 {
			for i := 0; i < fv.Len(); i++ {
				if b, err = appendField(b, f, fv.Index(i)); err != nil {
					return nil, err
				}
			}
			continue
		}
		if b, err = appendField(b, f, fv); err != nil {
			return nil, err
		}
	}
	return b, nil
}

func appendKey(b []byte, num uint64, wire int) []byte {
	return binary.AppendUvarint(b, num<<3|uint64(wire))
}

func appendField(b []byte, f fieldInfo, v reflect.Value) ([]byte, error) {
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return b, nil
		}
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Bool:
		n := uint64(0)
		if v.Bool() {
			n = 1
		}
		return binary.AppendUvarint(appendKey(b, f.num, wireVarint), n), nil
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return binary.AppendUvarint(appendKey(b, f.num, wireVarint), v.Uint()), nil
	case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n := v.Int()
		if f.zigzag {
			return binary.AppendUvarint(appendKey(b, f.num, wireVarint), uint64(n<<1)^uint64(n>>63)), nil
		}
		return binary.AppendUvarint(appendKey(b, f.num, wireVarint), uint64(n)), nil
	case reflect.String:
		b = binary.AppendUvarint(appendKey(b, f.num, wireBytes), uint64(v.Len()))
		return append(b, v.String()...), nil
	case reflect.Slice: // []byte
		if v.IsNil() {
			return b, nil
		}
		b = binary.AppendUvarint(appendKey(b, f.num, wireBytes), uint64(v.Len()))
		return append(b, v.Bytes()...), nil
	case reflect.Struct:
		inner, err := appendMessage(nil, v)
		if err != nil {
			return nil, err
		}
		b = binary.AppendUvarint(appendKey(b, f.num, wireBytes), uint64(len(inner)))
		return append(b, inner...), nil
	}
	return nil, fmt.Errorf("pb: cannot encode %s", v.Type())
}

// ErrTruncated reports a message cut short.
var ErrTruncated = errors.New("pb: truncated message")

// Unmarshal decodes data into the message m points to. Unknown fields are
// skipped.
func Unmarshal(data []byte, m any) error {
	v := reflect.ValueOf(m)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return errors.New("pb: Unmarshal needs a non-nil pointer")
	}
	return decodeMessage(data, v.Elem(), 0)
}

const maxNesting = 32

func decodeMessage(data []byte, v reflect.Value, depth int) error {
	if depth > maxNesting {
		return errors.New("pb: messages nested too deep")
	}
	fs, err := fields(v.Type())
	if err != nil {
		return err
	}
	byNum := map[uint64]fieldInfo{}
	for _, f := range fs {
		byNum[f.num] = f
	}
	for len(data) > 0 {
		key, n := binary.Uvarint(data)
		if n <= 0 {
			return ErrTruncated
		}
		data = data[n:]
		num, wire := key>>3, int(key&7)
		var raw []byte
		var scalar uint64
		switch wire {
		case wireVarint:
			x, n := binary.Uvarint(data)
			if n <= 0 {
				return ErrTruncated
			}
			scalar, data = x, data[n:]
		case wireBytes:
			l, n := binary.Uvarint(data)
			if n <= 0 || l > uint64(len(data)-n) {
				return ErrTruncated
			}
			raw, data = data[n:n+int(l)], data[n+int(l):]
		case wireI64:
			if len(data) < 8 {
				return ErrTruncated
			}
			scalar, data = binary.LittleEndian.Uint64(data), data[8:]
		case wireI32:
			if len(data) < 4 {
				return ErrTruncated
			}
			scalar, data = uint64(binary.LittleEndian.Uint32(data)), data[4:]
		default:
			return fmt.Errorf("pb: unsupported wire type %d", wire)
		}
		f, ok := byNum[num]
		if !ok {
			continue
		}
		fv := v.Field(f.index)
		if err := setField(fv, f, wire, scalar, raw, depth); err != nil {
			return fmt.Errorf("pb: field %d of %s: %w", num, v.Type().Name(), err)
		}
	}
	return nil
}

func setField(fv reflect.Value, f fieldInfo, wire int, scalar uint64, raw []byte, depth int) error {
	t := fv.Type()
	if t.Kind() == reflect.Slice && t.Elem().Kind() != reflect.Uint8 {
		elem := t.Elem()
		// packed repeated scalars
		if wire == wireBytes && isScalar(elem) {
			for len(raw) > 0 {
				x, n := binary.Uvarint(raw)
				if n <= 0 {
					return ErrTruncated
				}
				raw = raw[n:]
				e := reflect.New(elem).Elem()
				if err := setScalar(e, f, x); err != nil {
					return err
				}
				fv.Set(reflect.Append(fv, e))
			}
			return nil
		}
		e := reflect.New(elem).Elem()
		if err := setField(e, f, wire, scalar, raw, depth); err != nil {
			return err
		}
		fv.Set(reflect.Append(fv, e))
		return nil
	}
	if t.Kind() == reflect.Pointer {
		e := reflect.New(t.Elem())
		if err := setField(e.Elem(), f, wire, scalar, raw, depth); err != nil {
			return err
		}
		fv.Set(e)
		return nil
	}
	switch t.Kind() {
	case reflect.String:
		if wire != wireBytes {
			return errors.New("wrong wire type")
		}
		fv.SetString(string(raw))
	case reflect.Slice:
		if wire != wireBytes {
			return errors.New("wrong wire type")
		}
		fv.SetBytes(append([]byte{}, raw...))
	case reflect.Struct:
		if wire != wireBytes {
			return errors.New("wrong wire type")
		}
		return decodeMessage(raw, fv, depth+1)
	default:
		if wire == wireBytes {
			return errors.New("wrong wire type")
		}
		return setScalar(fv, f, scalar)
	}
	return nil
}

func isScalar(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Bool, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return true
	}
	return false
}

func setScalar(v reflect.Value, f fieldInfo, x uint64) error {
	switch v.Kind() {
	case reflect.Bool:
		v.SetBool(x != 0)
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if v.OverflowUint(x) {
			return fmt.Errorf("value %d overflows %s", x, v.Type())
		}
		v.SetUint(x)
	case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n := int64(x)
		if f.zigzag {
			n = int64(x>>1) ^ -int64(x&1)
		}
		if v.Kind() != reflect.Int64 && (n > math.MaxInt32 || n < math.MinInt32) && !f.zigzag {
			// proto int32 negative values are sign-extended to 64 bits
			n = int64(int32(x))
		}
		if v.OverflowInt(n) {
			return fmt.Errorf("value %d overflows %s", n, v.Type())
		}
		v.SetInt(n)
	default:
		return fmt.Errorf("cannot decode into %s", v.Type())
	}
	return nil
}
