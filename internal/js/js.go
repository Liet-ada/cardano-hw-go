// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package js reproduces how Node.js reads files and parses JSON, error
// messages included, and the little of JavaScript's values that reading
// cardano-hw-cli's files needs. With it cardano-hw-go fails on a missing
// or malformed file with the message cardano-hw-cli gives.
package js

import (
	"errors"
	"io"
	"io/fs"
	"math"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf16"
)

// Error is a JavaScript error: Message is what cardano-hw-cli prints.
type Error struct {
	Name    string // Error, TypeError, SyntaxError, RangeError
	Message string
}

func (e *Error) Error() string { return e.Message }

// NewTypeError is a TypeError.
func NewTypeError(msg string) *Error { return &Error{Name: "TypeError", Message: msg} }

// IsTypeError reports whether err is a JavaScript TypeError, which
// argparse turns into an "invalid type value" error.
func IsTypeError(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Name == "TypeError"
}

// Kind is the type of a value.
type Kind int

const (
	Undefined Kind = iota
	Null
	Bool
	Number
	String
	Array
	Object
)

// Value is a JavaScript value as JSON.parse makes them.
type Value struct {
	Kind  Kind
	Bool  bool
	Num   float64
	Str   string
	Items []Value
	// Keys keeps the order of an object's properties.
	Keys  []string
	Props map[string]Value
}

// Get reads a property; it is undefined if missing. On null or undefined
// JavaScript throws instead: check Nullish first.
func (v Value) Get(key string) Value {
	switch v.Kind {
	case Object:
		return v.Props[key]
	case Array:
		if key == "length" {
			return Value{Kind: Number, Num: float64(len(v.Items))}
		}
		if i, err := strconv.Atoi(key); err == nil && i >= 0 && i < len(v.Items) && strconv.Itoa(i) == key {
			return v.Items[i]
		}
	case String:
		if key == "length" {
			return Value{Kind: Number, Num: float64(len(utf16.Encode([]rune(v.Str))))}
		}
	}
	return Value{}
}

// Has is the "in" operator for objects.
func (v Value) Has(key string) bool {
	_, ok := v.Props[key]
	return v.Kind == Object && ok
}

// Nullish reports null or undefined.
func (v Value) Nullish() bool { return v.Kind == Undefined || v.Kind == Null }

// Name is how JavaScript names null and undefined in its messages.
func (v Value) Name() string {
	if v.Kind == Null {
		return "null"
	}
	return "undefined"
}

// ToString is String(v) for the values JSON gives.
func (v Value) ToString() string {
	switch v.Kind {
	case Undefined:
		return "undefined"
	case Null:
		return "null"
	case Bool:
		return strconv.FormatBool(v.Bool)
	case Number:
		return NumberToString(v.Num)
	case String:
		return v.Str
	case Array:
		parts := make([]string, len(v.Items))
		for i, x := range v.Items {
			if !x.Nullish() {
				parts[i] = x.ToString()
			}
		}
		return strings.Join(parts, ",")
	}
	return "[object Object]"
}

// NumberToString is JavaScript's conversion of a number to a string, for
// the integers and simple fractions files hold.
func NumberToString(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	case f == 0:
		return "0"
	}
	a := math.Abs(f)
	if a >= 1e21 || a < 1e-6 {
		s := strconv.FormatFloat(f, 'e', -1, 64)
		mant, exp, _ := strings.Cut(s, "e")
		if exp[0] == '+' {
			exp = exp[1:]
		} else {
			exp = "-" + strings.TrimLeft(exp[1:], "0")
		}
		exp = strings.TrimLeft(exp, "0")
		if exp == "" || exp == "-" {
			exp += "0"
		}
		sign := "+"
		if strings.HasPrefix(exp, "-") {
			sign = ""
		}
		return mant + "e" + sign + exp
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// IsInteger is Number.isInteger.
func (v Value) IsInteger() bool {
	return v.Kind == Number && !math.IsInf(v.Num, 0) && v.Num == math.Trunc(v.Num)
}

// ParseInt is parseInt(s, 10): the leading integer of s, NaN if none.
func ParseInt(s string) float64 {
	s = strings.TrimLeft(s, " \t\n\v\f\r\u00a0\ufeff\u2028\u2029")
	neg := false
	if s != "" && (s[0] == '-' || s[0] == '+') {
		neg = s[0] == '-'
		s = s[1:]
	}
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return math.NaN()
	}
	f, _ := strconv.ParseFloat(s[:end], 64)
	if neg {
		f = -f
	}
	return f
}

// DecodeUTF8 decodes bytes as Node's Buffer does, with the replacement
// character for each maximal invalid subsequence (the WHATWG decoder).
func DecodeUTF8(b []byte) string {
	var out strings.Builder
	i := 0
	for i < len(b) {
		c := b[i]
		if c < 0x80 {
			out.WriteByte(c)
			i++
			continue
		}
		var need int
		var cp rune
		lower, upper := byte(0x80), byte(0xbf)
		switch {
		case c >= 0xc2 && c <= 0xdf:
			need, cp = 1, rune(c&0x1f)
		case c >= 0xe0 && c <= 0xef:
			need, cp = 2, rune(c&0x0f)
			if c == 0xe0 {
				lower = 0xa0
			}
			if c == 0xed {
				upper = 0x9f
			}
		case c >= 0xf0 && c <= 0xf4:
			need, cp = 3, rune(c&0x07)
			if c == 0xf0 {
				lower = 0x90
			}
			if c == 0xf4 {
				upper = 0x8f
			}
		default:
			out.WriteRune('�')
			i++
			continue
		}
		j := i + 1
		ok := true
		for k := 0; k < need; k++ {
			if j >= len(b) || b[j] < lower || b[j] > upper {
				ok = false
				break
			}
			cp = cp<<6 | rune(b[j]&0x3f)
			lower, upper = 0x80, 0xbf
			j++
		}
		if !ok {
			out.WriteRune('�')
			i = j
			continue
		}
		out.WriteRune(cp)
		i = j
	}
	return out.String()
}

// BufferFromHex is Buffer.from(s, 'hex'): it stops at the first pair that
// is not hex.
func BufferFromHex(s string) []byte {
	var out []byte
	for i := 0; i+1 < len(s); i += 2 {
		hi, ok1 := hexDigit(s[i])
		lo, ok2 := hexDigit(s[i+1])
		if !ok1 || !ok2 {
			break
		}
		out = append(out, hi<<4|lo)
	}
	return out
}

func hexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// The descriptions libuv gives the errors Node reports.
var errnoText = map[syscall.Errno][2]string{
	syscall.ENOENT:       {"ENOENT", "no such file or directory"},
	syscall.EACCES:       {"EACCES", "permission denied"},
	syscall.EPERM:        {"EPERM", "operation not permitted"},
	syscall.EISDIR:       {"EISDIR", "illegal operation on a directory"},
	syscall.ENOTDIR:      {"ENOTDIR", "not a directory"},
	syscall.ELOOP:        {"ELOOP", "too many symbolic links encountered"},
	syscall.ENAMETOOLONG: {"ENAMETOOLONG", "name too long"},
	syscall.EMFILE:       {"EMFILE", "too many open files"},
	syscall.EIO:          {"EIO", "i/o error"},
	syscall.ENXIO:        {"ENXIO", "no such device or address"},
	syscall.EBUSY:        {"EBUSY", "resource busy or locked"},
}

// nodeError writes a file system error as Node does:
// "ENOENT: no such file or directory, stat 'file'".
func nodeError(err error, syscallName, path string) error {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return &Error{Name: "Error", Message: err.Error()}
	}
	t, ok := errnoText[errno]
	if !ok {
		t = [2]string{"E" + strings.ToUpper(strings.ReplaceAll(errno.Error(), " ", "")), errno.Error()}
	}
	msg := t[0] + ": " + t[1] + ", " + syscallName
	if path != "" || syscallName != "read" {
		msg += " " + "'" + path + "'"
	}
	return &Error{Name: "Error", Message: msg}
}

// ReadFile reads a file as text, as cardano-hw-cli does with the rw
// package: it stats the file first, then reads it whole, or as a stream if
// it is not a regular file.
func ReadFile(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", nodeError(err, "stat", path)
	}
	if st.Mode().IsRegular() {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", nodeError(err, "open", path)
		}
		return DecodeUTF8(b), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return "", nodeError(err, "open", path)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return "", nodeError(err, "read", "")
	}
	return DecodeUTF8(b), nil
}
