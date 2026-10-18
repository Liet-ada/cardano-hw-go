// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package js

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
)

// ParseJSON is JSON.parse, with the error messages of V8 (Node 22): the
// position, line and column of the problem, or the unexpected character
// with up to ten characters around it.
func ParseJSON(text string) (Value, error) {
	p := &jsonParser{src: utf16.Encode([]rune(text)), text: text}
	p.skip()
	v, err := p.value()
	if err != nil {
		return Value{}, err
	}
	p.skip()
	if p.pos < len(p.src) {
		return Value{}, p.at("Unexpected non-whitespace character after JSON")
	}
	return v, nil
}

type jsonParser struct {
	src  []uint16
	text string
	pos  int
}

func (p *jsonParser) syntax(msg string) error { return &Error{Name: "SyntaxError", Message: msg} }

// at reports a problem at the current position, counting lines as V8
// does: \n, \r and \r\n end one.
func (p *jsonParser) at(what string) error {
	line, start := 1, 0
	for i := 0; i < p.pos; i++ {
		switch p.src[i] {
		case '\r':
			if i+1 < p.pos && p.src[i+1] == '\n' {
				i++
			}
			line, start = line+1, i+1
		case '\n':
			line, start = line+1, i+1
		}
	}
	return p.syntax(fmt.Sprintf("%s at position %d (line %d column %d)", what, p.pos, line, p.pos-start+1))
}

func (p *jsonParser) eos() error { return p.syntax("Unexpected end of JSON input") }

func (p *jsonParser) slice(from, to int) string { return string(utf16.Decode(p.src[from:to])) }

// unexpected reports the character at the current position.
func (p *jsonParser) unexpected() error {
	if p.pos >= len(p.src) {
		return p.eos()
	}
	switch c := p.src[p.pos]; {
	case c == '"':
		return p.at("Unexpected string in JSON")
	case c == '-' || (c >= '0' && c <= '9'):
		return p.at("Unexpected number in JSON")
	}
	switch p.text {
	case "NaN", "Infinity", "undefined", "[object Object]":
		return p.syntax(fmt.Sprintf("%q is not valid JSON", p.text))
	}
	token := p.slice(p.pos, p.pos+1)
	const context = 10
	if len(p.src) < 2*context+1 {
		return p.syntax(fmt.Sprintf("Unexpected token '%s', \"%s\" is not valid JSON", token, p.slice(0, len(p.src))))
	}
	start, end := max(0, p.pos-context), min(len(p.src), p.pos+context)
	pre, post := "", ""
	if start > 0 {
		pre = "..."
	}
	if end < len(p.src) {
		post = "..."
	}
	return p.syntax(fmt.Sprintf("Unexpected token '%s', %s\"%s\"%s is not valid JSON", token, pre, p.slice(start, end), post))
}

func (p *jsonParser) skip() {
	for p.pos < len(p.src) {
		switch p.src[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *jsonParser) peek() int {
	if p.pos >= len(p.src) {
		return -1
	}
	return int(p.src[p.pos])
}

func (p *jsonParser) value() (Value, error) {
	switch c := p.peek(); {
	case c < 0:
		return Value{}, p.eos()
	case c == '"':
		s, err := p.str()
		return Value{Kind: String, Str: s}, err
	case c == '{':
		return p.object()
	case c == '[':
		return p.array()
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	case c == 't':
		return Value{Kind: Bool, Bool: true}, p.literal("true")
	case c == 'f':
		return Value{Kind: Bool}, p.literal("false")
	case c == 'n':
		return Value{Kind: Null}, p.literal("null")
	}
	return Value{}, p.unexpected()
}

func (p *jsonParser) literal(word string) error {
	for i := 0; i < len(word); i++ {
		if p.pos >= len(p.src) {
			return p.eos()
		}
		if p.src[p.pos] != uint16(word[i]) {
			return p.unexpected()
		}
		p.pos++
	}
	return nil
}

func isDigit(c int) bool { return c >= '0' && c <= '9' }

func (p *jsonParser) number() (Value, error) {
	start := p.pos
	if p.peek() == '-' {
		p.pos++
		if !isDigit(p.peek()) {
			return Value{}, p.at("No number after minus sign in JSON")
		}
	}
	if p.peek() == '0' {
		p.pos++
		if isDigit(p.peek()) {
			return Value{}, p.at("Unexpected number in JSON")
		}
	} else {
		for isDigit(p.peek()) {
			p.pos++
		}
	}
	if p.peek() == '.' {
		p.pos++
		if !isDigit(p.peek()) {
			return Value{}, p.at("Unterminated fractional number in JSON")
		}
		for isDigit(p.peek()) {
			p.pos++
		}
	}
	if c := p.peek(); c == 'e' || c == 'E' {
		p.pos++
		if c := p.peek(); c == '+' || c == '-' {
			p.pos++
		}
		if !isDigit(p.peek()) {
			return Value{}, p.at("Exponent part is missing a number in JSON")
		}
		for isDigit(p.peek()) {
			p.pos++
		}
	}
	f, err := strconv.ParseFloat(p.slice(start, p.pos), 64)
	if err != nil && !math.IsInf(f, 0) {
		return Value{}, p.at("Unexpected number in JSON")
	}
	return Value{Kind: Number, Num: f}, nil
}

func (p *jsonParser) str() (string, error) {
	p.pos++ // the opening quote
	var out []uint16
	for {
		c := p.peek()
		switch {
		case c < 0:
			return "", p.at("Unterminated string in JSON")
		case c == '"':
			p.pos++
			return string(utf16.Decode(out)), nil
		case c < 0x20:
			return "", p.at("Bad control character in string literal in JSON")
		case c == '\\':
			p.pos++
			e := p.peek()
			switch e {
			case '"', '\\', '/':
				out = append(out, uint16(e))
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				var r uint16
				for i := 0; i < 4; i++ {
					p.pos++
					d := p.peek()
					var v int
					switch {
					case d >= '0' && d <= '9':
						v = d - '0'
					case d >= 'a' && d <= 'f':
						v = d - 'a' + 10
					case d >= 'A' && d <= 'F':
						v = d - 'A' + 10
					default:
						if d < 0 {
							return "", p.at("Unterminated string in JSON")
						}
						return "", p.at("Bad Unicode escape in JSON")
					}
					r = r<<4 | uint16(v)
				}
				out = append(out, r)
			default:
				if e < 0 {
					return "", p.at("Unterminated string in JSON")
				}
				return "", p.at("Bad escaped character in JSON")
			}
			p.pos++
		default:
			out = append(out, uint16(c))
			p.pos++
		}
	}
}

func (p *jsonParser) object() (Value, error) {
	p.pos++ // {
	v := Value{Kind: Object, Props: map[string]Value{}}
	p.skip()
	if p.peek() == '}' {
		p.pos++
		return v, nil
	}
	if p.peek() != '"' {
		return Value{}, p.at("Expected property name or '}' in JSON")
	}
	for {
		key, err := p.str()
		if err != nil {
			return Value{}, err
		}
		p.skip()
		if p.peek() != ':' {
			return Value{}, p.at("Expected ':' after property name in JSON")
		}
		p.pos++
		p.skip()
		val, err := p.value()
		if err != nil {
			return Value{}, err
		}
		if _, dup := v.Props[key]; !dup {
			v.Keys = append(v.Keys, key)
		}
		v.Props[key] = val
		p.skip()
		switch p.peek() {
		case ',':
			p.pos++
			p.skip()
			if p.peek() != '"' {
				return Value{}, p.at("Expected double-quoted property name in JSON")
			}
		case '}':
			p.pos++
			return v, nil
		default:
			return Value{}, p.at("Expected ',' or '}' after property value in JSON")
		}
	}
}

func (p *jsonParser) array() (Value, error) {
	p.pos++ // [
	v := Value{Kind: Array}
	p.skip()
	if p.peek() == ']' {
		p.pos++
		return v, nil
	}
	for {
		item, err := p.value()
		if err != nil {
			return Value{}, err
		}
		v.Items = append(v.Items, item)
		p.skip()
		switch p.peek() {
		case ',':
			p.pos++
			p.skip()
		case ']':
			p.pos++
			return v, nil
		default:
			return Value{}, p.at("Expected ',' or ']' after array element in JSON")
		}
	}
}

// Quote is JSON.stringify of a string.
func Quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, u := range utf16.Encode([]rune(s)) {
		switch {
		case u == '"' || u == '\\':
			b.WriteByte('\\')
			b.WriteByte(byte(u))
		case u == '\n':
			b.WriteString(`\n`)
		case u == '\r':
			b.WriteString(`\r`)
		case u == '\t':
			b.WriteString(`\t`)
		case u == '\b':
			b.WriteString(`\b`)
		case u == '\f':
			b.WriteString(`\f`)
		case u < 0x20:
			fmt.Fprintf(&b, `\u%04x`, u)
		default:
			b.WriteString(string(utf16.Decode([]uint16{u})))
		}
	}
	b.WriteByte('"')
	return b.String()
}
