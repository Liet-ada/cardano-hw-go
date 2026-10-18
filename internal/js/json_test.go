// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package js

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestParseJSONMessages(t *testing.T) {
	for _, c := range []struct{ in, msg string }{
		{"", "Unexpected end of JSON input"},
		{"xyz", `Unexpected token 'x', "xyz" is not valid JSON`},
		{`{"a":1} x`, "Unexpected non-whitespace character after JSON at position 8 (line 1 column 9)"},
		{"{a:1}", "Expected property name or '}' in JSON at position 1 (line 1 column 2)"},
		{`{"a" 1}`, "Expected ':' after property name in JSON at position 5 (line 1 column 6)"},
		{`{"a":1 "b":2}`, "Expected ',' or '}' after property value in JSON at position 7 (line 1 column 8)"},
		{"[1 2]", "Expected ',' or ']' after array element in JSON at position 3 (line 1 column 4)"},
		{"{\"a\":\"x\n\"}", "Bad control character in string literal in JSON at position 7 (line 1 column 8)"},
		{`{"a":"x`, "Unterminated string in JSON at position 7 (line 1 column 8)"},
		{"undefined", `"undefined" is not valid JSON`},
		{"tru", "Unexpected end of JSON input"},
		{"[1,]", `Unexpected token ']', "[1,]" is not valid JSON`},
		{`{"a":1,}`, "Expected double-quoted property name in JSON at position 7 (line 1 column 8)"},
		{"01", "Unexpected number in JSON at position 1 (line 1 column 2)"},
		{"1.", "Unterminated fractional number in JSON at position 2 (line 1 column 3)"},
		{"-", "No number after minus sign in JSON at position 1 (line 1 column 2)"},
		{`"\u12"`, "Bad Unicode escape in JSON at position 5 (line 1 column 6)"},
		{`{"a":"\x"}`, "Bad escaped character in JSON at position 7 (line 1 column 8)"},
		{"1e+", "Exponent part is missing a number in JSON at position 3 (line 1 column 4)"},
		{"\n\n  {\n \"a\" 1}", "Expected ':' after property name in JSON at position 11 (line 4 column 6)"},
		{`{"aaaaaaaaaaaaaaaaaaaa":x}`, `Unexpected token 'x', ..."aaaaaaaa":x}" is not valid JSON`},
		{"xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", `Unexpected token 'x', "xaaaaaaaaa"... is not valid JSON`},
		{"\ufeff{}", "Unexpected token '\ufeff', \"\ufeff{}\" is not valid JSON"},
	} {
		_, err := ParseJSON(c.in)
		got := "OK"
		if err != nil {
			got = err.Error()
		}
		if got != c.msg {
			t.Errorf("%q: got %q, want %q", c.in, got, c.msg)
		}
	}
}

// TestParseJSONAgainstNode compares with what Node 22 said about
// malformed texts: those in testdata, or in JS_JSON_CASES (lines of
// {input, message}).
func TestParseJSONAgainstNode(t *testing.T) {
	path := os.Getenv("JS_JSON_CASES")
	if path == "" {
		path = "testdata/node-json.jsonl"
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	n, bad := 0, 0
	for sc.Scan() {
		var c struct{ Input, Message string }
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		n++
		_, err := ParseJSON(c.Input)
		got := "OK"
		if err != nil {
			got = err.Error()
		}
		if got != c.Message {
			bad++
			if bad <= 20 {
				t.Errorf("%q: got %q, want %q", c.Input, got, c.Message)
			}
		}
	}
	t.Logf("%d cases, %d differ", n, bad)
}

// TestDecodeUTF8AgainstNode compares with Buffer#toString('utf8').
func TestDecodeUTF8AgainstNode(t *testing.T) {
	f, err := os.Open("testdata/node-utf8.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var c struct {
			Hex string
			Cps []rune
		}
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		b, _ := hex.DecodeString(c.Hex)
		if got := []rune(DecodeUTF8(b)); string(got) != string(c.Cps) {
			t.Errorf("%s: got %U, want %U", c.Hex, got, c.Cps)
		}
	}
}
