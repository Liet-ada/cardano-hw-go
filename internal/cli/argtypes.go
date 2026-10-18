// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cli

import (
	"errors"
	"math/big"
	"strings"

	"github.com/Liet-ada/cardano-hw-go/internal/cardano"
	"github.com/Liet-ada/cardano-hw-go/internal/cbor"
	"github.com/Liet-ada/cardano-hw-go/internal/hw"
	"github.com/Liet-ada/cardano-hw-go/internal/js"
)

// The type functions cardano-hw-cli gives argparse, which read and check
// option values while the command line is parsed. A JavaScript TypeError
// makes argparse report an invalid value; other errors stop the program.

func convPath(s string) error {
	_, err := cardano.ParsePath(s)
	return err
}

func convTxFile(s string) error {
	_, err := cardano.ReadTxFile(s)
	return err
}

func convSigningFile(s string) error {
	_, err := cardano.ReadSigningFile(s)
	return err
}

func convNativeScript(s string) error {
	_, err := cardano.ReadNativeScriptFile(s)
	return err
}

func convAddressFile(s string) error {
	_, err := readAddressFile(s)
	return err
}

func convScriptHash(s string) error {
	_, err := parseScriptHash(s)
	return err
}

func convKESVKey(s string) error {
	_, err := readKesVKey(s)
	return err
}

func convVoteKeyJcli(s string) error {
	_, err := voteKeyJcli(s)
	return err
}

func convVoteKeyString(s string) error {
	_, err := voteKeyBech32(s)
	return err
}

func convVoteKeyHwsfile(s string) error {
	_, err := voteKeyHwsfile(s)
	return err
}

func convVoteKeyFile(s string) error {
	_, err := voteKeyFile(s)
	return err
}

func convBigInt(s string) error {
	_, err := jsBigInt(s)
	return err
}

func convMessage(s string) error {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7f {
			return errInvalidMessage
		}
	}
	return nil
}

// convDerivationType is parseDerivationType: no value, or a name of the
// DerivationType enum (where "in" also finds what every object has).
func convDerivationType(s string) error {
	if s == "" {
		return nil
	}
	if _, err := hw.ParseDerivationType(s); err != nil && !objectPrototypeName[s] {
		return err
	}
	return nil
}

// objectPrototypeName are the properties of Object.prototype, which the
// "in" operator finds on any object.
var objectPrototypeName = map[string]bool{
	"constructor": true, "__defineGetter__": true, "__defineSetter__": true, "hasOwnProperty": true,
	"__lookupGetter__": true, "__lookupSetter__": true, "isPrototypeOf": true, "propertyIsEnumerable": true,
	"toString": true, "valueOf": true, "__proto__": true, "toLocaleString": true,
}

// convProtocolParams is parseProtocolParamsFile: the file needs an object
// of cost models; what they hold is checked when they are used.
func convProtocolParams(s string) error {
	text, err := js.ReadFile(s)
	if err != nil {
		return err
	}
	v, err := js.ParseJSON(text)
	if err != nil {
		return err
	}
	if v.Nullish() {
		return js.NewTypeError("Cannot read properties of " + v.Name() + " (reading 'costModels')")
	}
	if m := v.Get("costModels"); m.Kind != js.Object && m.Kind != js.Array {
		return errors.New(`Invalid protocol params file: expected a protocol parameters JSON with a "costModels" field.`)
	}
	return nil
}

// jsBigInt is BigInt(s) for a string: decimal with an optional sign, or
// hexadecimal, octal or binary, around whitespace; an empty string is 0.
func jsBigInt(s string) (*big.Int, error) {
	fail := &js.Error{Name: "SyntaxError", Message: "Cannot convert " + s + " to a BigInt"}
	t := strings.Trim(s, jsWhitespace)
	if t == "" {
		return new(big.Int), nil
	}
	base, digits := 10, t
	if len(t) > 2 && t[0] == '0' {
		switch t[1] {
		case 'x', 'X':
			base, digits = 16, t[2:]
		case 'o', 'O':
			base, digits = 8, t[2:]
		case 'b', 'B':
			base, digits = 2, t[2:]
		}
	}
	neg := false
	if base == 10 && (digits[0] == '+' || digits[0] == '-') {
		neg, digits = digits[0] == '-', digits[1:]
	}
	if digits == "" {
		return nil, fail
	}
	for _, c := range digits {
		d := base
		switch {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case c|0x20 >= 'a' && c|0x20 <= 'f':
			d = int(c|0x20-'a') + 10
		}
		if d >= base {
			return nil, fail
		}
	}
	n, ok := new(big.Int).SetString(digits, base)
	if !ok {
		return nil, fail
	}
	if neg {
		n.Neg(n)
	}
	return n, nil
}

// readAddressFile is parseAddressFile: the trimmed text of the file.
func readAddressFile(path string) (string, error) {
	text, err := js.ReadFile(path)
	if err != nil {
		return "", err
	}
	return jsTrim(text), nil
}

// jsWhitespace is what String.prototype.trim removes.
const jsWhitespace = " \t\n\v\f\r\u00a0\ufeff\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"

// jsTrim is String.prototype.trim.
func jsTrim(s string) string { return strings.Trim(s, jsWhitespace) }

// readKesVKey is parseKesVKeyFile: a CBOR byte string of 32 bytes.
func readKesVKey(path string) ([]byte, error) {
	text, err := js.ReadFile(path)
	if err != nil {
		return nil, err
	}
	v, err := js.ParseJSON(text)
	if err != nil {
		return nil, err
	}
	if v.Nullish() {
		return nil, js.NewTypeError("Cannot destructure property 'type' of 'data' as it is " + v.Name() + ".")
	}
	if h := v.Get("cborHex"); h.Kind == js.String {
		if b := js.BufferFromHex(h.Str); cbor.WellFormed(b) == nil {
			if d, err := cbor.Decode(b); err == nil && d.Kind == cbor.Bytes && len(d.Bytes) == 32 {
				return d.Bytes, nil
			}
		}
	}
	return nil, errInvalidKesVKeyFile
}

// voteKeyBech32 is parseVotePubKeyBech32: a bech32 key of 32 bytes.
func voteKeyBech32(s string) ([]byte, error) {
	_, b, err := cardano.Bech32Decode(s)
	if err != nil || len(b) != 32 {
		return nil, errInvalidCVotePublicKey
	}
	return b, nil
}

// voteKeyJcli is parseVotePubFileJcli: a bech32 key in a text file.
func voteKeyJcli(path string) ([]byte, error) {
	text, err := js.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return voteKeyBech32(jsTrim(text))
}

func readJSONFile(path string) (js.Value, error) {
	text, err := js.ReadFile(path)
	if err != nil {
		return js.Value{}, err
	}
	return js.ParseJSON(text)
}

// voteXPubKey is tryToExtractVoteXPubKey: the public key of an extended
// key in CBOR.
func voteXPubKey(v js.Value) ([]byte, error) {
	if v.Kind == js.String && len(v.Str) == 2*(2+64) {
		if pub, _, err := cardano.SplitXPubCBORHex(v.Str); err == nil && len(pub) == 32 {
			return pub, nil
		}
	}
	return nil, errInvalidCVotePublicKey
}

// voteKeyHwsfile is parseVotePubFileHw: the key of a CIP-36 vote key
// signing file.
func voteKeyHwsfile(path string) ([]byte, error) {
	v, err := readJSONFile(path)
	if err != nil {
		return nil, err
	}
	if v.Nullish() {
		return nil, js.NewTypeError("Cannot destructure property 'type' of 'data' as it is " + v.Name() + ".")
	}
	if t := v.Get("type"); t.Kind == js.String && t.Str == cardano.SigningFileType(cardano.LabelCIP36Vote, cardano.PathCVoteKey) {
		return voteXPubKey(v.Get("cborXPubKeyHex"))
	}
	return nil, errInvalidCVotePublicKey
}

// voteKeyFile is parseVotePubFileCli: a vote verification key file, with
// the key or an extended key.
func voteKeyFile(path string) ([]byte, error) {
	v, err := readJSONFile(path)
	if err != nil {
		return nil, err
	}
	if v.Nullish() {
		return nil, js.NewTypeError("Cannot destructure property 'type' of 'data' as it is " + v.Name() + ".")
	}
	if t := v.Get("type"); t.Kind != js.String || t.Str != cardano.LabelCIP36Vote+"VerificationKey_ed25519" {
		return nil, errInvalidCVotePublicKey
	}
	h := v.Get("cborHex")
	if h.Kind == js.String && len(h.Str) == 2*(2+32) {
		d, err := cbor.Decode(js.BufferFromHex(h.Str))
		if err != nil {
			return nil, errors.New("Insufficient data")
		}
		if d.Kind == cbor.Bytes && len(d.Bytes) == 32 {
			return d.Bytes, nil
		}
	}
	return voteXPubKey(h)
}
