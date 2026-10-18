// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cardano

import (
	"errors"

	"golang.org/x/crypto/blake2b"

	"github.com/Liet-ada/cardano-hw-go/internal/cbor"
	"github.com/Liet-ada/cardano-hw-go/internal/js"
)

// NativeScriptType is the type of a native script.
type NativeScriptType int

const (
	ScriptPubKey NativeScriptType = iota
	ScriptAll
	ScriptAny
	ScriptNOfK
	ScriptInvalidBefore
	ScriptInvalidHereafter
)

// NativeScript is a native (timelock and multisig) script.
type NativeScript struct {
	Type     NativeScriptType
	KeyHash  []byte
	Required uint64
	Scripts  []NativeScript
	Slot     uint64
}

// ErrInvalidNativeScriptFile is cardano-hw-cli's error.
var ErrInvalidNativeScriptFile = errors.New("Invalid native script file")

var scriptTypes = map[string]NativeScriptType{
	"sig": ScriptPubKey, "all": ScriptAll, "any": ScriptAny,
	"atLeast": ScriptNOfK, "after": ScriptInvalidBefore, "before": ScriptInvalidHereafter,
}

// ReadNativeScriptFile reads a native script in cardano-cli's JSON format,
// as cardano-hw-cli's parseNativeScriptFile does. A key hash is any
// string that is not empty, read as Buffer.from does.
func ReadNativeScriptFile(path string) (NativeScript, error) {
	v, err := readJSON(path)
	if err != nil {
		return NativeScript{}, err
	}
	return parseNativeScript(v)
}

// objectPrototype are the names "in" also finds on any object.
var objectPrototype = map[string]bool{
	"constructor": true, "__defineGetter__": true, "__defineSetter__": true, "hasOwnProperty": true,
	"__lookupGetter__": true, "__lookupSetter__": true, "isPrototypeOf": true, "propertyIsEnumerable": true,
	"toString": true, "valueOf": true, "__proto__": true, "toLocaleString": true,
}

// ErrUnreachable is cardano-hw-cli's error for a case it does not expect.
var ErrUnreachable = errors.New("Unreachable code reached")

func parseNativeScript(v js.Value) (NativeScript, error) {
	if v.Kind != js.Object || !v.Has("type") || v.Get("type").Kind != js.String {
		return NativeScript{}, ErrInvalidNativeScriptFile
	}
	ts := v.Get("type").Str
	t, ok := scriptTypes[ts]
	switch {
	case objectPrototype[ts]:
		return NativeScript{}, ErrUnreachable
	case !ok:
		return NativeScript{}, ErrInvalidNativeScriptFile
	}
	// a number in the range of safe integers, as isCorrectNumber
	number := func(key string) (js.Value, bool) {
		n := v.Get(key)
		return n, v.Has(key) && n.Kind == js.Number && n.Num >= 0 && n.Num <= 1<<53-1
	}
	s := NativeScript{Type: t}
	scripts := func() error {
		list := v.Get("scripts")
		if !v.Has("scripts") || list.Kind != js.Array {
			return ErrInvalidNativeScriptFile
		}
		for _, item := range list.Items {
			sub, err := parseNativeScript(item)
			if err != nil {
				return err
			}
			s.Scripts = append(s.Scripts, sub)
		}
		return nil
	}
	switch t {
	case ScriptPubKey:
		h := v.Get("keyHash")
		if !v.Has("keyHash") || h.Kind != js.String || h.Str == "" {
			return NativeScript{}, ErrInvalidNativeScriptFile
		}
		s.KeyHash = js.BufferFromHex(h.Str)
	case ScriptAll, ScriptAny:
		if err := scripts(); err != nil {
			return NativeScript{}, err
		}
	case ScriptNOfK:
		// an integer (cardano-hw-cli defect native-script-fractional-required)
		n, ok := number("required")
		if !ok || !n.IsInteger() {
			return NativeScript{}, ErrInvalidNativeScriptFile
		}
		s.Required = uint64(n.Num)
		if err := scripts(); err != nil {
			return NativeScript{}, err
		}
	case ScriptInvalidBefore, ScriptInvalidHereafter:
		// an integer (cardano-hw-cli defect native-script-fractional-slot)
		n, ok := number("slot")
		if !ok || !n.IsInteger() {
			return NativeScript{}, ErrInvalidNativeScriptFile
		}
		s.Slot = uint64(n.Num)
	}
	return s, nil
}

// CBOR returns the script as the ledger encodes it.
func (s NativeScript) CBOR() cbor.Value {
	t := cbor.NewUint(uint64(s.Type))
	sub := func() cbor.Value {
		items := make([]cbor.Value, len(s.Scripts))
		for i, x := range s.Scripts {
			items[i] = x.CBOR()
		}
		return cbor.NewArray(items...)
	}
	switch s.Type {
	case ScriptPubKey:
		return cbor.NewArray(t, cbor.NewBytes(s.KeyHash))
	case ScriptAll, ScriptAny:
		return cbor.NewArray(t, sub())
	case ScriptNOfK:
		return cbor.NewArray(t, cbor.NewUint(s.Required), sub())
	}
	return cbor.NewArray(t, cbor.NewUint(s.Slot))
}

// Hash is the script hash (policy id): Blake2b-224 of a zero byte and the
// script's CBOR.
func (s NativeScript) Hash() []byte {
	h, _ := blake2b.New(28, nil)
	h.Write([]byte{0})
	h.Write(cbor.Encode(s.CBOR()))
	return h.Sum(nil)
}
