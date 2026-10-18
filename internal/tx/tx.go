// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tx

import (
	"fmt"

	"golang.org/x/crypto/blake2b"

	"github.com/Liet-ada/cardano-hw-go/internal/cbor"
)

// MaxTxSize bounds the transactions this package decodes. The ledger allows
// 16 KiB today; the margin covers unsigned drafts and future increases.
const MaxTxSize = 1 << 20

// Decoded is a transaction with the bytes it was decoded from.
type Decoded struct {
	Tx Transaction
	// Raw is the whole transaction and RawBody its body, as given.
	Raw, RawBody []byte
}

// Decode decodes and parses a transaction.
func Decode(data []byte) (*Decoded, error) {
	if len(data) > MaxTxSize {
		return nil, fmt.Errorf("transaction of %d bytes is larger than %d", len(data), MaxTxSize)
	}
	v, err := cbor.Decode(data)
	if err != nil {
		return nil, err
	}
	t, err := ParseTx(v)
	if err != nil {
		return nil, err
	}
	items, err := cbor.ArrayItems(data)
	if err != nil {
		return nil, err
	}
	return &Decoded{Tx: t, Raw: data, RawBody: items[0]}, nil
}

// Encode encodes a transaction canonically.
func Encode(t *Transaction) []byte { return cbor.EncodeCanonical(SerializeTx(t)) }

// EncodeBody encodes a body canonically.
func EncodeBody(b *Body) []byte { return cbor.EncodeCanonical(SerializeBody(b)) }

// BodyHash is the transaction id: the Blake2b-256 hash of the encoded body.
func BodyHash(body []byte) []byte {
	h := blake2b.Sum256(body)
	return h[:]
}

// Validate decodes a transaction and returns its CIP-21 issues.
func Validate(data []byte) ([]ValidationError, error) {
	d, err := Decode(data)
	if err != nil {
		return nil, err
	}
	return validateCommon(data, Encode(&d.Tx), &d.Tx.Body), nil
}

// ValidateBody decodes a transaction body and returns its CIP-21 issues.
func ValidateBody(data []byte) ([]ValidationError, error) {
	v, err := cbor.Decode(data)
	if err != nil {
		return nil, err
	}
	b, err := ParseBody(v)
	if err != nil {
		return nil, err
	}
	return validateCommon(data, EncodeBody(&b), &b), nil
}

// HasVKeyWitnesses reports whether the witness set holds Shelley or Byron
// signatures, which a transformation would invalidate.
func HasVKeyWitnesses(t *Transaction) bool {
	for _, k := range []uint64{WitnessVKey, WitnessBootstrap} {
		if w, ok := t.WitnessSet.Get(k); ok {
			if c := setItems(w); len(c) > 0 {
				return true
			}
		}
	}
	return false
}

// setItems returns the items of an array, tagged 258 or not.
func setItems(v cbor.Value) []cbor.Value {
	if v.Kind == cbor.Tag && v.Uint == cbor.TagSet {
		v = v.Content()
	}
	if v.Kind == cbor.Array {
		return v.Items
	}
	return nil
}
