// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tx

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/Liet-ada/cardano-hw-go/internal/cbor"
)

// TestGenerateCorpus writes mutated transactions for differential testing
// against cardano-hw-cli. It only runs with TX_CORPUS_IN (a directory of
// transaction envelopes) and TX_CORPUS_OUT set.
func TestGenerateCorpus(t *testing.T) {
	in, out := os.Getenv("TX_CORPUS_IN"), os.Getenv("TX_CORPUS_OUT")
	if in == "" || out == "" {
		t.Skip("TX_CORPUS_IN and TX_CORPUS_OUT not set")
	}
	files, err := filepath.Glob(filepath.Join(in, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(1))
	n := 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var env struct{ CBORHex string }
		if err := json.Unmarshal(data, &env); err != nil {
			t.Fatal(err)
		}
		raw, _ := hex.DecodeString(env.CBORHex)
		v, err := cbor.Decode(raw)
		if err != nil {
			continue
		}
		if _, err := ParseTx(v); err != nil {
			continue
		}
		for i, m := range mutations {
			for k := 0; k < 3; k++ {
				w, ok := m(rng, clone(v))
				if !ok {
					break
				}
				enc := cbor.EncodeCanonical(w)
				if k > 0 {
					enc = noncanonical(rng, w)
				}
				n++
				name := filepath.Join(out, fmt.Sprintf("%05d-m%02d-%s", n, i, filepath.Base(f)))
				body, _ := json.Marshal(map[string]string{"type": "Unwitnessed Tx ConwayEra", "description": "", "cborHex": hex.EncodeToString(enc)})
				if err := os.WriteFile(name, body, 0o644); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	t.Logf("%d files", n)
}

func clone(v cbor.Value) cbor.Value {
	w := v
	if v.Bytes != nil {
		w.Bytes = append([]byte{}, v.Bytes...)
	}
	if v.Items != nil {
		w.Items = make([]cbor.Value, len(v.Items))
		for i := range v.Items {
			w.Items[i] = clone(v.Items[i])
		}
	}
	if v.Entries != nil {
		w.Entries = make([]cbor.Entry, len(v.Entries))
		for i, e := range v.Entries {
			w.Entries[i] = cbor.Entry{Key: clone(e.Key), Value: clone(e.Value)}
		}
	}
	return w
}

func body(v *cbor.Value) *cbor.Value { return &v.Items[0] }

func setKey(m *cbor.Value, k uint64, val cbor.Value) {
	for i := range m.Entries {
		if m.Entries[i].Key.Kind == cbor.Uint && m.Entries[i].Key.Uint == k {
			m.Entries[i].Value = val
			return
		}
	}
	m.Entries = append(m.Entries, cbor.Entry{Key: cbor.NewUint(k), Value: val})
}

func bytesOf(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func cred(b byte) cbor.Value { return cbor.NewArray(cbor.NewUint(0), cbor.NewBytes(bytesOf(28, b))) }

var mutations = []func(*rand.Rand, cbor.Value) (cbor.Value, bool){
	// unchanged
	func(r *rand.Rand, v cbor.Value) (cbor.Value, bool) { return v, true },
	// empty withdrawals
	func(r *rand.Rand, v cbor.Value) (cbor.Value, bool) {
		setKey(body(&v), keyWithdrawals, cbor.NewMap())
		return v, true
	},
	// first output's amount as a tuple with an empty multiasset
	func(r *rand.Rand, v cbor.Value) (cbor.Value, bool) {
		outs, _ := body(&v).Get(keyOutputs)
		if len(outs.Items) == 0 {
			return v, false
		}
		o := outs.Items[0]
		coin := cbor.NewUint(1000000)
		amt := cbor.NewArray(coin, cbor.NewMap())
		if o.Kind == cbor.Array {
			o.Items[1] = amt
		} else {
			setKey(&o, outKeyAmount, amt)
		}
		outs.Items[0] = o
		setKey(body(&v), keyOutputs, outs)
		return v, true
	},
	// an empty token map under a policy
	func(r *rand.Rand, v cbor.Value) (cbor.Value, bool) {
		outs, _ := body(&v).Get(keyOutputs)
		if len(outs.Items) == 0 {
			return v, false
		}
		ma := cbor.NewMap(cbor.Entry{Key: cbor.NewBytes(bytesOf(28, 7)), Value: cbor.NewMap()})
		o := outs.Items[0]
		amt := cbor.NewArray(cbor.NewUint(2000000), ma)
		if o.Kind == cbor.Array {
			o.Items[1] = amt
		} else {
			setKey(&o, outKeyAmount, amt)
		}
		outs.Items[0] = o
		return v, true
	},
	// a 258 tag on the inputs only
	func(r *rand.Rand, v cbor.Value) (cbor.Value, bool) {
		b := body(&v)
		in, _ := b.Get(keyInputs)
		if in.Kind == cbor.Tag {
			setKey(b, keyInputs, in.Content())
		} else {
			setKey(b, keyInputs, cbor.NewTag(cbor.TagSet, in))
		}
		setKey(b, keyRequiredSigners, cbor.NewArray(cbor.NewBytes(bytesOf(28, 3))))
		return v, true
	},
	// update proposal
	func(r *rand.Rand, v cbor.Value) (cbor.Value, bool) {
		setKey(body(&v), keyUpdate, cbor.NewArray(cbor.NewMap(), cbor.NewUint(1)))
		return v, true
	},
	// fee beyond uint64, and a huge ttl
	func(r *rand.Rand, v cbor.Value) (cbor.Value, bool) {
		setKey(body(&v), keyFee, cbor.NewTag(cbor.TagPosBignum, cbor.NewBytes(append([]byte{1}, bytesOf(8, 0)...))))
		setKey(body(&v), keyTTL, cbor.NewUint(1<<63))
		return v, true
	},
	// Babbage output with an empty inline datum and reference script
	func(r *rand.Rand, v cbor.Value) (cbor.Value, bool) {
		outs, _ := body(&v).Get(keyOutputs)
		addr := cbor.NewBytes(append([]byte{0x61}, bytesOf(28, 9)...))
		o := cbor.NewMap(
			cbor.Entry{Key: cbor.NewUint(0), Value: addr},
			cbor.Entry{Key: cbor.NewUint(1), Value: cbor.NewUint(1500000)},
			cbor.Entry{Key: cbor.NewUint(2), Value: cbor.NewArray(cbor.NewUint(1), cbor.NewTag(24, cbor.NewBytes(nil)))},
			cbor.Entry{Key: cbor.NewUint(3), Value: cbor.NewTag(24, cbor.NewBytes(nil))},
		)
		outs.Items = append(outs.Items, o)
		setKey(body(&v), keyOutputs, outs)
		return v, true
	},
	// collateral return with a datum hash and total collateral
	func(r *rand.Rand, v cbor.Value) (cbor.Value, bool) {
		addr := cbor.NewBytes(append([]byte{0x61}, bytesOf(28, 9)...))
		o := cbor.NewMap(
			cbor.Entry{Key: cbor.NewUint(0), Value: addr},
			cbor.Entry{Key: cbor.NewUint(1), Value: cbor.NewUint(1500000)},
			cbor.Entry{Key: cbor.NewUint(2), Value: cbor.NewArray(cbor.NewUint(0), cbor.NewBytes(bytesOf(32, 1)))},
		)
		setKey(body(&v), keyCollateralReturn, o)
		setKey(body(&v), keyTotalCollateral, cbor.NewUint(5000000))
		return v, true
	},
	// two voters with two votes each
	func(r *rand.Rand, v cbor.Value) (cbor.Value, bool) {
		vote := func(b byte) cbor.Entry {
			return cbor.Entry{Key: cbor.NewArray(cbor.NewBytes(bytesOf(32, b)), cbor.NewUint(0)), Value: cbor.NewArray(cbor.NewUint(1), cbor.Null)}
		}
		vp := cbor.NewMap(
			cbor.Entry{Key: cbor.NewArray(cbor.NewUint(2), cbor.NewBytes(bytesOf(28, 1))), Value: cbor.NewMap(vote(1), vote(2))},
			cbor.Entry{Key: cbor.NewArray(cbor.NewUint(4), cbor.NewBytes(bytesOf(28, 2))), Value: cbor.NewMap(vote(3))},
		)
		setKey(body(&v), keyVotingProcedures, vp)
		return v, true
	},
	// pool registration with a withdrawal and another certificate
	func(r *rand.Rand, v cbor.Value) (cbor.Value, bool) {
		reg := cbor.NewArray(cbor.NewUint(3), cbor.NewBytes(bytesOf(28, 1)), cbor.NewBytes(bytesOf(32, 2)),
			cbor.NewUint(1000), cbor.NewUint(340000000), cbor.NewTag(30, cbor.NewArray(cbor.NewUint(1), cbor.NewUint(100))),
			cbor.NewBytes(append([]byte{0xe1}, bytesOf(28, 3)...)), cbor.NewArray(cbor.NewBytes(bytesOf(28, 4))),
			cbor.NewArray(cbor.NewArray(cbor.NewUint(0), cbor.NewUint(3001), cbor.NewBytes([]byte{1, 2, 3, 4}), cbor.Null)),
			cbor.NewArray(cbor.NewText("https://example.com/p.json"), cbor.NewBytes(bytesOf(32, 5))))
		setKey(body(&v), keyCertificates, cbor.NewArray(reg, cbor.NewArray(cbor.NewUint(0), cred(9))))
		setKey(body(&v), keyWithdrawals, cbor.NewMap(cbor.Entry{Key: cbor.NewBytes(append([]byte{0xe1}, bytesOf(28, 3)...)), Value: cbor.NewUint(5)}))
		return v, true
	},
	// Conway certificates hardware wallets refuse, and governance ones
	func(r *rand.Rand, v cbor.Value) (cbor.Value, bool) {
		drep := cbor.NewArray(cbor.NewUint(2))
		certs := cbor.NewArray(
			cbor.NewArray(cbor.NewUint(10), cred(1), cbor.NewBytes(bytesOf(28, 2)), drep),
			cbor.NewArray(cbor.NewUint(11), cred(1), cbor.NewBytes(bytesOf(28, 2)), cbor.NewUint(2000000)),
			cbor.NewArray(cbor.NewUint(12), cred(1), drep, cbor.NewUint(2000000)),
			cbor.NewArray(cbor.NewUint(13), cred(1), cbor.NewBytes(bytesOf(28, 2)), drep, cbor.NewUint(2000000)),
			cbor.NewArray(cbor.NewUint(16), cred(3), cbor.NewUint(500000000), cbor.Null),
			cbor.NewArray(cbor.NewUint(9), cred(1), cbor.NewArray(cbor.NewUint(0), cbor.NewBytes(bytesOf(28, 6)))),
		)
		setKey(body(&v), keyCertificates, certs)
		return v, true
	},
	// proposal procedures, treasury and donation
	func(r *rand.Rand, v cbor.Value) (cbor.Value, bool) {
		pp := cbor.NewArray(cbor.NewArray(cbor.NewUint(100000000000), cbor.NewBytes(append([]byte{0xe1}, bytesOf(28, 3)...)),
			cbor.NewArray(cbor.NewUint(6)), cbor.NewArray(cbor.NewText("https://example.com/a"), cbor.NewBytes(bytesOf(32, 1)))))
		setKey(body(&v), keyProposalProcedures, pp)
		setKey(body(&v), keyTreasury, cbor.NewUint(10))
		setKey(body(&v), keyDonation, cbor.NewUint(5))
		return v, true
	},
	// mint with a negative amount and int64 overflow, empty mint group
	func(r *rand.Rand, v cbor.Value) (cbor.Value, bool) {
		mint := cbor.NewMap(
			cbor.Entry{Key: cbor.NewBytes(bytesOf(28, 1)), Value: cbor.NewMap(cbor.Entry{Key: cbor.NewBytes([]byte("a")), Value: cbor.NewInt(-5)})},
			cbor.Entry{Key: cbor.NewBytes(bytesOf(28, 2)), Value: cbor.NewMap(cbor.Entry{Key: cbor.NewBytes(nil), Value: cbor.NewUint(1 << 63)})},
			cbor.Entry{Key: cbor.NewBytes(bytesOf(28, 3)), Value: cbor.NewMap()},
		)
		setKey(body(&v), keyMint, mint)
		return v, true
	},
	// auxiliary data that is not canonical and a stale hash
	func(r *rand.Rand, v cbor.Value) (cbor.Value, bool) {
		meta := cbor.NewMap(cbor.Entry{Key: cbor.NewUint(674), Value: cbor.NewMap(
			cbor.Entry{Key: cbor.NewText("msg"), Value: cbor.NewArray(cbor.NewText("hello"))},
			cbor.Entry{Key: cbor.NewText("a"), Value: cbor.NewUint(1)},
		)})
		v.Items[len(v.Items)-1] = meta
		setKey(body(&v), keyAuxiliaryDataHash, cbor.NewBytes(bytesOf(32, 0xaa)))
		return v, true
	},
	// witness set with a vkey witness
	func(r *rand.Rand, v cbor.Value) (cbor.Value, bool) {
		v.Items[1] = cbor.NewMap(cbor.Entry{Key: cbor.NewUint(0), Value: cbor.NewArray(cbor.NewArray(cbor.NewBytes(bytesOf(32, 1)), cbor.NewBytes(bytesOf(64, 2))))})
		setKey(body(&v), keyWithdrawals, cbor.NewMap())
		return v, true
	},
	// network id, reference inputs and collateral with tags everywhere
	func(r *rand.Rand, v cbor.Value) (cbor.Value, bool) {
		in := func(b byte) cbor.Value { return cbor.NewArray(cbor.NewBytes(bytesOf(32, b)), cbor.NewUint(uint64(b))) }
		b := body(&v)
		inputs, _ := b.Get(keyInputs)
		if inputs.Kind != cbor.Tag {
			setKey(b, keyInputs, cbor.NewTag(cbor.TagSet, inputs))
		}
		setKey(b, keyCollateralInputs, cbor.NewTag(cbor.TagSet, cbor.NewArray(in(1))))
		setKey(b, keyReferenceInputs, cbor.NewTag(cbor.TagSet, cbor.NewArray(in(2), in(3))))
		setKey(b, keyNetworkID, cbor.NewUint(0))
		return v, true
	},
}

// noncanonical encodes v with random long heads, indefinite lengths and
// shuffled maps.
func noncanonical(r *rand.Rand, v cbor.Value) []byte {
	var b []byte
	head := func(major byte, n uint64) {
		m := major << 5
		switch r.Intn(4) {
		case 0:
			if n < 24 {
				b = append(b, m|byte(n))
				return
			}
			fallthrough
		case 1:
			if n <= 0xff {
				b = append(b, m|24, byte(n))
				return
			}
			fallthrough
		case 2:
			if n <= 0xffff {
				b = binary.BigEndian.AppendUint16(append(b, m|25), uint16(n))
				return
			}
			fallthrough
		default:
			b = binary.BigEndian.AppendUint64(append(b, m|27), n)
		}
	}
	var enc func(v cbor.Value)
	enc = func(v cbor.Value) {
		indef := r.Intn(5) == 0
		switch v.Kind {
		case cbor.Uint:
			head(0, v.Uint)
		case cbor.NegInt:
			head(1, v.Uint)
		case cbor.Bytes, cbor.Text:
			major := byte(2)
			if v.Kind == cbor.Text {
				major = 3
			}
			if indef && v.Kind == cbor.Bytes && len(v.Bytes) > 1 {
				b = append(b, major<<5|31)
				half := len(v.Bytes) / 2
				head(major, uint64(half))
				b = append(b, v.Bytes[:half]...)
				head(major, uint64(len(v.Bytes)-half))
				b = append(b, v.Bytes[half:]...)
				b = append(b, 0xff)
				return
			}
			head(major, uint64(len(v.Bytes)))
			b = append(b, v.Bytes...)
		case cbor.Array:
			if indef {
				b = append(b, 4<<5|31)
			} else {
				head(4, uint64(len(v.Items)))
			}
			for _, it := range v.Items {
				enc(it)
			}
			if indef {
				b = append(b, 0xff)
			}
		case cbor.Map:
			entries := append([]cbor.Entry{}, v.Entries...)
			if r.Intn(2) == 0 {
				r.Shuffle(len(entries), func(i, j int) { entries[i], entries[j] = entries[j], entries[i] })
			}
			if indef {
				b = append(b, 5<<5|31)
			} else {
				head(5, uint64(len(entries)))
			}
			for _, e := range entries {
				enc(e.Key)
				enc(e.Value)
			}
			if indef {
				b = append(b, 0xff)
			}
		case cbor.Tag:
			head(6, v.Uint)
			enc(v.Content())
		default:
			b = append(b, cbor.Encode(v)...)
		}
	}
	enc(v)
	return b
}
