// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package ledgersim

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"math/big"

	"filippo.io/edwards25519"

	"github.com/Liet-ada/cardano-hw-go/internal/cardano"
)

// The keys of a test wallet, derived as a Ledger derives them: the master
// key from the BIP-39 seed with the "ed25519 seed" HMAC (SLIP-10 style,
// retried until the third bit of the last byte of kL is clear), then
// BIP32-Ed25519 children. Only for tests: the keys are in memory, in the
// clear.

// TestMnemonic is the mnemonic of cardano-hw-cli's Ledger integration
// tests, whose expected keys and witnesses come from a real device.
const TestMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// xprv is an extended private key: kL, kR and the chain code.
type xprv struct {
	kL, kR, chain [32]byte
}

func hmac512(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha512.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// ledgerMaster derives the root key from a mnemonic and passphrase.
func ledgerMaster(mnemonic, passphrase string) (xprv, error) {
	seed, err := pbkdf2.Key(sha512.New, mnemonic, []byte("mnemonic"+passphrase), 2048, 64)
	if err != nil {
		return xprv{}, err
	}
	key := []byte("ed25519 seed")
	i := hmac512(key, seed)
	for i[31]&0x20 != 0 {
		i = hmac512(key, i)
	}
	var k xprv
	copy(k.kL[:], i[:32])
	copy(k.kR[:], i[32:])
	k.kL[0] &= 0xf8
	k.kL[31] &= 0x7f
	k.kL[31] |= 0x40
	c := hmac.New(sha256.New, key)
	c.Write([]byte{1})
	c.Write(seed)
	copy(k.chain[:], c.Sum(nil))
	return k, nil
}

func scalar(kL [32]byte) *edwards25519.Scalar {
	var wide [64]byte
	copy(wide[:], kL[:])
	s, _ := edwards25519.NewScalar().SetUniformBytes(wide[:])
	return s
}

func (k xprv) public() []byte {
	return new(edwards25519.Point).ScalarBaseMult(scalar(k.kL)).Bytes()
}

func le(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(r)
}

func putLE(dst []byte, n *big.Int) {
	b := n.Bytes()
	for i := range dst {
		dst[i] = 0
	}
	for i := 0; i < len(b) && i < len(dst); i++ {
		dst[i] = b[len(b)-1-i]
	}
}

// child derives the child at index i (BIP32-Ed25519, version 2).
func (k xprv) child(i uint32) xprv {
	idx := binary.LittleEndian.AppendUint32(nil, i)
	var z, cc []byte
	if i >= cardano.Hardened {
		z = hmac512(k.chain[:], []byte{0}, k.kL[:], k.kR[:], idx)
		cc = hmac512(k.chain[:], []byte{1}, k.kL[:], k.kR[:], idx)
	} else {
		a := k.public()
		z = hmac512(k.chain[:], []byte{2}, a, idx)
		cc = hmac512(k.chain[:], []byte{3}, a, idx)
	}
	var c xprv
	kL := new(big.Int).Add(new(big.Int).Mul(le(z[:28]), big.NewInt(8)), le(k.kL[:]))
	putLE(c.kL[:], kL)
	mod := new(big.Int).Lsh(big.NewInt(1), 256)
	kR := new(big.Int).Add(le(z[32:]), le(k.kR[:]))
	putLE(c.kR[:], kR.Mod(kR, mod))
	copy(c.chain[:], cc[32:])
	return c
}

func (k xprv) derive(p cardano.Path) xprv {
	for _, i := range p {
		k = k.child(i)
	}
	return k
}

// xpub is the public key and chain code, as the device returns them.
func (k xprv) xpub() []byte {
	return append(k.public(), k.chain[:]...)
}

// sign signs msg with the extended key (Ed25519 with kL as the scalar and kR
// as the nonce prefix).
func (k xprv) sign(msg []byte) []byte {
	h := sha512.New()
	h.Write(k.kR[:])
	h.Write(msg)
	r, _ := edwards25519.NewScalar().SetUniformBytes(h.Sum(nil))
	R := new(edwards25519.Point).ScalarBaseMult(r).Bytes()
	h.Reset()
	h.Write(R)
	h.Write(k.public())
	h.Write(msg)
	hram, _ := edwards25519.NewScalar().SetUniformBytes(h.Sum(nil))
	s := edwards25519.NewScalar().MultiplyAdd(hram, scalar(k.kL), r)
	return append(R, s.Bytes()...)
}
