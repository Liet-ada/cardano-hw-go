// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package thp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/big"

	"filippo.io/edwards25519/field"
)

// The secure channel layer of the Trezor Host Protocol: a Noise XX handshake
// over X25519, AES-256-GCM and SHA-256, in which the Trezor's static key is
// masked with its ephemeral key, followed by CodeEntry pairing with CPace.
// Names follow the specification (docs/common/thp/specification.md in
// trezor-firmware).

var protocolName = []byte("Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00")

var errDecrypt = errors.New("thp: decryption failed")

// hkdf is the HKDF of Noise: two 32-byte outputs.
func hkdf(ck, input []byte) (out1, out2 []byte) {
	m := hmac.New(sha256.New, ck)
	m.Write(input)
	temp := m.Sum(nil)
	m = hmac.New(sha256.New, temp)
	m.Write([]byte{1})
	out1 = m.Sum(nil)
	m = hmac.New(sha256.New, temp)
	m.Write(append(append([]byte{}, out1...), 2))
	out2 = m.Sum(nil)
	return out1, out2
}

func sha(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// iv is the AES-GCM nonce of Noise: 32 zero bits and a big-endian counter.
func iv(n uint64) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint64(b[4:], n)
	return b
}

func gcm(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // keys are always 32 bytes
	}
	a, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return a
}

func seal(key []byte, n uint64, ad, plaintext []byte) []byte {
	return gcm(key).Seal(nil, iv(n), plaintext, ad)
}

func open(key []byte, n uint64, ad, ciphertext []byte) ([]byte, error) {
	p, err := gcm(key).Open(nil, iv(n), ciphertext, ad)
	if err != nil {
		return nil, errDecrypt
	}
	return p, nil
}

func x25519(priv, pub []byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	p, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return k.ECDH(p)
}

// maskedStaticKey is the form in which the Trezor shows its static key in
// the handshake: X25519(SHA-256(static || ephemeral), static).
func maskedStaticKey(trezorStatic, trezorEphemeral []byte) ([]byte, error) {
	return x25519(sha(trezorStatic, trezorEphemeral), trezorStatic)
}

// Trezor states in the handshake completion response.
const (
	stateUnpaired          = 0
	statePaired            = 1
	statePairedAutoconnect = 2
)

// handshake is the host's side of the handshake.
type handshake struct {
	deviceProperties []byte
	ephemeral        *ecdh.PrivateKey
	tryToUnlock      byte

	h, ck, k []byte
	// learned from the Trezor
	trezorEphemeral, trezorMaskedStatic []byte
}

// initiationRequest starts the handshake (state HH0).
func newHandshake(deviceProperties []byte, ephemeral *ecdh.PrivateKey, tryToUnlock bool) *handshake {
	hs := &handshake{deviceProperties: deviceProperties, ephemeral: ephemeral}
	if tryToUnlock {
		hs.tryToUnlock = 1
	}
	return hs
}

func (hs *handshake) initiationRequest() []byte {
	return append(hs.ephemeral.PublicKey().Bytes(), hs.tryToUnlock)
}

// readInitiationResponse handles HandshakeInitiationResponse (state HH1,
// steps 1 to 10).
func (hs *handshake) readInitiationResponse(resp []byte) error {
	if len(resp) != 32+48+16 {
		return errors.New("thp: handshake initiation response of the wrong size")
	}
	te, encStatic, tag := resp[:32], resp[32:80], resp[80:]
	hs.h = sha(protocolName, hs.deviceProperties)
	hs.h = sha(hs.h, hs.ephemeral.PublicKey().Bytes())
	hs.h = sha(hs.h, []byte{hs.tryToUnlock})
	hs.h = sha(hs.h, te)
	dh, err := x25519(hs.ephemeral.Bytes(), te)
	if err != nil {
		return err
	}
	hs.ck, hs.k = hkdf(protocolName, dh)
	masked, err := open(hs.k, 0, hs.h, encStatic)
	if err != nil {
		return err
	}
	hs.h = sha(hs.h, encStatic)
	dh, err = x25519(hs.ephemeral.Bytes(), masked)
	if err != nil {
		return err
	}
	hs.ck, hs.k = hkdf(hs.ck, dh)
	empty, err := open(hs.k, 0, hs.h, tag)
	if err != nil || len(empty) != 0 {
		return errDecrypt
	}
	hs.h = sha(hs.h, tag)
	hs.trezorEphemeral, hs.trezorMaskedStatic = te, masked
	return nil
}

// matches reports whether trezorStatic is the static key of the Trezor in
// this handshake.
func (hs *handshake) matches(trezorStatic []byte) bool {
	m, err := maskedStaticKey(trezorStatic, hs.trezorEphemeral)
	return err == nil && subtle.ConstantTimeCompare(m, hs.trezorMaskedStatic) == 1
}

// completionRequest builds HandshakeCompletionRequest (state HH1, steps 12
// to 17) with the host's static key and an optional pairing credential.
func (hs *handshake) completionRequest(hostStatic *ecdh.PrivateKey, payload []byte) ([]byte, error) {
	encStatic := seal(hs.k, 1, hs.h, hostStatic.PublicKey().Bytes())
	hs.h = sha(hs.h, encStatic)
	dh, err := x25519(hostStatic.Bytes(), hs.trezorEphemeral)
	if err != nil {
		return nil, err
	}
	hs.ck, hs.k = hkdf(hs.ck, dh)
	encPayload := seal(hs.k, 0, hs.h, payload)
	hs.h = sha(hs.h, encPayload)
	return append(encStatic, encPayload...), nil
}

// readCompletionResponse handles HandshakeCompletionResponse (states HH2
// and HH3) and returns the Trezor's state and the keys of the channel.
func (hs *handshake) readCompletionResponse(resp []byte) (state byte, keys *cipherState, err error) {
	kReq, kResp := hkdf(hs.ck, nil)
	st, err := open(kResp, 0, nil, resp)
	if err != nil {
		return 0, nil, err
	}
	if len(st) != 1 || st[0] > statePairedAutoconnect {
		return 0, nil, errors.New("thp: invalid Trezor state in the handshake")
	}
	return st[0], &cipherState{keyRequest: kReq, keyResponse: kResp, nonceRequest: 0, nonceResponse: 1}, nil
}

// handshakeHash is h at the end of the handshake, which pairing binds to.
func (hs *handshake) handshakeHash() []byte { return hs.h }

// cipherState encrypts the application messages of an open channel.
type cipherState struct {
	keyRequest, keyResponse     []byte
	nonceRequest, nonceResponse uint64
}

func (c *cipherState) encrypt(plaintext []byte) []byte {
	out := seal(c.keyRequest, c.nonceRequest, nil, plaintext)
	c.nonceRequest++
	return out
}

func (c *cipherState) decrypt(ciphertext []byte) ([]byte, error) {
	out, err := open(c.keyResponse, c.nonceResponse, nil, ciphertext)
	if err != nil {
		return nil, err
	}
	c.nonceResponse++
	return out, nil
}

// --- CodeEntry pairing

// codeEntryCode is the six-digit code the Trezor shows, from its secret and
// the host's challenge.
func codeEntryCode(handshakeHash, secret, challenge []byte) uint32 {
	h := sha([]byte{2}, handshakeHash, secret, challenge) // 2 is ThpPairingMethod CodeEntry
	n := new(big.Int).SetBytes(h)
	return uint32(n.Mod(n, big.NewInt(1000000)).Uint64())
}

// cpaceGenerator maps the code and the handshake hash to a point, as in
// CPace255 with the code as password and the handshake hash as channel
// identifier.
func cpaceGenerator(code string, handshakeHash []byte) []byte {
	in := []byte{0x08, 'C', 'P', 'a', 'c', 'e', '2', '5', '5', byte(len(code))}
	in = append(in, code...)
	in = append(in, 0x6f)
	in = append(in, make([]byte, 111)...)
	in = append(in, byte(len(handshakeHash)))
	in = append(in, handshakeHash...)
	in = append(in, 0x00)
	pre := sha512.Sum512(in)
	return elligator2(pre[:32])
}

// cpaceHost computes the host's CPace public key and the tag that proves the
// shared secret to the Trezor.
func cpaceHost(code string, handshakeHash, trezorPublic, hostPrivate []byte) (hostPublic, tag []byte, err error) {
	g := cpaceGenerator(code, handshakeHash)
	hostPublic, err = x25519(hostPrivate, g)
	if err != nil {
		return nil, nil, err
	}
	shared, err := x25519(hostPrivate, trezorPublic)
	if err != nil {
		return nil, nil, errors.New("thp: invalid CPace public key from the Trezor")
	}
	return hostPublic, sha(shared), nil
}

var (
	elligatorJ  = feFromUint(486662)
	elligatorC3 = mustFE("b0a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b") // sqrt(-1)
	feOne       = new(field.Element).One()
	feTwo       = feFromUint(2)
	feNegJ      = new(field.Element).Negate(feFromUint(486662))
)

func feFromUint(n uint64) *field.Element {
	b := make([]byte, 32)
	binary.LittleEndian.PutUint64(b, n)
	e, _ := new(field.Element).SetBytes(b)
	return e
}

func mustFE(h string) *field.Element {
	b := make([]byte, 32)
	for i := range b {
		var v byte
		for j := 0; j < 2; j++ {
			c := h[2*i+j]
			switch {
			case c >= '0' && c <= '9':
				v = v<<4 | (c - '0')
			default:
				v = v<<4 | (c - 'a' + 10)
			}
		}
		b[i] = v
	}
	e, err := new(field.Element).SetBytes(b)
	if err != nil {
		panic(err)
	}
	return e
}

// elligator2 is map_to_curve_elligator2_curve25519 of RFC 9380, returning
// the Montgomery u-coordinate. The input is a little-endian field element
// whose top bit is ignored.
func elligator2(in []byte) []byte {
	u, err := new(field.Element).SetBytes(in)
	if err != nil {
		panic(err)
	}
	tv1 := new(field.Element).Square(u)
	tv1.Multiply(tv1, feTwo)
	xd := new(field.Element).Add(tv1, feOne)
	x1n := new(field.Element).Set(feNegJ)
	tv2 := new(field.Element).Square(xd)
	gxd := new(field.Element).Multiply(tv2, xd)
	gx1 := new(field.Element).Multiply(elligatorJ, tv1)
	gx1.Multiply(gx1, x1n)
	gx1.Add(gx1, tv2)
	gx1.Multiply(gx1, x1n)
	tv3 := new(field.Element).Square(gxd)
	tv2.Square(tv3)
	tv3.Multiply(tv3, gxd)
	tv3.Multiply(tv3, gx1)
	tv2.Multiply(tv2, tv3)
	y11 := new(field.Element).Pow22523(tv2)
	y11.Multiply(y11, tv3)
	y12 := new(field.Element).Multiply(y11, elligatorC3)
	tv2.Square(y11)
	tv2.Multiply(tv2, gxd)
	e1 := tv2.Equal(gx1)
	y1 := new(field.Element).Select(y11, y12, e1)
	x2n := new(field.Element).Multiply(x1n, tv1)
	tv2.Square(y1)
	tv2.Multiply(tv2, gxd)
	e3 := tv2.Equal(gx1)
	xn := new(field.Element).Select(x1n, x2n, e3)
	x := new(field.Element).Multiply(xn, new(field.Element).Invert(xd))
	return x.Bytes()
}
