// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package thp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSqrtM1(t *testing.T) {
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	want, _ := new(big.Int).SetString("19681161376707505956807079304988542015446066515923890162744021073123829784752", 10)
	le := elligatorC3.Bytes()
	for i, j := 0, len(le)-1; i < j; i, j = i+1, j-1 {
		le[i], le[j] = le[j], le[i]
	}
	if got := new(big.Int).SetBytes(le); got.Cmp(want) != 0 {
		t.Fatalf("sqrt(-1) = %v", got)
	}
	sq := new(big.Int).Mul(want, want)
	if sq.Mod(sq, p).Cmp(new(big.Int).Sub(p, big.NewInt(1))) != 0 {
		t.Fatal("not a square root of -1")
	}
}

// Vectors from elligator.org (curve25519_direct.vec), as used by Trezor
// Suite's tests.
func TestElligator2(t *testing.T) {
	for _, v := range [][2]string{
		{"0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"66665895c5bc6e44ba8d65fd9307092e3244bf2c18877832bd568cb3a2d38a12", "04d44290d13100b2c25290c9343d70c12ed4813487a07ac1176daa5925e7975e"},
		{"673a505e107189ee54ca93310ac42e4545e9e59050aaac6f8b5f64295c8ec02f", "242ae39ef158ed60f20b89396d7d7eef5374aba15dc312a6aea6d1e57cacf85e"},
		{"990b30e04e1c3620b4162b91a33429bddb9f1b70f1da6e5f76385ed3f98ab131", "998e98021eb4ee653effaa992f3fae4b834de777a953271baaa1fa3fef6b776e"},
		{"341a60725b482dd0de2e25a585b208433044bc0a1ba762442df3a0e888ca063c", "683a71d7fca4fc6ad3d4690108be808c2e50a5af3174486741d0a83af52aeb01"},
		{"922688fa428d42bc1fa8806998fbc5959ae801817e85a42a45e8ec25a0d7541a", "696f341266c64bcfa7afa834f8c34b2730be11c932e08474d1a22f26ed82410b"},
		{"0d3b0eb88b74ed13d5f6a130e03c4ad607817057dc227152827c0506a538bb3a", "0b00df174d9fb0b6ee584d2cf05613130bad18875268c38b377e86dfefef177f"},
		{"01a3ea5658f4e00622eeacf724e0bd82068992fae66ed2b04a8599be16662e35", "7ae4c58bc647b5646c9f5ae4c2554ccbf7c6e428e7b242a574a5a9c293c21f7e"},
		{"1d991dff82a84afe97874c0f03a60a56616a15212fbe10d6c099aa3afcfabe35", "f81f235696f81df90ac2fc861ceee517bff611a394b5be5faaee45584642fb0a"},
		{"185435d2b005a3b63f3187e64a1ef3582533e1958d30e4e4747b4d1d3376c728", "f938b1b320abb0635930bd5d7ced45ae97fa8b5f71cc21d87b4c60905c125d34"},
	} {
		if got := hex.EncodeToString(elligator2(unhex(t, v[0]))); got != v[1] {
			t.Errorf("%s: got %s, want %s", v[0], got, v[1])
		}
	}
}

// The vector of Trezor Suite's findKnownPairingCredentials test.
func TestMaskedStaticKey(t *testing.T) {
	m, err := maskedStaticKey(
		unhex(t, "2bcdbc9fd7949c3f37aa80a53801f52ec554facfe76118030926294250fd6838"),
		unhex(t, "f817f577f24d7ec08c1ea397df2da916e0ee81423961763dc45395e18fc02121"))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(m) != "be8d024bbcd5ac116e041035fcc6243ce1d77d7075e351c87aa0831fbf46ce66" {
		t.Errorf("masked key %x", m)
	}
}

func TestCodeEntryCode(t *testing.T) {
	hh := bytes.Repeat([]byte{1}, 32)
	c := codeEntryCode(hh, bytes.Repeat([]byte{2}, 16), bytes.Repeat([]byte{3}, 16))
	if c >= 1000000 {
		t.Fatalf("code %d", c)
	}
	if c != codeEntryCode(hh, bytes.Repeat([]byte{2}, 16), bytes.Repeat([]byte{3}, 16)) {
		t.Fatal("code not deterministic")
	}
}

// The host's and the Trezor's sides of CPace agree on the shared secret.
func TestCPace(t *testing.T) {
	hh := bytes.Repeat([]byte{7}, 32)
	g := cpaceGenerator("012345", hh)
	trezorPriv := make([]byte, 32)
	rand.Read(trezorPriv)
	trezorPub, err := x25519(trezorPriv, g)
	if err != nil {
		t.Fatal(err)
	}
	hostPriv := make([]byte, 32)
	rand.Read(hostPriv)
	hostPub, tag, err := cpaceHost("012345", hh, trezorPub, hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := x25519(trezorPriv, hostPub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sha(shared), tag) {
		t.Fatal("tags differ")
	}
	// with a wrong code, the Trezor's shared secret does not match the tag
	wrongPub, wrongTag, err := cpaceHost("012346", hh, trezorPub, hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	wrongShared, err := x25519(trezorPriv, wrongPub)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sha(wrongShared), wrongTag) {
		t.Fatal("a wrong code passed the Trezor's check")
	}
}

func newKey(t *testing.T) *ecdh.PrivateKey {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The host's handshake against fakeTrezor, which follows the Trezor's side
// of the specification.
func TestHandshake(t *testing.T) {
	props := []byte{0x0a, 0x04, 'T', '3', 'W', '1', 0x18, 0x02, 0x20, 0x00, 0x28, 0x02}
	trezor := newFakeTrezor(t, props)
	host := newHandshake(props, newKey(t), true)

	resp, err := trezor.initiation(host.initiationRequest())
	if err != nil {
		t.Fatal(err)
	}
	if err := host.readInitiationResponse(resp); err != nil {
		t.Fatal(err)
	}
	if !host.matches(trezor.static.PublicKey().Bytes()) {
		t.Fatal("host does not recognise the Trezor's static key")
	}
	if host.matches(newKey(t).PublicKey().Bytes()) {
		t.Fatal("host recognises another key")
	}
	hostStatic := newKey(t)
	req, err := host.completionRequest(hostStatic, []byte{0x0a, 0x01, 0x42})
	if err != nil {
		t.Fatal(err)
	}
	cresp, payload, err := trezor.completion(req, statePaired)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, []byte{0x0a, 0x01, 0x42}) || !bytes.Equal(trezor.hostStatic, hostStatic.PublicKey().Bytes()) {
		t.Fatalf("Trezor got payload %x", payload)
	}
	state, keys, err := host.readCompletionResponse(cresp)
	if err != nil {
		t.Fatal(err)
	}
	if state != statePaired || !bytes.Equal(host.handshakeHash(), trezor.h) {
		t.Fatalf("state %d, hashes differ", state)
	}
	// application messages both ways
	ct := keys.encrypt([]byte("hello"))
	pt, err := trezor.keys.decryptRequest(ct)
	if err != nil || string(pt) != "hello" {
		t.Fatalf("Trezor read %q, %v", pt, err)
	}
	pt, err = keys.decrypt(trezor.keys.encryptResponse([]byte("world")))
	if err != nil || string(pt) != "world" {
		t.Fatalf("host read %q, %v", pt, err)
	}
	if _, err := keys.decrypt(ct); err == nil {
		t.Fatal("host decrypted its own message")
	}
}
