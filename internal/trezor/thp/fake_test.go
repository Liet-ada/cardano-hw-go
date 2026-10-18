// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package thp

import (
	"crypto/ecdh"
	"errors"
	"testing"
)

// fakeTrezor follows the Trezor's state machine of the specification
// (states TH1 and TH2), to test the host's side without a device.
type fakeTrezor struct {
	t          *testing.T
	props      []byte
	static     *ecdh.PrivateKey
	ephemeral  *ecdh.PrivateKey
	h, ck, k   []byte
	hostStatic []byte
	keys       *fakeKeys
}

type fakeKeys struct {
	req, resp           []byte
	nonceReq, nonceResp uint64
}

func (k *fakeKeys) decryptRequest(c []byte) ([]byte, error) {
	p, err := open(k.req, k.nonceReq, nil, c)
	if err == nil {
		k.nonceReq++
	}
	return p, err
}

func (k *fakeKeys) encryptResponse(p []byte) []byte {
	c := seal(k.resp, k.nonceResp, nil, p)
	k.nonceResp++
	return c
}

func newFakeTrezor(t *testing.T, props []byte) *fakeTrezor {
	return &fakeTrezor{t: t, props: props, static: newKey(t)}
}

func (f *fakeTrezor) initiation(req []byte) ([]byte, error) {
	if len(req) != 33 {
		return nil, errors.New("bad initiation request")
	}
	hostEph, unlock := req[:32], req[32:]
	f.ephemeral = newKey(f.t)
	te := f.ephemeral.PublicKey().Bytes()
	f.h = sha(protocolName, f.props)
	f.h = sha(f.h, hostEph)
	f.h = sha(f.h, unlock)
	f.h = sha(f.h, te)
	dh, err := x25519(f.ephemeral.Bytes(), hostEph)
	if err != nil {
		return nil, err
	}
	f.ck, f.k = hkdf(protocolName, dh)
	ts := f.static.PublicKey().Bytes()
	mask := sha(ts, te)
	masked, err := x25519(mask, ts)
	if err != nil {
		return nil, err
	}
	encStatic := seal(f.k, 0, f.h, masked)
	f.h = sha(f.h, encStatic)
	inner, err := x25519(f.static.Bytes(), hostEph)
	if err != nil {
		return nil, err
	}
	dh, err = x25519(mask, inner)
	if err != nil {
		return nil, err
	}
	f.ck, f.k = hkdf(f.ck, dh)
	tag := seal(f.k, 0, f.h, nil)
	f.h = sha(f.h, tag)
	return append(append(append([]byte{}, te...), encStatic...), tag...), nil
}

func (f *fakeTrezor) completion(req []byte, state byte) (resp, payload []byte, err error) {
	encStatic, encPayload := req[:48], req[48:]
	hostStatic, err := open(f.k, 1, f.h, encStatic)
	if err != nil {
		return nil, nil, err
	}
	f.h = sha(f.h, encStatic)
	dh, err := x25519(f.ephemeral.Bytes(), hostStatic)
	if err != nil {
		return nil, nil, err
	}
	f.ck, f.k = hkdf(f.ck, dh)
	payload, err = open(f.k, 0, f.h, encPayload)
	if err != nil {
		return nil, nil, err
	}
	f.h = sha(f.h, encPayload)
	f.hostStatic = hostStatic
	kReq, kResp := hkdf(f.ck, nil)
	f.keys = &fakeKeys{req: kReq, resp: kResp, nonceResp: 1}
	return seal(kResp, 0, nil, []byte{state}), payload, nil
}
