// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package thp

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Liet-ada/cardano-hw-go/internal/trezor/msg"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/wire"
)

// pipeLink is one end of an in-memory link.
type pipeLink struct {
	in  <-chan []byte
	out chan<- []byte
}

func newPipe() (host, device *pipeLink) {
	a, b := make(chan []byte, 256), make(chan []byte, 256)
	return &pipeLink{in: a, out: b}, &pipeLink{in: b, out: a}
}

func (l *pipeLink) Write(p []byte) error {
	l.out <- append([]byte{}, p...)
	return nil
}

func (l *pipeLink) Read(timeout time.Duration) ([]byte, error) {
	if timeout == 0 {
		timeout = time.Hour
	}
	select {
	case p := <-l.in:
		return p, nil
	case <-time.After(timeout):
		return nil, wire.ErrTimeout
	}
}

func (l *pipeLink) Close() error { return nil }

type memStore struct{ creds []Credential }

func (s *memStore) Credentials() ([]Credential, error) { return s.creds, nil }
func (s *memStore) Save(c Credential) error {
	s.creds = append(s.creds, c)
	return nil
}

// serveOpen plays the Trezor's side of Open up to ThpEndResponse, answering
// the handshake with state.
func serveOpen(_ *testing.T, f *fakeTrezor, link *pipeLink, state byte) error {
	const cid = 0x1234
	tr := &transport{link: link}
	m, err := tr.readMessage(broadcastCID, 5*time.Second)
	if err != nil {
		return err
	}
	resp := append(append([]byte{}, m.payload...), 0, 0)
	binary.BigEndian.PutUint16(resp[len(m.payload):], cid)
	if err := tr.writeMessage(ctrlChannelAllocResp, broadcastCID, append(resp, f.props...)); err != nil {
		return err
	}
	tr.cid = cid
	if m, err = tr.receive(5 * time.Second); err != nil {
		return err
	}
	init, err := f.initiation(m.payload)
	if err != nil {
		return err
	}
	if err := tr.send(ctrlHandshakeInitResp, init); err != nil {
		return err
	}
	if m, err = tr.receive(5 * time.Second); err != nil {
		return err
	}
	comp, _, err := f.completion(m.payload, state)
	if err != nil {
		return err
	}
	if err := tr.send(ctrlHandshakeCompResp, comp); err != nil {
		return err
	}
	if m, err = tr.receive(time.Second); err != nil {
		return err
	}
	if _, err := f.keys.decryptRequest(m.payload); err != nil {
		return err
	}
	t := msg.TypeThpEndResponse
	end := f.keys.encryptResponse([]byte{0, byte(t >> 8), byte(t)})
	return tr.send(ctrlEncryptedTransport, end)
}

var testProps = []byte{0x0a, 0x04, 'T', '3', 'W', '1', 0x18, 0x02, 0x20, 0x00, 0x28, 0x02}

// A device that claims the host is paired, when the host presented no
// credential, never proved to be the paired Trezor: Open must refuse it
// instead of skipping the pairing code.
func TestOpenRefusesPairedWithoutCredential(t *testing.T) {
	for _, state := range []byte{statePaired, statePairedAutoconnect} {
		host, device := newPipe()
		f := newFakeTrezor(t, testProps)
		go serveOpen(t, f, device, state)
		// a credential for another Trezor: the host cannot present it
		store := &memStore{creds: []Credential{{
			TrezorStaticPublicKey: newKey(t).PublicKey().Bytes(),
			HostStaticPrivateKey:  newKey(t).Bytes(),
			Credential:            []byte{1},
		}}}
		_, err := Open(host, Options{Store: store, Timeout: 5 * time.Second})
		if err == nil || !strings.Contains(err.Error(), "no credential") {
			t.Fatalf("state %d: Open = %v, want a refusal", state, err)
		}
	}
}

// With a credential for this Trezor, a paired state opens the channel.
func TestOpenPairedWithCredential(t *testing.T) {
	host, device := newPipe()
	f := newFakeTrezor(t, testProps)
	done := make(chan error, 1)
	go func() { done <- serveOpen(t, f, device, statePaired) }()
	hostStatic := newKey(t)
	store := &memStore{creds: []Credential{{
		TrezorStaticPublicKey: f.static.PublicKey().Bytes(),
		HostStaticPrivateKey:  hostStatic.Bytes(),
		Credential:            []byte{1, 2, 3},
	}}}
	c, err := Open(host, Options{Store: store, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil && !errors.Is(err, wire.ErrTimeout) {
		t.Fatal(err)
	}
	if !c.Paired || c.Autoconnect {
		t.Fatalf("Paired %v, Autoconnect %v", c.Paired, c.Autoconnect)
	}
	if string(f.hostStatic) != string(hostStatic.PublicKey().Bytes()) {
		t.Fatal("the host did not present the stored static key")
	}
}
