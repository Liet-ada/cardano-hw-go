// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package thp_test

import (
	"encoding/hex"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Liet-ada/cardano-hw-go/internal/trezor/debuglink"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/msg"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/pb"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/thp"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/wire"
)

// These tests need the Trezor emulator, started with the "all all ..." seed
// (emu.py --slip0014), at TREZOR_EMULATOR (host:port of its main UDP port).

type memStore struct {
	mu    sync.Mutex
	creds []thp.Credential
}

func (m *memStore) Credentials() ([]thp.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]thp.Credential{}, m.creds...), nil
}

func (m *memStore) Save(c thp.Credential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.creds = append(m.creds, c)
	return nil
}

type debugUI struct {
	t     *testing.T
	debug *debuglink.Debug
	codes int
}

func (u *debugUI) PairingCode(info thp.PairingInfo) (string, error) {
	u.codes++
	return u.debug.PairingCode(info)
}

func (u *debugUI) ButtonRequest(code uint32, name string) {
	u.t.Logf("button request %d %q", code, name)
	if u.debug == nil {
		return
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		if err := u.debug.PressYes(); err != nil {
			u.t.Logf("press yes: %v", err)
		}
	}()
}

func emulator(t *testing.T) (string, *debuglink.Debug) {
	addr := os.Getenv("TREZOR_EMULATOR")
	if addr == "" {
		t.Skip("TREZOR_EMULATOR not set")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	var p int
	for _, c := range port {
		p = p*10 + int(c-'0')
	}
	d, err := debuglink.Dial(net.JoinHostPort(host, itoa(p+1)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return addr, d
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for ; n > 0; n /= 10 {
		s = string(rune('0'+n%10)) + s
	}
	return s
}

func call(t *testing.T, c *thp.Channel, session byte, reqType uint16, req any, want uint16, resp any, ui *debugUI) {
	t.Helper()
	data, err := pb.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Write(session, reqType, data); err != nil {
		t.Fatal(err)
	}
	for {
		s, typ, d, err := c.Read(60 * time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if s != session {
			continue
		}
		switch typ {
		case want:
			if err := pb.Unmarshal(d, resp); err != nil {
				t.Fatal(err)
			}
			return
		case msg.TypeButtonRequest:
			ui.ButtonRequest(0, "")
			if err := c.Write(session, msg.TypeButtonAck, nil); err != nil {
				t.Fatal(err)
			}
		case msg.TypeFailure:
			var f msg.Failure
			pb.Unmarshal(d, &f)
			t.Fatalf("failure: %v %v", *f.Code, *f.Message)
		default:
			t.Fatalf("unexpected message type %d", typ)
		}
	}
}

func TestEmulatorPairAndPublicKey(t *testing.T) {
	addr, debug := emulator(t)
	store := &memStore{}
	ui := &debugUI{t: t, debug: debug}
	open := func() *thp.Channel {
		link, err := wire.DialUDP(addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { link.Close() })
		c, err := thp.Open(link, thp.Options{Store: store, UI: ui, HostName: "test host", AppName: "cardano-hw-go test", Timeout: 60 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	c := open()
	if c.Paired || len(store.creds) != 1 || ui.codes != 1 {
		t.Fatalf("first channel: paired %v, %d credentials, %d codes", c.Paired, len(store.creds), ui.codes)
	}
	props := c.DeviceProperties()
	t.Logf("device %s, THP %d.%d", props.InternalModel, props.ProtocolVersionMajor, props.ProtocolVersionMinor)

	var f msg.Features
	call(t, c, 0, msg.TypeGetFeatures, &msg.GetFeatures{}, msg.TypeFeatures, &f, ui)
	t.Logf("firmware %d.%d.%d", f.MajorVersion, f.MinorVersion, f.PatchVersion)

	yes := true
	call(t, c, 1, msg.TypeThpCreateNewSession, &msg.ThpCreateNewSession{DeriveCardano: &yes}, msg.TypeSuccess, &msg.Success{}, ui)
	var pk msg.CardanoPublicKey
	call(t, c, 1, msg.TypeCardanoGetPublicKey, &msg.CardanoGetPublicKey{
		AddressN:       []uint32{0x8000073c, 0x80000717, 0x80000000, 0, 0},
		DerivationType: msg.DerivationIcarusTrezor,
	}, msg.TypeCardanoPublicKey, &pk, ui)
	if hex.EncodeToString(pk.Node.PublicKey) != "5d010cf16fdeff40955633d6c565f3844a288a24967cf6b76acbeb271b4f13c1" {
		t.Errorf("public key %x", pk.Node.PublicKey)
	}

	// a second channel opens with the credential, without a code
	c2 := open()
	if !c2.Paired || ui.codes != 1 {
		t.Fatalf("second channel: paired %v, %d codes", c2.Paired, ui.codes)
	}
	call(t, c2, 0, msg.TypeGetFeatures, &msg.GetFeatures{}, msg.TypeFeatures, &f, ui)
}
