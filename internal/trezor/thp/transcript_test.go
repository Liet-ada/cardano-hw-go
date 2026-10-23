// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package thp_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"testing/cryptotest"
	"time"

	"github.com/Liet-ada/cardano-hw-go/internal/trezor/msg"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/thp"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/wire"
)

// The transcript test replays, packet by packet, a session recorded from the
// Trezor Safe 7 emulator: pairing with a code, a public key, and a second
// channel opened with the credential. The host's randomness is fixed, so the
// host must send exactly the packets it sent to the emulator; that checks
// the handshake, CPace and the channel against the firmware, not against
// this package's own idea of the specification.
//
// To record it again, start the emulator as for the other emulator tests
// and run with TREZOR_EMULATOR and THP_RECORD=1.

const transcriptFile = "testdata/emulator-transcript.json"

type event struct {
	Op     string `json:"op"` // "write", "read" or "timeout"
	Packet string `json:"packet,omitempty"`
}

type transcript struct {
	Codes  []string `json:"codes"`
	Events []event  `json:"events"`
}

// recordLink records what passes through a link.
type recordLink struct {
	wire.Link
	tr *transcript
}

func (l *recordLink) Write(p []byte) error {
	l.tr.Events = append(l.tr.Events, event{"write", hex.EncodeToString(p)})
	return l.Link.Write(p)
}

func (l *recordLink) Read(timeout time.Duration) ([]byte, error) {
	p, err := l.Link.Read(timeout)
	switch {
	case errors.Is(err, wire.ErrTimeout):
		l.tr.Events = append(l.tr.Events, event{Op: "timeout"})
	case err == nil:
		l.tr.Events = append(l.tr.Events, event{"read", hex.EncodeToString(p)})
	}
	return p, err
}

// replayLink checks the host's packets against a transcript and answers
// with the recorded ones.
type replayLink struct {
	t      *testing.T
	events []event
}

func (l *replayLink) next(op string) event {
	l.t.Helper()
	if len(l.events) == 0 {
		l.t.Fatalf("the host goes on (%s) after the end of the transcript", op)
	}
	e := l.events[0]
	l.events = l.events[1:]
	return e
}

func (l *replayLink) Write(p []byte) error {
	e := l.next("write")
	if e.Op != "write" || e.Packet != hex.EncodeToString(p) {
		l.t.Fatalf("the host wrote %x, the transcript has %s %s", p, e.Op, e.Packet)
	}
	return nil
}

func (l *replayLink) Read(time.Duration) ([]byte, error) {
	switch e := l.next("read"); e.Op {
	case "timeout":
		return nil, wire.ErrTimeout
	case "read":
		return hex.DecodeString(e.Packet)
	default:
		l.t.Fatalf("the host reads, the transcript has %s %s", e.Op, e.Packet)
		return nil, nil
	}
}

func (l *replayLink) Close() error { return nil }

type replayUI struct{ codes []string }

func (u *replayUI) PairingCode(thp.PairingInfo) (string, error) {
	if len(u.codes) == 0 {
		return "", errors.New("no more recorded codes")
	}
	c := u.codes[0]
	u.codes = u.codes[1:]
	return c, nil
}

func (u *replayUI) ButtonRequest(uint32, string) {}

type recordUI struct {
	debugUI
	tr *transcript
}

func (u *recordUI) PairingCode(info thp.PairingInfo) (string, error) {
	c, err := u.debugUI.PairingCode(info)
	u.tr.Codes = append(u.tr.Codes, c)
	return c, err
}

// session runs what the transcript holds over links from dial.
func session(t *testing.T, dial func() wire.Link, ui thp.UI) {
	t.Helper()
	cryptotest.SetGlobalRandom(t, 1)
	store := &memStore{}
	// replaying, nothing presses the Trezor's buttons
	u := &debugUI{t: t}
	if r, ok := ui.(*recordUI); ok {
		u = &r.debugUI
	}
	do := func(c *thp.Channel, s byte, reqType uint16, req any, want uint16, resp any) {
		t.Helper()
		call(t, c, s, reqType, req, want, resp, u)
	}
	open := func() *thp.Channel {
		c, err := thp.Open(dial(), thp.Options{Store: store, UI: ui, HostName: "test host", AppName: "cardano-hw-go test", Timeout: 60 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := open()
	if c.Paired || len(store.creds) != 1 {
		t.Fatalf("first channel: paired %v, %d credentials", c.Paired, len(store.creds))
	}
	yes := true
	do(c, 1, msg.TypeThpCreateNewSession, &msg.ThpCreateNewSession{DeriveCardano: &yes}, msg.TypeSuccess, &msg.Success{})
	var pk msg.CardanoPublicKey
	do(c, 1, msg.TypeCardanoGetPublicKey, &msg.CardanoGetPublicKey{
		AddressN:       []uint32{0x8000073c, 0x80000717, 0x80000000, 0, 0},
		DerivationType: msg.DerivationIcarusTrezor,
	}, msg.TypeCardanoPublicKey, &pk)
	if hex.EncodeToString(pk.Node.PublicKey) != "5d010cf16fdeff40955633d6c565f3844a288a24967cf6b76acbeb271b4f13c1" {
		t.Errorf("public key %x", pk.Node.PublicKey)
	}
	c2 := open()
	if !c2.Paired {
		t.Fatal("second channel not paired")
	}
	var f msg.Features
	do(c2, 0, msg.TypeGetFeatures, &msg.GetFeatures{}, msg.TypeFeatures, &f)
}

func TestEmulatorTranscript(t *testing.T) {
	if os.Getenv("THP_RECORD") == "" {
		data, err := os.ReadFile(transcriptFile)
		if err != nil {
			t.Fatal(err)
		}
		var tr transcript
		if err := json.Unmarshal(data, &tr); err != nil {
			t.Fatal(err)
		}
		link := &replayLink{t: t, events: tr.Events}
		session(t, func() wire.Link { return link }, &replayUI{codes: tr.Codes})
		if len(link.events) != 0 {
			t.Fatalf("%d recorded events left over", len(link.events))
		}
		return
	}

	addr, debug := emulator(t)
	tr := &transcript{}
	ui := &recordUI{debugUI: debugUI{t: t, debug: debug}, tr: tr}
	session(t, func() wire.Link {
		link, err := wire.DialUDP(addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { link.Close() })
		return &recordLink{Link: link, tr: tr}
	}, ui)
	data, err := json.MarshalIndent(tr, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(transcriptFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(transcriptFile, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("recorded %d events, %d codes", len(tr.Events), len(tr.Codes))
}
