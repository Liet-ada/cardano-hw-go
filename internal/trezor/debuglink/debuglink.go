// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package debuglink drives the Trezor emulator's debug link: it tells the
// pairing code and presses the buttons, so tests run without a person. Real
// Trezors in production mode have no debug link.
package debuglink

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/Liet-ada/cardano-hw-go/internal/trezor/msg"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/pb"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/thp"
	v1 "github.com/Liet-ada/cardano-hw-go/internal/trezor/v1"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/wire"
)

// Debug is a connection to the debug link. It is safe for concurrent use.
type Debug struct {
	mu   sync.Mutex
	conn v1.Conn
}

// Dial connects to the debug link of the emulator at addr.
func Dial(addr string) (*Debug, error) {
	u, err := wire.DialUDP(addr)
	if err != nil {
		return nil, err
	}
	return &Debug{conn: v1.Conn{Link: u}}, nil
}

// Close closes the connection.
func (d *Debug) Close() error { return d.conn.Link.Close() }

func (d *Debug) call(reqType uint16, req any, want uint16, resp any) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	data, err := pb.Marshal(req)
	if err != nil {
		return err
	}
	if err := d.conn.Write(reqType, data); err != nil {
		return err
	}
	for {
		t, b, err := d.conn.Read(30 * time.Second)
		if err != nil {
			return err
		}
		switch t {
		case want:
			return pb.Unmarshal(b, resp)
		case msg.TypeFailure:
			var f msg.Failure
			pb.Unmarshal(b, &f)
			return fmt.Errorf("debuglink: failure %v", f.Message)
		}
	}
}

// PairingCode tells the CodeEntry code the emulator shows for a pairing.
func (d *Debug) PairingCode(info thp.PairingInfo) (string, error) {
	cid := binary.BigEndian.AppendUint16(nil, info.ChannelID)
	var r msg.DebugLinkPairingInfo
	if err := d.call(msg.TypeDebugLinkGetPairingInfo, &msg.DebugLinkGetPairingInfo{ChannelID: cid, HandshakeHash: info.HandshakeHash},
		msg.TypeDebugLinkPairingInfo, &r); err != nil {
		return "", err
	}
	if r.CodeEntryCode == nil {
		return "", fmt.Errorf("debuglink: no pairing code")
	}
	return fmt.Sprintf("%06d", *r.CodeEntryCode), nil
}

// PressYes confirms the screen the emulator shows.
func (d *Debug) PressYes() error { return d.press(msg.DebugButtonYes) }

// PressNo refuses the screen the emulator shows.
func (d *Debug) PressNo() error { return d.press(msg.DebugButtonNo) }

func (d *Debug) press(button uint32) error {
	data, err := pb.Marshal(&msg.DebugLinkDecision{Button: &button})
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.conn.Write(msg.TypeDebugLinkDecision, data)
}

// PressSoon confirms the screen, or refuses it, after it had time to
// appear.
func (d *Debug) PressSoon(yes bool) {
	time.Sleep(300 * time.Millisecond)
	if yes {
		d.PressYes()
	} else {
		d.PressNo()
	}
}

// Layout returns the text of the current screen.
func (d *Debug) Layout() (string, error) {
	wait := uint32(2) // CURRENT_LAYOUT
	var s msg.DebugLinkState
	if err := d.call(msg.TypeDebugLinkGetState, &msg.DebugLinkGetState{WaitLayout: &wait}, msg.TypeDebugLinkState, &s); err != nil {
		return "", err
	}
	out := ""
	for _, t := range s.Tokens {
		out += t
	}
	return out, nil
}
