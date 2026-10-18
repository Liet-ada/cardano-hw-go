// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package trezor talks to a Trezor: it tells THP devices (Safe 7) from
// Codec v1 ones (Model T, Safe 3, Safe 5 on older firmware), opens a
// session with Cardano derivation, and exchanges protocol buffers messages,
// answering button and passphrase requests on the way.
package trezor

import (
	"errors"
	"fmt"
	"time"

	"github.com/Liet-ada/cardano-hw-go/internal/trezor/msg"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/pb"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/thp"
	v1 "github.com/Liet-ada/cardano-hw-go/internal/trezor/v1"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/wire"
)

// UI is how the client talks to the person.
type UI interface {
	thp.UI
}

// Options configure Connect.
type Options struct {
	UI    UI
	Store thp.Store
	// HostName and AppName are shown on the Trezor when pairing.
	HostName, AppName string
	// Timeout bounds each wait for the Trezor, which may wait for the
	// person; zero waits without limit.
	Timeout time.Duration
}

// Client is a session with Cardano derivation on a Trezor.
type Client struct {
	conn     conn
	features msg.Features
	ui       UI
	timeout  time.Duration
	// Channel is the THP channel, nil with Codec v1.
	Channel *thp.Channel
}

// conn is a stream of messages in one session.
type conn interface {
	Write(msgType uint16, data []byte) error
	Read(timeout time.Duration) (uint16, []byte, error)
}

type thpSession struct {
	ch      *thp.Channel
	session byte
}

func (s *thpSession) Write(t uint16, d []byte) error { return s.ch.Write(s.session, t, d) }

func (s *thpSession) Read(timeout time.Duration) (uint16, []byte, error) {
	for {
		id, t, d, err := s.ch.Read(timeout)
		if err != nil || id == s.session {
			return t, d, err
		}
	}
}

// Failure is a Failure message from the Trezor.
type Failure = thp.FailureError

// ErrPassphraseNotOnDevice is the error cardano-hw-cli gives for a Trezor
// that cannot take the passphrase on the device.
var ErrPassphraseNotOnDevice = errors.New("Trezor passphrase not insertable on the device")

// usesTHP probes the device with a Codec v1 message: a THP device answers
// that the protocol is invalid.
func usesTHP(link wire.Link) (bool, error) {
	c := &v1.Conn{Link: link}
	// drop stale packets
	for {
		if _, err := link.Read(50 * time.Millisecond); err != nil {
			break
		}
	}
	if err := c.Write(msg.TypeCancel, nil); err != nil {
		return false, err
	}
	for {
		t, d, err := c.Read(5 * time.Second)
		if err != nil {
			return false, err
		}
		if t != msg.TypeFailure {
			continue
		}
		var f msg.Failure
		if err := pb.Unmarshal(d, &f); err != nil {
			return false, err
		}
		return f.Code != nil && *f.Code == msg.FailureInvalidProtocol, nil
	}
}

// Connect opens a Cardano session on the Trezor behind link.
func Connect(link wire.Link, o Options) (*Client, error) {
	isTHP, err := usesTHP(link)
	if err != nil {
		return nil, fmt.Errorf("trezor: probing the device: %w", err)
	}
	c := &Client{ui: o.UI, timeout: o.Timeout}
	yes := true
	if !isTHP {
		c.conn = &v1.Conn{Link: link}
		if err := c.Call(msg.TypeInitialize, &msg.Initialize{DeriveCardano: &yes}, msg.TypeFeatures, &c.features); err != nil {
			return nil, err
		}
		return c, nil
	}

	ch, err := thp.Open(link, thp.Options{
		Store: o.Store, UI: o.UI, HostName: o.HostName, AppName: o.AppName,
		TryToUnlock: true, Timeout: o.Timeout,
	})
	if err != nil {
		return nil, err
	}
	c.Channel = ch
	c.conn = &thpSession{ch: ch, session: 0}
	if err := c.Call(msg.TypeGetFeatures, &msg.GetFeatures{}, msg.TypeFeatures, &c.features); err != nil {
		return nil, err
	}
	create := &msg.ThpCreateNewSession{DeriveCardano: &yes}
	if c.features.PassphraseProtection != nil && *c.features.PassphraseProtection {
		if !c.HasCapability(msg.CapabilityPassphraseEntry) {
			return nil, ErrPassphraseNotOnDevice
		}
		create.OnDevice = &yes
	}
	c.conn = &thpSession{ch: ch, session: 1}
	if err := c.Call(msg.TypeThpCreateNewSession, create, msg.TypeSuccess, &msg.Success{}); err != nil {
		return nil, err
	}
	return c, nil
}

// Features returns what the Trezor reported about itself.
func (c *Client) Features() msg.Features { return c.features }

// HasCapability reports whether the Trezor has a capability.
func (c *Client) HasCapability(cap uint32) bool {
	for _, x := range c.features.Capabilities {
		if x == cap {
			return true
		}
	}
	return false
}

// Write sends a message without waiting for an answer.
func (c *Client) Write(reqType uint16, req any) error {
	data, err := pb.Marshal(req)
	if err != nil {
		return err
	}
	return c.conn.Write(reqType, data)
}

// Call sends a message and decodes the answer, which must be of type want,
// into resp.
func (c *Client) Call(reqType uint16, req any, want uint16, resp any) error {
	t, d, err := c.CallRaw(reqType, req)
	if err != nil {
		return err
	}
	if t != want {
		return fmt.Errorf("trezor: unexpected message type %d (want %d)", t, want)
	}
	return pb.Unmarshal(d, resp)
}

// CallRaw sends a message and returns the first answer that is not a
// button request, a passphrase request or a failure, which become errors.
func (c *Client) CallRaw(reqType uint16, req any) (uint16, []byte, error) {
	if err := c.Write(reqType, req); err != nil {
		return 0, nil, err
	}
	return c.ReadRaw()
}

// ReadRaw waits for the next answer, answering button and passphrase
// requests on the way.
func (c *Client) ReadRaw() (uint16, []byte, error) {
	for {
		t, d, err := c.conn.Read(c.timeout)
		if err != nil {
			return 0, nil, err
		}
		switch t {
		case msg.TypeButtonRequest:
			var br msg.ButtonRequest
			if err := pb.Unmarshal(d, &br); err != nil {
				return 0, nil, err
			}
			if c.ui != nil {
				code, name := uint32(0), ""
				if br.Code != nil {
					code = *br.Code
				}
				if br.Name != nil {
					name = *br.Name
				}
				c.ui.ButtonRequest(code, name)
			}
			if err := c.Write(msg.TypeButtonAck, &msg.ButtonAck{}); err != nil {
				return 0, nil, err
			}
		case msg.TypePassphraseRequest:
			if !c.HasCapability(msg.CapabilityPassphraseEntry) {
				return 0, nil, ErrPassphraseNotOnDevice
			}
			yes := true
			if err := c.Write(msg.TypePassphraseAck, &msg.PassphraseAck{OnDevice: &yes}); err != nil {
				return 0, nil, err
			}
		case msg.TypeFailure:
			var f msg.Failure
			if err := pb.Unmarshal(d, &f); err != nil {
				return 0, nil, err
			}
			fe := &Failure{}
			if f.Code != nil {
				fe.Code = *f.Code
			}
			if f.Message != nil {
				fe.Message = *f.Message
			}
			return t, nil, fe
		default:
			return t, d, nil
		}
	}
}

// Cancelled reports whether err means the person cancelled on the Trezor.
func Cancelled(err error) bool {
	var f *Failure
	return errors.As(err, &f) && (f.Code == msg.FailureActionCancelled || f.Code == msg.FailurePinCancelled)
}
