// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package thp implements the host side of the Trezor Host Protocol (THP),
// which the Trezor Safe 7 and newer firmware require: an encrypted channel
// set up with a Noise handshake, paired once with a code the Trezor shows,
// and reopened later with a credential the Trezor issues.
package thp

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Liet-ada/cardano-hw-go/internal/trezor/msg"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/pb"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/wire"
)

// Credential lets a host reopen a channel with a Trezor without pairing
// again. It holds no key of the wallet: every action still needs the
// person's confirmation on the Trezor.
type Credential struct {
	TrezorStaticPublicKey []byte
	HostStaticPrivateKey  []byte
	Credential            []byte
}

// Store keeps the credentials of the Trezors this host paired with.
type Store interface {
	Credentials() ([]Credential, error)
	Save(Credential) error
}

// PairingInfo identifies a pairing in progress; the emulator's debug link
// uses it to tell the code.
type PairingInfo struct {
	ChannelID     uint16
	HandshakeHash []byte
}

// UI is how the channel talks to the person.
type UI interface {
	// PairingCode asks for the six-digit code the Trezor shows.
	PairingCode(PairingInfo) (string, error)
	// ButtonRequest tells that the Trezor waits for the person.
	ButtonRequest(code uint32, name string)
}

// Options configure Open.
type Options struct {
	Store    Store
	UI       UI
	HostName string // shown on the Trezor when pairing
	AppName  string
	// TryToUnlock asks a locked Trezor to show its PIN entry instead of
	// failing the handshake.
	TryToUnlock bool
	// Timeout bounds each wait for the Trezor, which may wait for the
	// person; zero waits without limit.
	Timeout time.Duration
}

// Channel is an open, encrypted THP channel.
type Channel struct {
	tr            *transport
	keys          *cipherState
	props         msg.ThpDeviceProperties
	handshakeHash []byte
	timeout       time.Duration
	ui            UI
	// Paired tells whether the channel opened with a credential.
	Paired bool
	// Autoconnect tells whether the Trezor reused a cached channel and
	// asked no confirmation.
	Autoconnect bool
}

// ErrPairingCode reports a code that does not match the Trezor's.
var ErrPairingCode = errors.New("thp: the pairing code does not match the one on the Trezor")

// FailureError is a Failure message from the Trezor.
type FailureError struct {
	Code    uint32
	Message string
}

func (e *FailureError) Error() string {
	return fmt.Sprintf("Trezor failure %d: %s", e.Code, e.Message)
}

// Open allocates a channel on the Trezor behind link, runs the handshake,
// and pairs with the Trezor if this host has no credential for it.
func Open(link wire.Link, o Options) (*Channel, error) {
	tr, propsRaw, err := allocateChannel(link)
	if err != nil {
		return nil, err
	}
	c := &Channel{tr: tr, timeout: o.Timeout, ui: o.UI}
	if err := pb.Unmarshal(propsRaw, &c.props); err != nil {
		return nil, fmt.Errorf("thp: device properties: %w", err)
	}

	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	hs := newHandshake(propsRaw, eph, o.TryToUnlock)
	if err := tr.send(ctrlHandshakeInitReq, hs.initiationRequest()); err != nil {
		return nil, err
	}
	m, err := tr.receive(o.Timeout)
	if err != nil {
		return nil, err
	}
	if dataType(m.ctrl) != ctrlHandshakeInitResp {
		return nil, fmt.Errorf("thp: unexpected message %#x in the handshake", m.ctrl)
	}
	if err := hs.readInitiationResponse(m.payload); err != nil {
		return nil, err
	}

	var hostStatic *ecdh.PrivateKey
	var credential []byte
	if o.Store != nil {
		creds, err := o.Store.Credentials()
		if err != nil {
			return nil, err
		}
		for _, cr := range creds {
			if hs.matches(cr.TrezorStaticPublicKey) {
				if hostStatic, err = ecdh.X25519().NewPrivateKey(cr.HostStaticPrivateKey); err != nil {
					return nil, err
				}
				credential = cr.Credential
				break
			}
		}
	}
	if hostStatic == nil {
		if hostStatic, err = ecdh.X25519().GenerateKey(rand.Reader); err != nil {
			return nil, err
		}
	}
	payload, err := pb.Marshal(&msg.ThpHandshakeCompletionReqNoisePayload{HostPairingCredential: credential})
	if err != nil {
		return nil, err
	}
	req, err := hs.completionRequest(hostStatic, payload)
	if err != nil {
		return nil, err
	}
	if err := tr.send(ctrlHandshakeCompReq, req); err != nil {
		return nil, err
	}
	if m, err = tr.receive(o.Timeout); err != nil {
		return nil, err
	}
	if dataType(m.ctrl) != ctrlHandshakeCompResp {
		return nil, fmt.Errorf("thp: unexpected message %#x in the handshake", m.ctrl)
	}
	state, keys, err := hs.readCompletionResponse(m.payload)
	if err != nil {
		return nil, err
	}
	c.keys, c.handshakeHash = keys, hs.handshakeHash()

	switch state {
	case stateUnpaired:
		if err := c.pair(o, hs, hostStatic); err != nil {
			return nil, err
		}
	case statePaired, statePairedAutoconnect:
		c.Paired, c.Autoconnect = true, state == statePairedAutoconnect
	}
	if _, err := c.call(0, msg.TypeThpEndRequest, &msg.ThpEndRequest{}, msg.TypeThpEndResponse, &msg.ThpEndResponse{}); err != nil {
		return nil, err
	}
	return c, nil
}

// DeviceProperties returns what the Trezor told about itself.
func (c *Channel) DeviceProperties() msg.ThpDeviceProperties { return c.props }

// ChannelID returns the id of the channel.
func (c *Channel) ChannelID() uint16 { return c.tr.cid }

// HandshakeHash returns the hash the handshake ended with.
func (c *Channel) HandshakeHash() []byte { return c.handshakeHash }

// Write sends an application message in a session.
func (c *Channel) Write(session byte, msgType uint16, data []byte) error {
	pt := append([]byte{session, byte(msgType >> 8), byte(msgType)}, data...)
	return c.tr.send(ctrlEncryptedTransport, c.keys.encrypt(pt))
}

// Read returns the next application message, waiting up to timeout (zero
// waits without limit).
func (c *Channel) Read(timeout time.Duration) (session byte, msgType uint16, data []byte, err error) {
	m, err := c.tr.receive(timeout)
	if err != nil {
		return 0, 0, nil, err
	}
	if dataType(m.ctrl) != ctrlEncryptedTransport {
		return 0, 0, nil, fmt.Errorf("thp: unexpected message %#x on an open channel", m.ctrl)
	}
	pt, err := c.keys.decrypt(m.payload)
	if err != nil {
		return 0, 0, nil, err
	}
	if len(pt) < 3 {
		return 0, 0, nil, errors.New("thp: application message too short")
	}
	return pt[0], uint16(pt[1])<<8 | uint16(pt[2]), pt[3:], nil
}

// call sends a message in a session and returns the answer of type want,
// acknowledging button requests on the way.
func (c *Channel) call(session byte, reqType uint16, req any, want uint16, resp any) (uint16, error) {
	data, err := pb.Marshal(req)
	if err != nil {
		return 0, err
	}
	if err := c.Write(session, reqType, data); err != nil {
		return 0, err
	}
	for {
		s, t, d, err := c.Read(c.timeout)
		if err != nil {
			return 0, err
		}
		if s != session {
			continue
		}
		switch t {
		case want:
			return t, pb.Unmarshal(d, resp)
		case msg.TypeButtonRequest:
			var br msg.ButtonRequest
			if err := pb.Unmarshal(d, &br); err != nil {
				return 0, err
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
			if err := c.Write(session, msg.TypeButtonAck, nil); err != nil {
				return 0, err
			}
		case msg.TypeFailure:
			var f msg.Failure
			if err := pb.Unmarshal(d, &f); err != nil {
				return 0, err
			}
			fe := &FailureError{}
			if f.Code != nil {
				fe.Code = *f.Code
			}
			if f.Message != nil {
				fe.Message = *f.Message
			}
			return t, fe
		default:
			return t, fmt.Errorf("thp: unexpected message type %d", t)
		}
	}
}

func supports(methods []uint32, m uint32) bool {
	for _, x := range methods {
		if x == m {
			return true
		}
	}
	return false
}

// pair runs CodeEntry pairing and asks the Trezor for a credential.
func (c *Channel) pair(o Options, hs *handshake, hostStatic *ecdh.PrivateKey) error {
	if !supports(c.props.PairingMethods, msg.PairingCodeEntry) {
		return errors.New("thp: the Trezor does not offer pairing with a code")
	}
	if o.UI == nil || o.Store == nil {
		return errors.New("thp: this host is not paired with the Trezor; pair it first in a terminal")
	}
	if _, err := c.call(0, msg.TypeThpPairingRequest, &msg.ThpPairingRequest{HostName: o.HostName, AppName: o.AppName},
		msg.TypeThpPairingRequestApproved, &msg.ThpPairingRequestApproved{}); err != nil {
		return err
	}
	var commit msg.ThpCodeEntryCommitment
	if _, err := c.call(0, msg.TypeThpSelectMethod, &msg.ThpSelectMethod{SelectedPairingMethod: msg.PairingCodeEntry},
		msg.TypeThpCodeEntryCommitment, &commit); err != nil {
		return err
	}
	challenge := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}
	var cpace msg.ThpCodeEntryCpaceTrezor
	if _, err := c.call(0, msg.TypeThpCodeEntryChallenge, &msg.ThpCodeEntryChallenge{Challenge: challenge},
		msg.TypeThpCodeEntryCpaceTrezor, &cpace); err != nil {
		return err
	}

	code, err := o.UI.PairingCode(PairingInfo{ChannelID: c.tr.cid, HandshakeHash: c.handshakeHash})
	if err != nil {
		return err
	}
	code = strings.TrimSpace(code)
	n, err := strconv.Atoi(code)
	if err != nil || n < 0 || n > 999999 || len(code) > 6 {
		return errors.New("thp: the pairing code has six digits")
	}
	code = fmt.Sprintf("%06d", n)

	hostPriv := make([]byte, 32)
	if _, err := rand.Read(hostPriv); err != nil {
		return err
	}
	hostPub, tag, err := cpaceHost(code, c.handshakeHash, cpace.CpaceTrezorPublicKey, hostPriv)
	if err != nil {
		return err
	}
	var secret msg.ThpCodeEntrySecret
	_, err = c.call(0, msg.TypeThpCodeEntryCpaceHostTag, &msg.ThpCodeEntryCpaceHostTag{CpaceHostPublicKey: hostPub, Tag: tag},
		msg.TypeThpCodeEntrySecret, &secret)
	var fe *FailureError
	if errors.As(err, &fe) {
		return fmt.Errorf("%w (%v)", ErrPairingCode, err)
	}
	if err != nil {
		return err
	}
	// the Trezor proves it committed to its secret before the challenge
	commitment := sha256.Sum256(secret.Secret)
	if subtle.ConstantTimeCompare(commitment[:], commit.Commitment) != 1 {
		return errors.New("thp: the Trezor's secret does not match its commitment")
	}
	if fmt.Sprintf("%06d", codeEntryCode(c.handshakeHash, secret.Secret, challenge)) != code {
		return ErrPairingCode
	}

	var cred msg.ThpCredentialResponse
	if _, err := c.call(0, msg.TypeThpCredentialRequest, &msg.ThpCredentialRequest{HostStaticPublicKey: hostStatic.PublicKey().Bytes()},
		msg.TypeThpCredentialResponse, &cred); err != nil {
		return err
	}
	if len(cred.TrezorStaticPublicKey) != 32 || len(cred.Credential) == 0 {
		return errors.New("thp: invalid credential from the Trezor")
	}
	// the key the credential names must be the one behind the handshake
	if !hs.matches(cred.TrezorStaticPublicKey) {
		return errors.New("thp: the credential names another Trezor than the handshake")
	}
	return o.Store.Save(Credential{
		TrezorStaticPublicKey: cred.TrezorStaticPublicKey,
		HostStaticPrivateKey:  hostStatic.Bytes(),
		Credential:            cred.Credential,
	})
}
