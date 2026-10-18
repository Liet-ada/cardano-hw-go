// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package ledgersim simulates the Cardano app of a Ledger for tests. It
// answers the APDUs of app versions 7 and 8 with keys derived from a test
// mnemonic, keeps a transcript of what it received, and speaks the APDU
// protocol of the Speculos emulator over TCP, so cardano-hw-cli and
// cardano-hw-go can be run against it and their transcripts compared.
//
// It does not rebuild transactions from what it receives: the test tells
// it the body hash to return and sign.
package ledgersim

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/blake2b"

	"github.com/Liet-ada/cardano-hw-go/internal/cardano"
	"github.com/Liet-ada/cardano-hw-go/internal/cbor"
)

// Exchange is an APDU and the response to it, status word included.
type Exchange struct {
	APDU, Response []byte
}

// Sim is a simulated Cardano app.
type Sim struct {
	// Version is the app version: major, minor, patch and flags (1 debug,
	// 4 the reduced Nano S app).
	Version [4]byte
	// Serial is the serial number of the device.
	Serial []byte
	// TxHash is what the app returns as the hash of the transaction body
	// and signs for each witness.
	TxHash []byte
	// Fail, if set, can fail an APDU with the status word it returns
	// (zero: answer normally).
	Fail func(apdu []byte) uint16
	// OnExchange, if set, is called after each exchange.
	OnExchange func(Exchange)

	mu         sync.Mutex
	root       xprv
	transcript []Exchange
	cip36      *cip36State
	msg        *msgState
	script     *scriptBuilder
}

// New simulates an app whose keys come from mnemonic.
func New(mnemonic string, version [4]byte) (*Sim, error) {
	root, err := ledgerMaster(mnemonic, "")
	if err != nil {
		return nil, err
	}
	return &Sim{Version: version, Serial: []byte{1, 2, 3, 4, 5, 6, 7}, TxHash: make([]byte, 32), root: root}, nil
}

// Transcript returns the exchanges so far.
func (s *Sim) Transcript() []Exchange {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Exchange{}, s.transcript...)
}

// XPub returns the extended public key of a path.
func (s *Sim) XPub(p cardano.Path) []byte { return s.root.derive(p).xpub() }

// Close does nothing; it makes Sim a transport.
func (s *Sim) Close() error { return nil }

// Exchange answers one APDU.
func (s *Sim) Exchange(apdu []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	resp := s.answer(apdu)
	e := Exchange{APDU: append([]byte{}, apdu...), Response: resp}
	s.transcript = append(s.transcript, e)
	if s.OnExchange != nil {
		s.OnExchange(e)
	}
	return resp, nil
}

func (s *Sim) v8() bool { return s.Version[0] >= 8 }

// Status words the simulator answers with.
const (
	swOK            = 0x9000
	swInvalidDataV7 = 0x6e07
	swParsingV8     = 0x6b01
	swNotSupported  = 0x6d00 // INS not supported
	swCLA           = 0x6e00
)

func status(sw uint16, data []byte) []byte {
	return binary.BigEndian.AppendUint16(append([]byte{}, data...), sw)
}

func (s *Sim) invalid() []byte {
	if s.v8() {
		return status(swParsingV8, nil)
	}
	return status(swInvalidDataV7, nil)
}

var errShort = errors.New("short data")

// reader reads the fields of an APDU.
type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil || len(r.b) < n {
		r.err = errShort
		return make([]byte, n)
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}
func (r *reader) u8() uint8   { return r.take(1)[0] }
func (r *reader) u16() uint16 { return binary.BigEndian.Uint16(r.take(2)) }
func (r *reader) u32() uint32 { return binary.BigEndian.Uint32(r.take(4)) }
func (r *reader) u64() uint64 { return binary.BigEndian.Uint64(r.take(8)) }
func (r *reader) path() cardano.Path {
	n := int(r.u8())
	if n > 10 {
		r.err = errors.New("path too long")
		return nil
	}
	p := make(cardano.Path, n)
	for i := range p {
		p[i] = r.u32()
	}
	return p
}
func (r *reader) done() error {
	if r.err == nil && len(r.b) > 0 {
		return errors.New("extra data")
	}
	return r.err
}

func (s *Sim) answer(apdu []byte) []byte {
	if len(apdu) < 5 || int(apdu[4]) != len(apdu)-5 {
		return s.invalid()
	}
	if apdu[0] != 0xd7 {
		return status(swCLA, nil)
	}
	if s.Fail != nil {
		if sw := s.Fail(apdu); sw != 0 {
			return status(sw, nil)
		}
	}
	ins, p1, p2, data := apdu[1], apdu[2], apdu[3], apdu[5:]
	r := &reader{b: data}
	var out []byte
	var err error
	switch ins {
	case 0x00:
		out = s.Version[:]
	case 0x01:
		out = s.Serial
	case 0x10:
		out, err = s.xpub(p1, r)
	case 0x11:
		out, err = s.address(p1, r)
	case 0x12:
		out, err = s.nativeScript(p1, r)
	case 0x21:
		if s.v8() {
			out, err = s.signTxV8(p1, p2, r)
		} else {
			out, err = s.signTxV7(p1, p2, r)
		}
	case 0x22:
		out, err = s.opCert(r)
	case 0x24:
		out, err = s.signMessage(p1, r)
	default:
		return status(swNotSupported, nil)
	}
	if err != nil {
		return s.invalid()
	}
	return status(swOK, out)
}

func (s *Sim) xpub(p1 byte, r *reader) ([]byte, error) {
	p := r.path()
	if !s.v8() && p1 == 0 && len(r.b) == 4 {
		r.u32() // how many more keys follow
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return s.XPub(p), nil
}

func (s *Sim) keyHash(p cardano.Path) []byte { return cardano.KeyHash(s.root.derive(p).public()) }

// readAddress reads address parameters and derives the address.
func (s *Sim) readAddress(r *reader) []byte {
	t := cardano.AddressType(r.u8())
	if t == cardano.AddrByron {
		magic := r.u32()
		p := r.path()
		if r.u8() != 0x11 {
			r.err = errors.New("staking in a Byron address")
		}
		return cardano.ByronAddress(s.XPub(p), magic)
	}
	network := r.u8()
	var payment []byte
	switch t {
	case cardano.AddrBasePaymentKeyStakeKey, cardano.AddrBasePaymentKeyStakeScript,
		cardano.AddrPointerKey, cardano.AddrEnterpriseKey:
		payment = s.keyHash(r.path())
	case cardano.AddrBasePaymentScriptStakeKey, cardano.AddrBasePaymentScriptStakeScript,
		cardano.AddrPointerScript, cardano.AddrEnterpriseScript:
		payment = r.take(28)
	}
	var staking []byte
	switch r.u8() {
	case 0x11:
	case 0x22:
		staking = s.keyHash(r.path())
	case 0x33, 0x55:
		staking = r.take(28)
	case 0x44:
		for range 3 {
			staking = appendVarint(staking, r.u32())
		}
	default:
		r.err = errors.New("unknown staking choice")
	}
	return append(append([]byte{byte(t)<<4 | network&0x0f}, payment...), staking...)
}

func appendVarint(b []byte, n uint32) []byte {
	var groups []byte
	for {
		groups = append([]byte{byte(n & 0x7f)}, groups...)
		n >>= 7
		if n == 0 {
			break
		}
	}
	for i := 0; i < len(groups)-1; i++ {
		groups[i] |= 0x80
	}
	return append(b, groups...)
}

func (s *Sim) address(p1 byte, r *reader) ([]byte, error) {
	addr := s.readAddress(r)
	if err := r.done(); err != nil {
		return nil, err
	}
	switch p1 {
	case 0x01:
		return addr, nil
	case 0x02:
		return nil, nil
	}
	return nil, fmt.Errorf("unknown p1 %d", p1)
}

// scriptBuilder rebuilds a native script from its parts.
type scriptBuilder struct {
	root  *cardano.NativeScript
	stack []*openScript
}

type openScript struct {
	s    *cardano.NativeScript
	left int
}

func (b *scriptBuilder) add(n cardano.NativeScript, children int) error {
	var ref *cardano.NativeScript
	if len(b.stack) == 0 {
		if b.root != nil {
			return errors.New("script already complete")
		}
		b.root = &n
		ref = b.root
	} else {
		top := b.stack[len(b.stack)-1]
		top.s.Scripts = append(top.s.Scripts, n)
		ref = &top.s.Scripts[len(top.s.Scripts)-1]
		top.left--
	}
	// pop complete scripts, then open this one if it has children
	for len(b.stack) > 0 && b.stack[len(b.stack)-1].left == 0 {
		b.stack = b.stack[:len(b.stack)-1]
	}
	if children > 0 {
		b.stack = append(b.stack, &openScript{s: ref, left: children})
	}
	return nil
}

func (s *Sim) nativeScript(p1 byte, r *reader) ([]byte, error) {
	if s.script == nil || p1 == 0x00 {
		s.script = &scriptBuilder{}
	}
	b := s.script
	switch p1 {
	case 0x00:
		return nil, r.done()
	case 0x01:
		t := cardano.NativeScriptType(r.u8())
		n := int(r.u32())
		sc := cardano.NativeScript{Type: t}
		if t == cardano.ScriptNOfK {
			sc.Required = uint64(r.u32())
		}
		if err := r.done(); err != nil {
			return nil, err
		}
		if t < cardano.ScriptAll || t > cardano.ScriptNOfK {
			return nil, errors.New("not a complex script")
		}
		sc.Scripts = []cardano.NativeScript{}
		return nil, b.add(sc, n)
	case 0x02:
		t := cardano.NativeScriptType(r.u8())
		sc := cardano.NativeScript{Type: t}
		switch t {
		case cardano.ScriptPubKey:
			kind := r.u8()
			switch {
			case s.v8() && kind == 2, !s.v8() && kind == 1:
				sc.KeyHash = s.keyHash(r.path())
			case s.v8() && kind == 0, !s.v8() && kind == 2:
				sc.KeyHash = r.take(28)
			default:
				return nil, errors.New("unknown key kind")
			}
		case cardano.ScriptInvalidBefore, cardano.ScriptInvalidHereafter:
			sc.Slot = r.u64()
		default:
			return nil, errors.New("not a simple script")
		}
		if err := r.done(); err != nil {
			return nil, err
		}
		return nil, b.add(sc, 0)
	case 0x03:
		r.u8() // display format
		if err := r.done(); err != nil {
			return nil, err
		}
		s.script = nil
		if b.root == nil || len(b.stack) > 0 {
			return nil, errors.New("script incomplete")
		}
		return b.root.Hash(), nil
	}
	return nil, fmt.Errorf("unknown p1 %d", p1)
}

func (s *Sim) opCert(r *reader) ([]byte, error) {
	kes := r.take(32)
	period := r.u64()
	counter := r.u64()
	p := r.path()
	if err := r.done(); err != nil {
		return nil, err
	}
	// the signable part of an operational certificate: the KES key, then
	// the counter and the period as big-endian 64-bit numbers
	msg := binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(append([]byte{}, kes...), counter), period)
	return s.root.derive(p).sign(msg), nil
}

// cip36State gathers a CIP-36 registration.
type cip36State struct {
	delegations []cbor.Value
	left        int
	stakingPath cardano.Path
	address     []byte
	nonce       uint64
	purpose     uint64
}

// finish signs the registration: the device signs the hash of the
// registration map and returns the hash of the auxiliary data that holds
// it with the signature.
func (s *Sim) finishCIP36() []byte {
	c := s.cip36
	s.cip36 = nil
	stake := s.root.derive(c.stakingPath)
	payload := cbor.NewMap(
		cbor.Entry{Key: cbor.NewUint(1), Value: cbor.NewArray(c.delegations...)},
		cbor.Entry{Key: cbor.NewUint(2), Value: cbor.NewBytes(stake.public())},
		cbor.Entry{Key: cbor.NewUint(3), Value: cbor.NewBytes(c.address)},
		cbor.Entry{Key: cbor.NewUint(4), Value: cbor.NewUint(c.nonce)},
		cbor.Entry{Key: cbor.NewUint(5), Value: cbor.NewUint(c.purpose)},
	)
	registration := cbor.Encode(cbor.NewMap(cbor.Entry{Key: cbor.NewUint(61284), Value: payload}))
	h := blake2b.Sum256(registration)
	sig := stake.sign(h[:])
	metadata := cbor.NewMap(
		cbor.Entry{Key: cbor.NewUint(61284), Value: payload},
		cbor.Entry{Key: cbor.NewUint(61285), Value: cbor.NewMap(cbor.Entry{Key: cbor.NewUint(1), Value: cbor.NewBytes(sig)})},
	)
	aux := blake2b.Sum256(cbor.Encode(cbor.NewArray(metadata, cbor.NewArray())))
	return append(aux[:], sig...)
}

func (s *Sim) voteKey(r *reader, keyKind, pathKind uint8) []byte {
	switch r.u8() {
	case keyKind:
		return r.take(32)
	case pathKind:
		return s.root.derive(r.path()).public()
	}
	r.err = errors.New("unknown vote key kind")
	return nil
}

func (s *Sim) delegation(r *reader, keyKind, pathKind uint8) error {
	key := s.voteKey(r, keyKind, pathKind)
	weight := r.u32()
	if err := r.done(); err != nil {
		return err
	}
	if s.cip36 == nil || s.cip36.left == 0 {
		return errors.New("unexpected delegation")
	}
	s.cip36.delegations = append(s.cip36.delegations, cbor.NewArray(cbor.NewBytes(key), cbor.NewUint(uint64(weight))))
	s.cip36.left--
	return nil
}

func (s *Sim) witness(r *reader) ([]byte, error) {
	p := r.path()
	if err := r.done(); err != nil {
		return nil, err
	}
	return s.root.derive(p).sign(s.TxHash), nil
}

func (s *Sim) signTxV7(p1, p2 byte, r *reader) ([]byte, error) {
	switch p1 {
	case 0x01:
		s.cip36 = nil
	case 0x08:
		switch p2 {
		case 0x00:
			if r.u8() == 1 {
				s.cip36 = &cip36State{}
			}
		case 0x36:
			if s.cip36 == nil || r.u8() != 2 {
				return nil, errors.New("not a CIP-36 registration")
			}
			s.cip36.left = int(r.u32())
		case 0x37:
			return nil, s.delegation(r, 1, 2)
		case 0x31:
			s.cip36.stakingPath = r.path()
		case 0x32:
			switch r.u8() {
			case 1:
				s.cip36.address = r.take(int(r.u32()))
			case 2:
				s.cip36.address = s.readAddress(r)
			default:
				return nil, errors.New("unknown destination")
			}
		case 0x33:
			s.cip36.nonce = r.u64()
		case 0x35:
			if r.u8() == 2 {
				s.cip36.purpose = r.u64()
			}
		case 0x34:
			if s.cip36 == nil || s.cip36.left != 0 {
				return nil, errors.New("registration incomplete")
			}
			return s.finishCIP36(), r.done()
		}
		return nil, r.err
	case 0x0a:
		return s.TxHash, r.done()
	case 0x0f:
		return s.witness(r)
	}
	return nil, nil
}

func (s *Sim) signTxV8(p1, p2 byte, r *reader) ([]byte, error) {
	switch p1 {
	case 0x10:
		s.cip36 = nil
	case 0x13:
		switch p2 {
		case 0x36:
			if r.u8() != 2 {
				return nil, errors.New("not a CIP-36 registration")
			}
			c := &cip36State{left: int(r.u16())}
			if r.u8() != 2 {
				return nil, errors.New("staking key not a path")
			}
			c.stakingPath = r.path()
			switch r.u8() {
			case 1:
				c.address = r.take(int(r.u16()))
			case 2:
				c.address = s.readAddress(r)
			default:
				return nil, errors.New("unknown destination")
			}
			c.nonce = r.u64()
			c.purpose = r.u64()
			s.cip36 = c
			if c.left == 0 {
				key := s.voteKey(r, 0, 2)
				c.delegations = []cbor.Value{cbor.NewBytes(key)}
				if err := r.done(); err != nil {
					return nil, err
				}
				return s.finishCIP36(), nil
			}
			return nil, r.done()
		case 0x37:
			if err := s.delegation(r, 0, 2); err != nil {
				return nil, err
			}
			if s.cip36.left == 0 {
				return s.finishCIP36(), nil
			}
		}
		return nil, r.err
	case 0x12:
		return s.TxHash, nil
	case 0x0f:
		return s.witness(r)
	}
	return nil, nil
}

// msgState gathers a CIP-8 message.
type msgState struct {
	size    int
	path    cardano.Path
	hashed  bool
	address []byte
	data    []byte
}

func (s *Sim) signMessage(p1 byte, r *reader) ([]byte, error) {
	yes := byte(1)
	if s.v8() {
		yes = 2
	}
	switch p1 {
	case 0x01:
		m := &msgState{size: int(r.u32()), path: r.path()}
		m.hashed = r.u8() == yes
		r.u8() // ASCII display
		switch r.u8() {
		case 1:
			m.address = s.readAddress(r)
		case 2:
			m.address = s.keyHash(m.path)
		default:
			return nil, errors.New("unknown address field type")
		}
		if err := r.done(); err != nil {
			return nil, err
		}
		s.msg = m
		return nil, nil
	case 0x02:
		n := int(r.u32())
		chunk := r.take(n)
		if err := r.done(); err != nil || s.msg == nil {
			return nil, errors.New("bad chunk")
		}
		s.msg.data = append(s.msg.data, chunk...)
		return nil, nil
	case 0x03:
		m := s.msg
		s.msg = nil
		if m == nil || len(m.data) != m.size {
			return nil, errors.New("message incomplete")
		}
		payload := m.data
		if m.hashed {
			h, _ := blake2b.New(28, nil)
			h.Write(m.data)
			payload = h.Sum(nil)
		}
		protected := cbor.Encode(cbor.NewMap(
			cbor.Entry{Key: cbor.NewUint(1), Value: cbor.NewInt(-8)},
			cbor.Entry{Key: cbor.NewText("address"), Value: cbor.NewBytes(m.address)},
		))
		toSign := cbor.Encode(cbor.NewArray(cbor.NewText("Signature1"), cbor.NewBytes(protected), cbor.NewBytes(nil), cbor.NewBytes(payload)))
		k := s.root.derive(m.path)
		out := append(k.sign(toSign), k.public()...)
		out = binary.BigEndian.AppendUint32(out, uint32(len(m.address)))
		out = append(out, m.address...)
		if !s.v8() {
			out = append(out, make([]byte, 128-len(m.address))...)
		}
		return out, nil
	}
	return nil, fmt.Errorf("unknown p1 %d", p1)
}

// Serve answers Speculos APDU connections on l until it is closed.
func (s *Sim) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go s.serveConn(c)
	}
}

func (s *Sim) serveConn(c net.Conn) {
	defer c.Close()
	for {
		var head [4]byte
		if _, err := io.ReadFull(c, head[:]); err != nil {
			return
		}
		apdu := make([]byte, binary.BigEndian.Uint32(head[:]))
		if _, err := io.ReadFull(c, apdu); err != nil {
			return
		}
		resp, _ := s.Exchange(apdu)
		out := binary.BigEndian.AppendUint32(nil, uint32(len(resp)-2))
		if _, err := c.Write(append(out, resp...)); err != nil {
			return
		}
	}
}
