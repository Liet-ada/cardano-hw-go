// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package ledger

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/Liet-ada/cardano-hw-go/internal/cardano"
)

// Instructions of the Cardano app.
const (
	cla                 = 0xd7
	insGetVersion       = 0x00
	insGetSerial        = 0x01
	insGetExtPublicKey  = 0x10
	insDeriveAddress    = 0x11
	insDeriveScriptHash = 0x12
	insSignTx           = 0x21
	insSignOpCert       = 0x22
	insSignCIP36Vote    = 0x23
	insSignMessage      = 0x24
)

// Lengths of what the app returns.
const (
	xpubLength       = 64
	signatureLength  = 64
	pubKeyLength     = 32
	txHashLength     = 32
	auxHashLength    = 32
	scriptHashLength = 28
	serialLength     = 7
	maxAddressLength = 128
)

// Version is the version of the Cardano app.
type Version struct {
	Major, Minor, Patch uint8
	Debug, AppXS        bool
}

// String is the version as ledgerjs writes it, "-NanoS" for the reduced
// app of the Nano S.
func (v Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.AppXS {
		s += "-NanoS"
	}
	return s
}

func (v Version) atLeast(major, minor uint8) bool {
	return v.Major > major || (v.Major == major && v.Minor >= minor)
}

// v7 reports whether the app uses the version 7 command set.
func (v Version) v7() bool { return v.Major <= 7 }

// App is the Cardano app on a Ledger. Every operation starts by asking the
// app for its version, as ledgerjs does, so it always knows which command
// set to use.
type App struct {
	x Exchanger
}

// New talks to the app through x.
func New(x Exchanger) *App { return &App{x: x} }

// Close closes the transport.
func (a *App) Close() error { return a.x.Close() }

// anyLength is the expected length of a response whose length varies.
const anyLength = -1

// send sends one APDU and returns the response data, checking its status
// word and, unless want is anyLength, its length.
func (a *App) send(ins, p1, p2 byte, data []byte, want int) ([]byte, error) {
	if len(data) > 255 {
		return nil, errors.New("APDU too large, likely a bug")
	}
	apdu := append([]byte{cla, ins, p1, p2, byte(len(data))}, data...)
	resp, err := a.x.Exchange(apdu)
	if err != nil {
		return nil, err
	}
	if len(resp) < 2 {
		return nil, assertion("response too short")
	}
	if sw := binary.BigEndian.Uint16(resp[len(resp)-2:]); sw != swOK {
		return nil, StatusError(sw)
	}
	resp = resp[:len(resp)-2]
	if want != anyLength && len(resp) != want {
		return nil, assertion(fmt.Sprintf("unexpected response length: %d instead of %d", len(resp), want))
	}
	return resp, nil
}

// version starts an operation: it asks for the app version, again once
// if the app is still in a former call (which the app then resets).
func (a *App) version() (Version, error) {
	r, err := a.send(insGetVersion, 0, 0, nil, 4)
	var e *Error
	if errors.As(err, &e) && e.Code == swStillInCall {
		r, err = a.send(insGetVersion, 0, 0, nil, 4)
		if errors.As(err, &e) && e.Code == swStillInCall {
			return Version{}, errorBase("Ledger app seems to be in an unexpected irrecoverable state. Please reopen the Cardano app and retry.")
		}
	}
	if err != nil {
		return Version{}, err
	}
	return Version{Major: r[0], Minor: r[1], Patch: r[2], Debug: r[3]&1 != 0, AppXS: r[3]&4 != 0}, nil
}

// GetVersion returns the version of the app.
func (a *App) GetVersion() (Version, error) { return a.version() }

// Serial returns the serial number of the device.
func (a *App) Serial() ([]byte, error) {
	v, err := a.version()
	if err != nil {
		return nil, err
	}
	if err := ensureCompatible(v); err != nil {
		return nil, err
	}
	return a.send(insGetSerial, 0, 0, nil, serialLength)
}

// ExtendedPublicKeys returns the 64-byte extended public keys of paths.
func (a *App) ExtendedPublicKeys(paths []cardano.Path) ([][]byte, error) {
	v, err := a.version()
	if err != nil {
		return nil, err
	}
	if err := ensureExtendedPublicKeysSupported(v, paths); err != nil {
		return nil, err
	}
	var out [][]byte
	for i, p := range paths {
		var r []byte
		switch {
		case !v.v7():
			r, err = a.send(insGetExtPublicKey, 0, 0, pathBytes(p), xpubLength)
		case i == 0:
			data := pathBytes(p)
			if len(paths) > 1 {
				data = append(data, u32(uint32(len(paths)-1))...)
			}
			r, err = a.send(insGetExtPublicKey, 0, 0, data, xpubLength)
		default:
			r, err = a.send(insGetExtPublicKey, 1, 0, pathBytes(p), xpubLength)
		}
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// ShowAddress shows an address on the device.
func (a *App) ShowAddress(p AddressParams) error {
	if err := validateAddress(p); err != nil {
		return err
	}
	v, err := a.version()
	if err != nil {
		return err
	}
	if err := ensureAddressSupported(v, p); err != nil {
		return err
	}
	data, err := addressParamsBytes(p)
	if err != nil {
		return err
	}
	_, err = a.send(insDeriveAddress, 0x02, 0, data, 0)
	return err
}

// DeriveAddress returns an address the device derives, without showing it.
func (a *App) DeriveAddress(p AddressParams) ([]byte, error) {
	if err := validateAddress(p); err != nil {
		return nil, err
	}
	v, err := a.version()
	if err != nil {
		return nil, err
	}
	if err := ensureAddressSupported(v, p); err != nil {
		return nil, err
	}
	data, err := addressParamsBytes(p)
	if err != nil {
		return nil, err
	}
	return a.send(insDeriveAddress, 0x01, 0, data, anyLength)
}

func certWitnessPaths(c Certificate) []cardano.Path {
	switch c.Type {
	case CertStakeRegistrationConway, CertStakeDeregistration, CertStakeDeregistrationConway,
		CertStakeDelegation, CertVoteDelegation:
		if c.StakeCredential.Kind == CredKeyPath {
			return []cardano.Path{c.StakeCredential.Path}
		}
	case CertAuthorizeCommitteeHot, CertResignCommitteeCold:
		if c.ColdCredential.Kind == CredKeyPath {
			return []cardano.Path{c.ColdCredential.Path}
		}
	case CertDRepRegistration, CertDRepDeregistration, CertDRepUpdate:
		if c.DRepCredential.Kind == CredKeyPath {
			return []cardano.Path{c.DRepCredential.Path}
		}
	case CertPoolRegistration:
		var out []cardano.Path
		for _, o := range c.Pool.Owners {
			if o.Kind == CredKeyPath {
				out = append(out, o.Path)
			}
		}
		if c.Pool.PoolKeyPath != nil {
			out = append(out, c.Pool.PoolKeyPath)
		}
		return out
	case CertPoolRetirement:
		return []cardano.Path{c.RetirementPath}
	}
	return nil
}

// WitnessPaths gathers the keys to sign with, each once, in the order
// ledgerjs asks for them.
func WitnessPaths(req *SignRequest) []cardano.Path {
	var paths []cardano.Path
	tx := &req.Tx
	if req.Mode != ModeMultisig {
		for _, in := range tx.Inputs {
			if in.Path != nil {
				paths = append(paths, in.Path)
			}
		}
		for _, c := range tx.Certificates {
			paths = append(paths, certWitnessPaths(c)...)
		}
		for _, w := range tx.Withdrawals {
			if w.Credential.Kind == CredKeyPath {
				paths = append(paths, w.Credential.Path)
			}
		}
		for _, s := range tx.RequiredSigners {
			if s.Path != nil {
				paths = append(paths, s.Path)
			}
		}
		for _, in := range tx.Collateral {
			if in.Path != nil {
				paths = append(paths, in.Path)
			}
		}
		for _, vv := range tx.VotingProcedures {
			switch vv.Voter.Type {
			case VoterCommitteeKeyPath, VoterDRepKeyPath, VoterStakePoolKeyPath:
				paths = append(paths, vv.Voter.Path)
			}
		}
	}
	paths = append(paths, req.AdditionalWitnesses...)
	seen := map[string]bool{}
	var out []cardano.Path
	for _, p := range paths {
		if !seen[p.String()] {
			seen[p.String()] = true
			out = append(out, p)
		}
	}
	return out
}

// SignTx signs a transaction.
func (a *App) SignTx(req *SignRequest) (*SignedTx, error) {
	if err := validateSignRequest(req); err != nil {
		return nil, err
	}
	v, err := a.version()
	if err != nil {
		return nil, err
	}
	if err := ensureSignTxSupported(v, req); err != nil {
		return nil, err
	}
	witnesses := WitnessPaths(req)
	if v.v7() {
		return a.v7SignTx(req, witnesses)
	}
	return a.v8SignTx(req, witnesses)
}

// OperationalCertificate is what the pool cold key signs.
type OperationalCertificate struct {
	KESPublicKey []byte
	KESPeriod    uint64
	IssueCounter uint64
	ColdKeyPath  cardano.Path
}

// SignOperationalCertificate signs an operational certificate with the
// pool cold key.
func (a *App) SignOperationalCertificate(c OperationalCertificate) ([]byte, error) {
	v, err := a.version()
	if err != nil {
		return nil, err
	}
	if err := ensureOperationalCertificateSupported(v); err != nil {
		return nil, err
	}
	data := cat(c.KESPublicKey, u64(c.KESPeriod), u64(c.IssueCounter), pathBytes(c.ColdKeyPath))
	return a.send(insSignOpCert, 0, 0, data, signatureLength)
}

// MessageRequest asks for a CIP-8 message signature.
type MessageRequest struct {
	MessageHex  string // as given, checked as ledgerjs checks it
	SigningPath cardano.Path
	HashPayload bool
	IsASCII     bool
	Address     *AddressParams // nil: the key hash is the address field
}

// SignedMessage is the device's message signature.
type SignedMessage struct {
	Signature, PubKey, AddressField []byte
}

// SignMessage signs a CIP-8 message.
func (a *App) SignMessage(m MessageRequest) (*SignedMessage, error) {
	// in the order ledgerjs parses the request
	if !isHexString(m.MessageHex) {
		return nil, invalidData("CIP-8 message signing: invalid message hex string")
	}
	msg, _ := hex.DecodeString(m.MessageHex)
	if m.Address != nil {
		if err := validateAddress(*m.Address); err != nil {
			return nil, err
		}
	}
	v, err := a.version()
	if err != nil {
		return nil, err
	}
	if err := ensureMessageSigningSupported(v); err != nil {
		return nil, err
	}
	flag := func(b bool) []byte {
		if !v.v7() {
			return included(b)
		}
		if b {
			return u8(1)
		}
		return u8(0)
	}
	init := cat(u32(uint32(len(msg))), pathBytes(m.SigningPath), flag(m.HashPayload), flag(m.IsASCII))
	if m.Address != nil {
		p, err := addressParamsBytes(*m.Address)
		if err != nil {
			return nil, err
		}
		init = append(init, cat(u8(1), p)...)
	} else {
		init = append(init, 2)
	}
	if _, err := a.send(insSignMessage, 0x01, 0, init, 0); err != nil {
		return nil, err
	}
	chunk := func(b []byte) error {
		_, err := a.send(insSignMessage, 0x02, 0, cat(u32(uint32(len(b))), b), 0)
		return err
	}
	if v.v7() {
		first := 99
		if m.IsASCII {
			first = 198
		}
		end := min(len(msg), first)
		if err := chunk(msg[:end]); err != nil {
			return nil, err
		}
		if end < len(msg) && !m.HashPayload {
			return nil, invalidData("CIP-8 message signing: non-hashed message too long")
		}
		for off := end; off < len(msg); {
			e := min(len(msg), off+250)
			if err := chunk(msg[off:e]); err != nil {
				return nil, err
			}
			off = e
		}
	} else {
		for off := 0; off < len(msg); {
			end := min(len(msg), off+250)
			if err := chunk(msg[off:end]); err != nil {
				return nil, err
			}
			off = end
		}
	}
	const prefix = signatureLength + pubKeyLength + 4
	want := anyLength
	if v.v7() {
		want = prefix + maxAddressLength // v7 pads the address field
	}
	r, err := a.send(insSignMessage, 0x03, 0, nil, want)
	if err != nil {
		return nil, err
	}
	if len(r) < prefix {
		return nil, assertion("invalid signMessage response length")
	}
	size := int(binary.BigEndian.Uint32(r[signatureLength+pubKeyLength:]))
	if size == 0 || size > maxAddressLength {
		return nil, assertion("invalid signMessage address field size")
	}
	if !v.v7() && prefix+size != len(r) {
		return nil, assertion("invalid v8 signMessage response length")
	}
	return &SignedMessage{
		Signature:    r[:signatureLength],
		PubKey:       r[signatureLength : signatureLength+pubKeyLength],
		AddressField: r[prefix : prefix+size],
	}, nil
}

// NativeScript is a native script for the device: public keys it owns are
// given as paths.
type NativeScript struct {
	Type     uint8 // 0 pubkey, 1 all, 2 any, 3 n of k, 4 invalid before, 5 invalid hereafter
	KeyPath  cardano.Path
	KeyHash  []byte
	Required uint32
	Scripts  []NativeScript
	Slot     uint64
}

// Display formats of a native script hash.
const (
	DisplayBech32   = 1
	DisplayPolicyID = 2
)

// NativeScriptHash asks the device for a script hash, shown as bech32 or
// policy id.
func (a *App) NativeScriptHash(s NativeScript, display uint8) ([]byte, error) {
	v, err := a.version()
	if err != nil {
		return nil, err
	}
	if err := ensureNativeScriptHashSupported(v); err != nil {
		return nil, err
	}
	v8 := !v.v7()
	send := func(p1 byte, data []byte) error {
		_, err := a.send(insDeriveScriptHash, p1, 0, data, 0)
		return err
	}
	if v8 {
		if err := send(0x00, nil); err != nil {
			return nil, err
		}
	}
	var add func(NativeScript) error
	add = func(s NativeScript) error {
		switch s.Type {
		case 1, 2, 3:
			data := cat(u8(s.Type), u32(uint32(len(s.Scripts))))
			if s.Type == 3 {
				data = append(data, u32(s.Required)...)
			}
			if err := send(0x01, data); err != nil {
				return err
			}
			for _, sub := range s.Scripts {
				if err := add(sub); err != nil {
					return err
				}
			}
			return nil
		case 0:
			var data []byte
			switch {
			case v8 && s.KeyPath != nil:
				data = cat(u8(0), v8Credential(Credential{Kind: CredKeyPath, Path: s.KeyPath}))
			case v8:
				data = cat(u8(0), v8Credential(Credential{Kind: CredKeyHash, Hash: s.KeyHash}))
			case s.KeyPath != nil:
				data = cat(u8(0), u8(1), pathBytes(s.KeyPath))
			default:
				data = cat(u8(0), u8(2), s.KeyHash)
			}
			return send(0x02, data)
		}
		return send(0x02, cat(u8(s.Type), u64(s.Slot)))
	}
	if err := add(s); err != nil {
		return nil, err
	}
	return a.send(insDeriveScriptHash, 0x03, 0, u8(display), scriptHashLength)
}
