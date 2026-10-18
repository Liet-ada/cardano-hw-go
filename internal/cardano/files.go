// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cardano

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Liet-ada/cardano-hw-go/internal/cbor"
	"github.com/Liet-ada/cardano-hw-go/internal/js"
)

// Errors with cardano-hw-cli's wording.
var (
	ErrInvalidFileType      = errors.New("Invalid file type of hw-signing-file")
	ErrInvalidHwSigningFile = errors.New("Invalid file contents of hw-signing-file")
	ErrInvalidTxFile        = errors.New("Invalid file contents of tx-file")
)

// Era is a Cardano era.
type Era string

const (
	EraByron   Era = "Byron"
	EraShelley Era = "Shelley"
	EraAllegra Era = "Allegra"
	EraMary    Era = "Mary"
	EraAlonzo  Era = "Alonzo"
	EraBabbage Era = "Babbage"
	EraConway  Era = "Conway"
)

var eras = []Era{EraByron, EraShelley, EraAllegra, EraMary, EraAlonzo, EraBabbage, EraConway}

var (
	unwitnessedType = map[Era]string{}
	witnessedType   = map[Era]string{}
	signedType      = map[Era]string{
		EraByron: "TxSignedByron", EraShelley: "TxSignedShelley",
	}
	witnessType = map[Era]string{
		EraByron: "TxWitnessByron", EraShelley: "TxWitnessShelley",
	}
	// txEnvelopeEra maps every transaction envelope type to its era.
	txEnvelopeEra = map[string]Era{}
)

func init() {
	for _, e := range eras {
		unwitnessedType[e] = fmt.Sprintf("Unwitnessed Tx %sEra", e)
		witnessedType[e] = fmt.Sprintf("Witnessed Tx %sEra", e)
		if _, ok := signedType[e]; !ok {
			signedType[e] = fmt.Sprintf("Tx %sEra", e)
		}
		if _, ok := witnessType[e]; !ok {
			witnessType[e] = fmt.Sprintf("TxWitness %sEra", e)
		}
	}
	for _, e := range eras {
		txEnvelopeEra[unwitnessedType[e]] = e
		txEnvelopeEra[witnessedType[e]] = e
		txEnvelopeEra[signedType[e]] = e
	}
}

// WitnessType is the envelope type of a witness file of an era.
func WitnessType(e Era) string { return witnessType[e] }

// TxFile is a transaction in a text envelope.
type TxFile struct {
	EnvelopeType string
	Era          Era
	Description  string
	CBORHex      string
	CBOR         []byte
}

// ReadTxFile reads a transaction envelope as cardano-hw-cli's parseTxFile
// does: its type must be a transaction envelope type, its description a
// string and its cborHex one CBOR data item. The bytes are those of
// Buffer.from(cborHex, 'hex'), which stops at the first pair that is not
// hex.
func ReadTxFile(path string) (*TxFile, error) {
	v, err := readJSON(path)
	if err != nil {
		return nil, err
	}
	if v.Nullish() {
		return nil, js.NewTypeError("Cannot destructure property 'type' of 'json' as it is " + v.Name() + ".")
	}
	typ, desc, hexV := v.Get("type"), v.Get("description"), v.Get("cborHex")
	era, ok := txEnvelopeEra[typ.Str]
	if typ.Kind != js.String || !ok || desc.Kind != js.String || !isCBORHex(hexV) {
		return nil, ErrInvalidTxFile
	}
	return &TxFile{typ.Str, era, desc.Str, hexV.Str, js.BufferFromHex(hexV.Str)}, nil
}

// isCBORHex is cardano-hw-cli's isCborHex: a string whose bytes are one
// well-formed data item.
func isCBORHex(v js.Value) bool {
	return v.Kind == js.String && cbor.WellFormed(js.BufferFromHex(v.Str)) == nil
}

// readJSON reads a file and parses it as cardano-hw-cli does, with Node's
// errors.
func readJSON(path string) (js.Value, error) {
	text, err := js.ReadFile(path)
	if err != nil {
		return js.Value{}, err
	}
	return js.ParseJSON(text)
}

// SigningType is the role of a key in a hardware wallet signing file.
type SigningType int

const (
	SigningPayment SigningType = iota
	SigningStake
	SigningDRep
	SigningCommitteeCold
	SigningCommitteeHot
	SigningPoolCold
	SigningMint
	SigningMultiSig
	SigningCIP36Voting
)

// Path labels of key files.
const (
	LabelPayment       = "Payment"
	LabelStake         = "Stake"
	LabelDRep          = "DRep"
	LabelCommitteeCold = "ConstitutionalCommitteeCold"
	LabelCommitteeHot  = "ConstitutionalCommitteeHot"
	LabelPoolCold      = "StakePool"
	LabelCIP36Vote     = "CIP36Vote"
)

// SigningFile is a hardware wallet signing file: a derivation path and its
// extended public key. It holds no secret.
type SigningFile struct {
	Type           SigningType
	Path           Path
	CBORXPubKeyHex string
}

// XPub returns the public key and chain code of the signing file.
func (s SigningFile) XPub() (pub, chainCode []byte, err error) {
	return SplitXPubCBORHex(s.CBORXPubKeyHex)
}

// PubKey returns the public key of the signing file.
func (s SigningFile) PubKey() []byte {
	pub, _, _ := s.XPub()
	return pub
}

// SplitXPubCBORHex splits the CBOR byte string of an extended public key.
func SplitXPubCBORHex(h string) (pub, chainCode []byte, err error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, nil, ErrInvalidHwSigningFile
	}
	v, err := cbor.Decode(b)
	if err != nil || v.Kind != cbor.Bytes || len(v.Bytes) != 64 {
		return nil, nil, ErrInvalidHwSigningFile
	}
	return v.Bytes[:32], v.Bytes[32:], nil
}

// signingTypeFor checks the file type label against the path and returns
// the role of the key.
func signingTypeFor(fileType string, pt PathType) (SigningType, error) {
	expect := func(label string, t SigningType) (SigningType, error) {
		if !strings.HasPrefix(fileType, label) {
			return 0, ErrInvalidFileType
		}
		return t, nil
	}
	switch pt {
	case PathWalletAccountMultisig, PathWalletSpendingKeyMultisig:
		return expect(LabelPayment, SigningMultiSig)
	case PathWalletStakingKeyMultisig:
		return expect(LabelStake, SigningMultiSig)
	case PathWalletAccount, PathWalletSpendingKeyByron, PathWalletSpendingKeyShelley:
		return expect(LabelPayment, SigningPayment)
	case PathWalletStakingKey:
		return expect(LabelStake, SigningStake)
	case PathDRepKey:
		return expect(LabelDRep, SigningDRep)
	case PathCommitteeColdKey:
		return expect(LabelCommitteeCold, SigningCommitteeCold)
	case PathCommitteeHotKey:
		return expect(LabelCommitteeHot, SigningCommitteeHot)
	case PathWalletMintingKey:
		return expect(LabelPayment, SigningMint)
	case PathPoolColdKey:
		return expect(LabelPoolCold, SigningPoolCold)
	case PathCVoteAccount, PathCVoteKey:
		return expect(LabelCIP36Vote, SigningCIP36Voting)
	}
	return 0, ErrInvalidFileType
}

// ReadSigningFile reads a hardware wallet signing file as
// cardano-hw-cli's parseHwSigningFile does: its path, then its type
// against the path, then that cborXPubKeyHex is a string.
func ReadSigningFile(path string) (SigningFile, error) {
	v, err := readJSON(path)
	if err != nil {
		return SigningFile{}, err
	}
	if v.Nullish() {
		return SigningFile{}, js.NewTypeError("Cannot read properties of " + v.Name() + " (reading 'path')")
	}
	pv := v.Get("path")
	if pv.Kind != js.String {
		if pv.Nullish() {
			return SigningFile{}, js.NewTypeError("Cannot read properties of " + pv.Name() + " (reading 'split')")
		}
		return SigningFile{}, js.NewTypeError("path.split is not a function")
	}
	p, err := ParsePath(pv.Str)
	if err != nil {
		return SigningFile{}, err
	}
	typ := v.Get("type")
	if pt := Classify(p); pt != PathInvalid && typ.Kind != js.String {
		if typ.Nullish() {
			return SigningFile{}, js.NewTypeError("Cannot read properties of " + typ.Name() + " (reading 'startsWith')")
		}
		return SigningFile{}, js.NewTypeError("fileTypeMagic.startsWith is not a function")
	}
	t, err := signingTypeFor(typ.Str, Classify(p))
	if err != nil {
		return SigningFile{}, err
	}
	x := v.Get("cborXPubKeyHex")
	if !v.Has("cborXPubKeyHex") || x.Kind != js.String {
		return SigningFile{}, ErrInvalidHwSigningFile
	}
	return SigningFile{t, p, x.Str}, nil
}

// label is the role of a path as written in key file types.
func label(p Path) (string, error) {
	switch Classify(p) {
	case PathWalletSpendingKeyByron, PathWalletSpendingKeyShelley, PathWalletSpendingKeyMultisig, PathWalletMintingKey:
		return LabelPayment, nil
	case PathWalletStakingKey, PathWalletStakingKeyMultisig:
		return LabelStake, nil
	case PathDRepKey:
		return LabelDRep, nil
	case PathCommitteeColdKey:
		return LabelCommitteeCold, nil
	case PathCommitteeHotKey:
		return LabelCommitteeHot, nil
	case PathPoolColdKey:
		return LabelPoolCold, nil
	case PathCVoteKey:
		return LabelCIP36Vote, nil
	}
	return "", errors.New("not implemented")
}

var keyDescriptions = map[PathType][2]string{ // verification key, signing file
	PathWalletSpendingKeyByron:    {"Hardware Payment Verification Key", "Payment Hardware Signing File"},
	PathWalletSpendingKeyShelley:  {"Hardware Payment Verification Key", "Payment Hardware Signing File"},
	PathWalletStakingKey:          {"Hardware Stake Verification Key", "Stake Hardware Signing File"},
	PathDRepKey:                   {"Hardware Delegate Representative Verification Key", "Hardware Delegate Representative Signing File"},
	PathCommitteeColdKey:          {"Hardware Constitutional Committee Cold Verification Key", "Hardware Constitutional Committee Cold Signing File"},
	PathCommitteeHotKey:           {"Hardware Constitutional Committee Hot Verification Key", "Hardware Constitutional Committee Hot Signing File"},
	PathWalletSpendingKeyMultisig: {"Hardware Script Payment Verification Key", "Script Payment Hardware Signing File"},
	PathWalletStakingKeyMultisig:  {"Hardware Script Stake Verification Key", "Script Stake Hardware Signing File"},
	PathWalletMintingKey:          {"Hardware Mint Verification Key", "Mint Hardware Signing File"},
	PathPoolColdKey:               {"Hardware Stake Pool Operator Verification Key", "Stake Pool Hardware Signing File"},
	PathCVoteKey:                  {"Hardware CIP36 Vote Verification Key", "CIP36 Vote Hardware Signing File"},
}

// SigningFileType is the type field of a signing file for a path type.
func SigningFileType(lbl string, pt PathType) string {
	switch pt {
	case PathWalletSpendingKeyByron:
		return lbl + "HWSigningFileByron_ed25519_bip32"
	case PathDRepKey, PathCommitteeColdKey, PathCommitteeHotKey, PathPoolColdKey, PathCVoteAccount, PathCVoteKey:
		return lbl + "HWSigningFile_ed25519"
	}
	return lbl + "HWSigningFileShelley_ed25519"
}

// Envelope is a cardano-cli text envelope.
type Envelope struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	CBORHex     string `json:"cborHex"`
}

// SigningFileOutput is the content of a signing file.
type SigningFileOutput struct {
	Type           string `json:"type"`
	Description    string `json:"description"`
	Path           string `json:"path"`
	CBORXPubKeyHex string `json:"cborXPubKeyHex"`
}

// NewSigningFileOutput builds a signing file from a path and the 64 bytes
// of its extended public key.
func NewSigningFileOutput(xpub []byte, p Path) (SigningFileOutput, error) {
	lbl, err := label(p)
	if err != nil {
		return SigningFileOutput{}, err
	}
	d, ok := keyDescriptions[Classify(p)]
	if !ok {
		return SigningFileOutput{}, errors.New("not implemented")
	}
	return SigningFileOutput{
		Type:           SigningFileType(lbl, Classify(p)),
		Description:    d[1],
		Path:           p.String(),
		CBORXPubKeyHex: hex.EncodeToString(cbor.Encode(cbor.NewBytes(xpub))),
	}, nil
}

// NewVerificationKeyOutput builds a verification key file from an extended
// public key (raw or CBOR, the key is in its last 64 bytes).
func NewVerificationKeyOutput(xpub []byte, p Path) (Envelope, error) {
	lbl, err := label(p)
	if err != nil {
		return Envelope{}, err
	}
	d, ok := keyDescriptions[Classify(p)]
	if !ok {
		return Envelope{}, errors.New("not implemented")
	}
	var t string
	switch Classify(p) {
	case PathDRepKey, PathCommitteeColdKey, PathCommitteeHotKey, PathPoolColdKey, PathCVoteKey, PathCVoteAccount:
		t = lbl + "VerificationKey_ed25519"
	case PathWalletSpendingKeyByron:
		t = lbl + "VerificationKeyByron_ed25519_bip32"
	default:
		t = lbl + "VerificationKeyShelley_ed25519"
	}
	if len(xpub) < 64 {
		return Envelope{}, ErrInvalidHwSigningFile
	}
	pub := xpub[len(xpub)-64 : len(xpub)-32]
	return Envelope{t, d[0], hex.EncodeToString(cbor.Encode(cbor.NewBytes(pub)))}, nil
}

// MarshalOutput formats an output file as cardano-hw-cli does:
// JSON.stringify with four spaces of indentation and no final newline.
func MarshalOutput(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "    ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
