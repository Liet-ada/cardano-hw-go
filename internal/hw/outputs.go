// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package hw

import (
	"bytes"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/blake2b"

	"github.com/Liet-ada/cardano-hw-go/internal/cardano"
	"github.com/Liet-ada/cardano-hw-go/internal/cbor"
)

// Errors with cardano-hw-cli's wording.
var (
	ErrInvalidCVoteWeight            = errors.New("Invalid CIP36 vote weight")
	ErrInvalidCIP36AddressType       = errors.New("CIP36 registration address type must be either BASE or REWARD")
	ErrMetadataSerializationMismatch = errors.New("Metadata serialization mismatch")
	ErrInvalidMessageAddress         = errors.New("Cannot derive address parameters in message signing: likely because address signing files are missing")
	ErrInvalidMessageAddressType     = errors.New("Invalid or unsupported address type in message signing")
	ErrMessageAddressSigningFiles    = errors.New("Missing address signing files in message signing")
	ErrMessageAddressMismatch        = errors.New("Message address mismatch: likely because incorrect address signing files were used")
)

// CheckCIP36AddressType accepts the address types a registration may pay to.
func CheckCIP36AddressType(t cardano.AddressType) error {
	if t != cardano.AddrBasePaymentKeyStakeKey && t != cardano.AddrRewardKey {
		return ErrInvalidCIP36AddressType
	}
	return nil
}

// EncodeCIP36Registration builds the registration metadata from the
// device's signature, after checking that the auxiliary data hash the
// device signed is the hash of what we encode.
func EncodeCIP36Registration(r CIP36Params, address, auxDataHash, signature []byte) ([]byte, error) {
	delegations := make([]cbor.Value, len(r.Delegations))
	for i, d := range r.Delegations {
		delegations[i] = cbor.NewArray(cbor.NewBytes(d.VotePublicKey), cbor.NewUint(d.Weight))
	}
	metadata := cbor.NewMap(
		cbor.Entry{Key: cbor.NewUint(61284), Value: cbor.NewMap(
			cbor.Entry{Key: cbor.NewUint(1), Value: cbor.NewArray(delegations...)},
			cbor.Entry{Key: cbor.NewUint(2), Value: cbor.NewBytes(r.StakeSigningFile.PubKey())},
			cbor.Entry{Key: cbor.NewUint(3), Value: cbor.NewBytes(address)},
			cbor.Entry{Key: cbor.NewUint(4), Value: cbor.NewUint(r.Nonce)},
			cbor.Entry{Key: cbor.NewUint(5), Value: cbor.NewUint(r.VotingPurpose)},
		)},
		cbor.Entry{Key: cbor.NewUint(61285), Value: cbor.NewMap(
			cbor.Entry{Key: cbor.NewUint(1), Value: cbor.NewBytes(signature)},
		)},
	)
	// the Mary-era auxiliary data the device hashed: [metadata, []]
	aux := cbor.Encode(cbor.NewArray(metadata, cbor.NewArray()))
	if h := blake2b.Sum256(aux); !bytes.Equal(h[:], auxDataHash) {
		return nil, ErrMetadataSerializationMismatch
	}
	return cbor.Encode(metadata), nil
}

// MessageAddressParams resolves the address of a message signature to the
// wallet's keys.
func MessageAddressParams(m SignMessageParams) (*AddressParams, cardano.Network, error) {
	_, addr, err := cardano.Bech32Decode(m.Address)
	if err != nil || len(addr) == 0 {
		return nil, cardano.Network{}, cardano.ErrInvalidAddress
	}
	network := cardano.Network{NetworkID: uint32(addr[0] & 0x0f), ProtocolMagic: cardano.ProtocolMagicMainnet}
	if len(m.AddressFiles) == 0 {
		return nil, network, ErrMessageAddressSigningFiles
	}
	ap := AddressParamsFor(m.AddressFiles, addr, network)
	if ap == nil {
		return nil, network, ErrInvalidMessageAddress
	}
	switch ap.Type {
	case cardano.AddrBasePaymentKeyStakeKey:
		if ap.PaymentPath == nil || ap.StakePath == nil {
			return nil, network, ErrInvalidMessageAddress
		}
	case cardano.AddrBasePaymentKeyStakeScript, cardano.AddrEnterpriseKey:
		if ap.PaymentPath == nil {
			return nil, network, ErrInvalidMessageAddress
		}
	case cardano.AddrRewardKey:
		if ap.StakePath == nil {
			return nil, network, ErrInvalidMessageAddress
		}
	default:
		return nil, network, ErrInvalidMessageAddressType
	}
	return ap, network, nil
}

// WitnessOutput is the witness file of one key.
func WitnessOutput(era cardano.Era, w Witness) cardano.Envelope {
	var v cbor.Value
	if w.Byron {
		// [2, [pub, signature, chain code, CBOR of empty address attributes]]
		v = cbor.NewArray(cbor.NewUint(2), cbor.NewArray(cbor.NewBytes(w.PubKey), cbor.NewBytes(w.Signature),
			cbor.NewBytes(w.ChainCode), cbor.NewBytes([]byte{0xa0})))
	} else {
		v = cbor.NewArray(cbor.NewUint(0), cbor.NewArray(cbor.NewBytes(w.PubKey), cbor.NewBytes(w.Signature)))
	}
	return cardano.Envelope{Type: cardano.WitnessType(era), Description: "", CBORHex: hex.EncodeToString(cbor.Encode(v))}
}

// SignedOpCert is the CBOR of a signed operational certificate.
func SignedOpCert(kesVKey []byte, kesPeriod uint64, c OpCertCounter, signature []byte) []byte {
	return cbor.Encode(cbor.NewArray(
		cbor.NewArray(cbor.NewBytes(kesVKey), cbor.NewUint(c.Counter), cbor.NewUint(kesPeriod), cbor.NewBytes(signature)),
		cbor.NewBytes(c.PoolColdKey),
	))
}

// OpCertCounterOutput is the issue counter file.
func OpCertCounterOutput(c OpCertCounter) cardano.Envelope {
	return cardano.Envelope{
		Type:        "NodeOperationalCertificateIssueCounter",
		Description: "Next certificate issue number: " + itoa(c.Counter),
		CBORHex:     hex.EncodeToString(cbor.Encode(cbor.NewArray(cbor.NewUint(c.Counter), cbor.NewBytes(c.PoolColdKey)))),
	}
}

func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// SignedMessageOutput is the output file of a message signature, in the
// format of M. Lang's cardano-signer.
type SignedMessageOutput struct {
	MessageHex   string `json:"messageHex"`
	IsHashed     bool   `json:"isHashed"`
	AddressHex   string `json:"addressHex"`
	SignatureHex string `json:"signatureHex"`
	PublicKeyHex string `json:"publicKeyHex"`
	COSESign1Hex string `json:"COSE_Sign1_hex"`
	COSEKeyHex   string `json:"COSE_Key_hex"`
}

// NewSignedMessageOutput builds the COSE structures of a message signature.
func NewSignedMessageOutput(message []byte, hashed bool, s SignedMessage) SignedMessageOutput {
	coseKey := cbor.NewMap(
		cbor.Entry{Key: cbor.NewUint(1), Value: cbor.NewUint(1)},
		cbor.Entry{Key: cbor.NewUint(3), Value: cbor.NewInt(-8)},
		cbor.Entry{Key: cbor.NewInt(-1), Value: cbor.NewUint(6)},
		cbor.Entry{Key: cbor.NewInt(-2), Value: cbor.NewBytes(s.PubKey)},
	)
	protected := cbor.NewMap(
		cbor.Entry{Key: cbor.NewUint(1), Value: cbor.NewInt(-8)},
		cbor.Entry{Key: cbor.NewText("address"), Value: cbor.NewBytes(s.Address)},
	)
	payload := message
	if hashed {
		h, _ := blake2b.New(28, nil)
		h.Write(message)
		payload = h.Sum(nil)
	}
	sign1 := cbor.NewArray(
		cbor.NewBytes(cbor.Encode(protected)),
		cbor.NewMap(cbor.Entry{Key: cbor.NewText("hashed"), Value: cbor.NewBool(hashed)}),
		cbor.NewBytes(payload),
		cbor.NewBytes(s.Signature),
	)
	return SignedMessageOutput{
		MessageHex:   hex.EncodeToString(message),
		IsHashed:     hashed,
		AddressHex:   hex.EncodeToString(s.Address),
		SignatureHex: hex.EncodeToString(s.Signature),
		PublicKeyHex: hex.EncodeToString(s.PubKey),
		COSESign1Hex: hex.EncodeToString(cbor.Encode(sign1)),
		COSEKeyHex:   hex.EncodeToString(cbor.Encode(coseKey)),
	}
}
