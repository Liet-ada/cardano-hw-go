// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package hw is the part of signing that does not depend on the device: the
// interface every hardware wallet implements, the choice of signing mode,
// the checks before and after witnessing, and the files that result. It
// follows cardano-hw-cli's crypto providers.
package hw

import (
	"errors"

	"github.com/Liet-ada/cardano-hw-go/internal/cardano"
	"github.com/Liet-ada/cardano-hw-go/internal/tx"
)

// DerivationType selects how Trezor derives Cardano keys from the seed.
type DerivationType int

const (
	DerivationDefault      DerivationType = iota // ICARUS_TREZOR on Trezor
	DerivationLedger                             // LEDGER
	DerivationIcarus                             // ICARUS
	DerivationIcarusTrezor                       // ICARUS_TREZOR
)

// ErrInvalidDerivationType is cardano-hw-cli's error for an unknown type.
var ErrInvalidDerivationType = errors.New("Invalid derivation type")

// ParseDerivationType reads LEDGER, ICARUS or ICARUS_TREZOR.
func ParseDerivationType(s string) (DerivationType, error) {
	switch s {
	case "":
		return DerivationDefault, nil
	case "LEDGER":
		return DerivationLedger, nil
	case "ICARUS":
		return DerivationIcarus, nil
	case "ICARUS_TREZOR":
		return DerivationIcarusTrezor, nil
	}
	return 0, ErrInvalidDerivationType
}

// SigningMode is how a device signs a transaction; it decides what the
// device shows and allows.
type SigningMode int

const (
	SigningOrdinary SigningMode = iota
	SigningPoolRegistrationAsOwner
	SigningPoolRegistrationAsOperator
	SigningMultisig
	SigningPlutus
	SigningUnrestricted
)

func (m SigningMode) String() string {
	return [...]string{"ORDINARY_TRANSACTION", "POOL_REGISTRATION_AS_OWNER", "POOL_REGISTRATION_AS_OPERATOR",
		"MULTISIG_TRANSACTION", "PLUTUS_TRANSACTION", "UNRESTRICTED"}[m]
}

// ShowAddressParams describe an address to show on the device.
type ShowAddressParams struct {
	PaymentPath       cardano.Path
	PaymentScriptHash []byte
	StakingPath       cardano.Path
	StakingScriptHash []byte
	Address           string
	DerivationType    DerivationType
}

// TxSigningParams are what a device needs to witness a transaction.
type TxSigningParams struct {
	Mode           SigningMode
	Tx             *tx.Transaction
	BodyHash       []byte
	SigningFiles   []cardano.SigningFile
	Network        cardano.Network
	Era            cardano.Era
	DerivationType DerivationType
}

// Witness is a signature of the transaction body by one key.
type Witness struct {
	Path      cardano.Path
	Byron     bool
	PubKey    []byte
	Signature []byte
	ChainCode []byte // Byron witnesses only
}

// OpCertCounter is the content of an operational certificate issue counter.
type OpCertCounter struct {
	Counter     uint64
	PoolColdKey []byte
}

// VoteDelegation delegates CIP-36 voting power to a vote key.
type VoteDelegation struct {
	VotePublicKey []byte
	Weight        uint64
}

// CIP36Params are the parameters of a CIP-36 vote registration.
type CIP36Params struct {
	Delegations         []VoteDelegation
	StakeSigningFile    cardano.SigningFile
	PaymentAddress      string
	Nonce               uint64
	VotingPurpose       uint64
	Network             cardano.Network
	PaymentSigningFiles []cardano.SigningFile
	DerivationType      DerivationType
}

// SignMessageParams describe a CIP-8 message signature.
type SignMessageParams struct {
	Message          []byte
	SigningFile      cardano.SigningFile
	HashPayload      bool
	PreferHexDisplay bool
	Address          string // empty: the key hash is used
	AddressFiles     []cardano.SigningFile
	DerivationType   DerivationType
}

// SignedMessage is what the device returns for a message.
type SignedMessage struct {
	Signature []byte
	PubKey    []byte
	Address   []byte // the address field of the COSE header
}

// NativeScriptDisplay is how the device shows a native script hash.
type NativeScriptDisplay int

const (
	DisplayBech32 NativeScriptDisplay = iota
	DisplayPolicyID
)

// Provider is a connected hardware wallet.
type Provider interface {
	// Version tells the device and app version.
	Version() (string, error)
	// SupportsUnrestricted reports whether the device can sign in
	// unrestricted mode.
	SupportsUnrestricted() (bool, error)
	ShowAddress(ShowAddressParams) error
	// XPubKeys returns the 64-byte extended public keys of paths.
	XPubKeys(paths []cardano.Path, dt DerivationType) ([][]byte, error)
	// WitnessTx witnesses a transaction; change files mark outputs that
	// return to the wallet.
	WitnessTx(p TxSigningParams, change []cardano.SigningFile) ([]Witness, error)
	// SignOperationalCertificate returns the signature of an operational
	// certificate.
	SignOperationalCertificate(kesVKey []byte, kesPeriod uint64, counter OpCertCounter, files []cardano.SigningFile) ([]byte, error)
	// SignCIP36Registration returns the CBOR of the registration metadata.
	SignCIP36Registration(CIP36Params) ([]byte, error)
	SignMessage(SignMessageParams) (SignedMessage, error)
	NativeScriptHash(script cardano.NativeScript, files []cardano.SigningFile, display NativeScriptDisplay, dt DerivationType) ([]byte, error)
	Close() error
}
