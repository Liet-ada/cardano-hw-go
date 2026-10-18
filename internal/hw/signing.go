// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package hw

import (
	"bytes"
	"crypto/ed25519"
	"errors"

	"github.com/Liet-ada/cardano-hw-go/internal/cardano"
	"github.com/Liet-ada/cardano-hw-go/internal/tx"
)

// Errors with cardano-hw-cli's wording.
var (
	ErrSigningPubKeyMismatch            = errors.New("Signing public key mismatch: likely because an incorrect signing file was used")
	ErrTxSerializationMismatch          = errors.New("Tx serialization mismatch")
	ErrMissingSigningFileForCertificate = errors.New("Missing signing file for certificate")
	ErrOwnerMultipleTimes               = errors.New("Owner multiple times in tx")
	ErrUnsupportedCertificateType       = errors.New("Transaction contains a certificate type that is not supported by HW wallets (see CIP-21)")
	ErrUnknownCertificate               = errors.New("Unknown certificate")
	ErrInvalidInput                     = errors.New("Invalid input")
	ErrInvalidCollateralInput           = errors.New("Invalid collateral input")
	ErrNetworkIDMismatch                = errors.New("Provided network id differs from network id included in transaction body")
	ErrMissingHwSigningDataAtPath       = errors.New("Can not find hw signing data by path")
	ErrMissingHwSigningDataAtXPub       = errors.New("Can not find hw signing data by extended public key")
	ErrMissingHwSigningDataAtPoolCold   = errors.New("Can not find hw signing data by pool cold key")
	ErrUnrestrictedModeRequired         = errors.New("This transaction can only be signed in unrestricted signing mode (e.g. it contains required signers). Re-run with --allow-unrestricted-mode to permit it.")
	ErrUnrestrictedModeUnsupported      = errors.New("This transaction requires unrestricted signing mode, but the connected device or app version does not support it (requires Ledger app v8 or newer with expert mode enabled).")
	ErrPoolRegistrationInUnrestricted   = errors.New("Pool registration certificate is not allowed in unrestricted transaction signing mode; use a pool registration signing mode instead")
	ErrInvalidVotingProcedures          = errors.New("Invalid voting procedures (might be a number out of range)")
	ErrUnreachable                      = errors.New("Unreachable code reached")
)

// FilesOfType returns the signing files with a role.
func FilesOfType(files []cardano.SigningFile, t cardano.SigningType) []cardano.SigningFile {
	var out []cardano.SigningFile
	for _, f := range files {
		if f.Type == t {
			out = append(out, f)
		}
	}
	return out
}

// PathForKeyHash returns the path of the signing file whose public key
// hashes to h.
func PathForKeyHash(h []byte, files []cardano.SigningFile) cardano.Path {
	for _, f := range files {
		if bytes.Equal(cardano.KeyHash(f.PubKey()), h) {
			return f.Path
		}
	}
	return nil
}

// FileForKey returns the signing file of a public key.
func FileForKey(pub []byte, files []cardano.SigningFile) *cardano.SigningFile {
	for i := range files {
		if bytes.Equal(files[i].PubKey(), pub) {
			return &files[i]
		}
	}
	return nil
}

// RewardAccountCredential is the stake credential of a reward account.
func RewardAccountCredential(acct []byte) (tx.Credential, error) {
	t, err := cardano.AddressTypeOf(acct)
	if err != nil || len(acct) < 1+cardano.KeyHashLength {
		return tx.Credential{}, cardano.ErrInvalidAddress
	}
	switch t {
	case cardano.AddrRewardKey:
		return tx.Credential{Type: tx.CredentialKeyHash, Hash: acct[1 : 1+cardano.KeyHashLength]}, nil
	case cardano.AddrRewardScript:
		return tx.Credential{Type: tx.CredentialScriptHash, Hash: acct[1 : 1+cardano.KeyHashLength]}, nil
	}
	return tx.Credential{}, cardano.ErrInvalidAddress
}

// certCredentials are the credentials a signing mode constrains in a
// certificate: stake, DRep and committee cold ones.
func certCredentials(c tx.Certificate) []tx.Credential {
	switch c.Type {
	case tx.CertStakeRegistration, tx.CertStakeDeregistration, tx.CertStakeDelegation,
		tx.CertStakeRegistrationConway, tx.CertStakeDeregistrationConway, tx.CertVoteDelegation,
		tx.CertStakeAndVoteDelegation, tx.CertStakeRegistrationAndDelegation,
		tx.CertStakeRegistrationWithVoteDelegation, tx.CertStakeRegistrationWithStakeAndVoteDeleg:
		return []tx.Credential{c.StakeCredential}
	case tx.CertDRepRegistration, tx.CertDRepDeregistration, tx.CertDRepUpdate:
		return []tx.Credential{c.DRepCredential}
	case tx.CertAuthorizeCommitteeHot, tx.CertResignCommitteeCold:
		return []tx.Credential{c.ColdCredential}
	}
	return nil
}

type credentialForm int

const (
	formKeyPath credentialForm = iota
	formKeyHash
	formScriptHash
)

func credentialForms(b *tx.Body, files []cardano.SigningFile) ([]credentialForm, error) {
	hashes := map[string]bool{}
	for _, f := range files {
		hashes[string(cardano.KeyHash(f.PubKey()))] = true
	}
	keyForm := func(h []byte) credentialForm {
		if hashes[string(h)] {
			return formKeyPath
		}
		return formKeyHash
	}
	form := func(c tx.Credential) credentialForm {
		if c.Type == tx.CredentialScriptHash {
			return formScriptHash
		}
		return keyForm(c.Hash)
	}
	var forms []credentialForm
	if b.Certificates != nil {
		for _, c := range b.Certificates.Items {
			for _, cr := range certCredentials(c) {
				forms = append(forms, form(cr))
			}
		}
	}
	for _, w := range b.Withdrawals {
		cr, err := RewardAccountCredential(w.RewardAccount)
		if err != nil {
			return nil, err
		}
		forms = append(forms, form(cr))
	}
	for _, vv := range b.VotingProcedures {
		if vv.Voter.Type == tx.VoterCommitteeScript || vv.Voter.Type == tx.VoterDRepScript {
			forms = append(forms, formScriptHash)
		} else {
			forms = append(forms, keyForm(vv.Voter.Hash))
		}
	}
	return forms, nil
}

func hasPlutusOnlyFields(b *tx.Body) bool {
	return b.CollateralInputs != nil || b.CollateralReturn != nil || b.TotalCollateral != nil || b.ReferenceInputs != nil
}

func allForms(forms []credentialForm, f credentialForm) bool {
	for _, x := range forms {
		if x != f {
			return false
		}
	}
	return true
}

func hasCertType(b *tx.Body, types ...tx.CertificateType) bool {
	if b.Certificates == nil {
		return false
	}
	for _, c := range b.Certificates.Items {
		for _, t := range types {
			if c.Type == t {
				return true
			}
		}
	}
	return false
}

// DetermineSigningMode picks the signing mode of a transaction from its
// content and the signing files given, as cardano-hw-cli does.
func DetermineSigningMode(b *tx.Body, files []cardano.SigningFile) (SigningMode, error) {
	if reg := b.PoolRegistration(); reg != nil {
		if PathForKeyHash(reg.PoolParams.Operator, files) != nil || len(FilesOfType(files, cardano.SigningPayment)) > 0 {
			return SigningPoolRegistrationAsOperator, nil
		}
		return SigningPoolRegistrationAsOwner, nil
	}
	if hasPlutusOnlyFields(b) {
		return SigningPlutus, nil
	}
	forms, err := credentialForms(b, files)
	if err != nil {
		return 0, err
	}
	if len(FilesOfType(files, cardano.SigningMultiSig)) > 0 {
		if !hasCertType(b, tx.CertPoolRegistration, tx.CertPoolRetirement) && allForms(forms, formScriptHash) {
			return SigningMultisig, nil
		}
		return SigningUnrestricted, nil
	}
	if allForms(forms, formKeyPath) {
		return SigningOrdinary, nil
	}
	return SigningUnrestricted, nil
}

// AddressParams describe an address of the wallet.
type AddressParams struct {
	Address     []byte
	Type        cardano.AddressType
	PaymentPath cardano.Path
	StakePath   cardano.Path
}

// AddressParamsFor finds which signing files an address belongs to, so the
// device can show derivation paths (and treat the output as change). It
// returns nil for a third-party address.
func AddressParamsFor(files []cardano.SigningFile, addr []byte, network cardano.Network) *AddressParams {
	if len(files) == 0 {
		return nil
	}
	t, err := cardano.AddressTypeOf(addr)
	if err != nil {
		return nil
	}
	payment := FilesOfType(files, cardano.SigningPayment)
	stake := FilesOfType(files, cardano.SigningStake)
	match := func(p *AddressParams) *AddressParams {
		if bytes.Equal(p.Address, addr) {
			return p
		}
		return nil
	}
	switch t {
	case cardano.AddrByron:
		for _, f := range payment {
			pub, chain, err := f.XPub()
			if err != nil {
				continue
			}
			a := cardano.ByronAddress(append(append([]byte{}, pub...), chain...), network.ProtocolMagic)
			if p := match(&AddressParams{a, t, f.Path, nil}); p != nil {
				return p
			}
		}
	case cardano.AddrBasePaymentKeyStakeKey:
		for _, f := range payment {
			for _, s := range stake {
				a := cardano.BaseAddress(t, cardano.KeyHash(f.PubKey()), cardano.KeyHash(s.PubKey()), network.NetworkID)
				if p := match(&AddressParams{a, t, f.Path, s.Path}); p != nil {
					return p
				}
			}
		}
	case cardano.AddrBasePaymentKeyStakeScript:
		if len(addr) != 1+2*cardano.KeyHashLength {
			return nil
		}
		for _, f := range payment {
			a := cardano.BaseAddress(t, cardano.KeyHash(f.PubKey()), addr[1+cardano.KeyHashLength:], network.NetworkID)
			if p := match(&AddressParams{a, t, f.Path, nil}); p != nil {
				return p
			}
		}
	case cardano.AddrEnterpriseKey:
		for _, f := range payment {
			if p := match(&AddressParams{cardano.EnterpriseAddress(cardano.KeyHash(f.PubKey()), network.NetworkID), t, f.Path, nil}); p != nil {
				return p
			}
		}
	case cardano.AddrRewardKey:
		for _, s := range stake {
			if p := match(&AddressParams{cardano.RewardAddress(cardano.KeyHash(s.PubKey()), network.NetworkID), t, nil, s.Path}); p != nil {
				return p
			}
		}
	}
	return nil
}

// AddressParamsAllowed reports whether a signing mode lets outputs be given
// as the wallet's own addresses.
func AddressParamsAllowed(m SigningMode) bool {
	return m == SigningOrdinary || m == SigningPlutus || m == SigningUnrestricted
}

// VerifyWitness checks that a signature from the device is the key of the
// signing file signing the body hash we expect.
func VerifyWitness(bodyHash []byte, file cardano.SigningFile, signature []byte) error {
	pub := file.PubKey()
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, bodyHash, signature) {
		return ErrSigningPubKeyMismatch
	}
	return nil
}
