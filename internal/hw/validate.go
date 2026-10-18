// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package hw

import (
	"errors"

	"github.com/Liet-ada/cardano-hw-go/internal/cardano"
	"github.com/Liet-ada/cardano-hw-go/internal/tx"
)

// Errors with cardano-hw-cli's wording.
var (
	ErrTooManyPaymentFilesWithPoolReg = errors.New("Unexpected payment hardware signing file with pool registration certificate found")
	ErrMissingStakeSigningFile        = errors.New("Missing staking signing file")
	ErrMissingPoolColdSigningFile     = errors.New("Missing pool cold key signing file")
	ErrTooManyPaymentSigningFiles     = errors.New("Too many payment signing files")
	ErrTooManyStakeSigningFiles       = errors.New("Too many stake signing files")
	ErrTooManyDRepSigningFiles        = errors.New("Too many DRep key signing files")
	ErrTooManyCommitteeColdFiles      = errors.New("Too many committee cold key signing files")
	ErrTooManyCommitteeHotFiles       = errors.New("Too many committee hot key signing files")
	ErrTooManyPoolColdSigningFiles    = errors.New("Too many pool cold key signing files")
	ErrTooManyMintSigningFiles        = errors.New("Too many mint signing files")
	ErrTooManyMultisigSigningFiles    = errors.New("Too many multisig signing files")
)

type fileCounts struct {
	payment, stake, drep, committeeCold, committeeHot, poolCold, mint, multisig int
}

func countFiles(files []cardano.SigningFile) fileCounts {
	var c fileCounts
	for _, f := range files {
		switch f.Type {
		case cardano.SigningPayment:
			c.payment++
		case cardano.SigningStake:
			c.stake++
		case cardano.SigningDRep:
			c.drep++
		case cardano.SigningCommitteeCold:
			c.committeeCold++
		case cardano.SigningCommitteeHot:
			c.committeeHot++
		case cardano.SigningPoolCold:
			c.poolCold++
		case cardano.SigningMint:
			c.mint++
		case cardano.SigningMultiSig:
			c.multisig++
		}
	}
	return c
}

func validateOrdinary(b *tx.Body, c fileCounts) error {
	var drep, cold, hot, pool int
	if b.Certificates != nil {
		for _, cert := range b.Certificates.Items {
			switch cert.Type {
			case tx.CertPoolRetirement:
				pool++
			case tx.CertDRepRegistration, tx.CertDRepDeregistration, tx.CertDRepUpdate:
				drep++
			case tx.CertAuthorizeCommitteeHot, tx.CertResignCommitteeCold:
				cold++
			}
		}
	}
	for _, vv := range b.VotingProcedures {
		switch vv.Voter.Type {
		case tx.VoterDRepKey:
			drep++
		case tx.VoterCommitteeKey:
			hot++
		case tx.VoterStakePool:
			pool++
		}
	}
	switch {
	case drep == 0 && c.drep > 0:
		return ErrTooManyDRepSigningFiles
	case cold == 0 && c.committeeCold > 0:
		return ErrTooManyCommitteeColdFiles
	case hot == 0 && c.committeeHot > 0:
		return ErrTooManyCommitteeHotFiles
	case pool == 0 && c.poolCold > 0:
		return ErrTooManyPoolColdSigningFiles
	case len(b.Mint) == 0 && c.mint > 0:
		return ErrTooManyMintSigningFiles
	case c.multisig > 0:
		return ErrTooManyMultisigSigningFiles
	}
	return nil
}

func validatePoolOwner(c fileCounts) error {
	switch {
	case c.payment > 0:
		return ErrTooManyPaymentFilesWithPoolReg
	case c.stake == 0:
		return ErrMissingStakeSigningFile
	case c.stake > 1:
		return ErrTooManyStakeSigningFiles
	case c.drep > 0:
		return ErrTooManyDRepSigningFiles
	case c.committeeCold > 0:
		return ErrTooManyCommitteeColdFiles
	case c.committeeHot > 0:
		return ErrTooManyCommitteeHotFiles
	case c.poolCold > 0:
		return ErrTooManyPoolColdSigningFiles
	case c.mint > 0:
		return ErrTooManyMintSigningFiles
	case c.multisig > 0:
		return ErrTooManyMultisigSigningFiles
	}
	return nil
}

func validatePoolOperator(c fileCounts) error {
	switch {
	case c.stake > 0:
		return ErrTooManyStakeSigningFiles
	case c.drep > 0:
		return ErrTooManyDRepSigningFiles
	case c.committeeCold > 0:
		return ErrTooManyCommitteeColdFiles
	case c.committeeHot > 0:
		return ErrTooManyCommitteeHotFiles
	case c.poolCold == 0:
		return ErrMissingPoolColdSigningFile
	case c.poolCold > 1:
		return ErrTooManyPoolColdSigningFiles
	case c.mint > 0:
		return ErrTooManyMintSigningFiles
	case c.multisig > 0:
		return ErrTooManyMultisigSigningFiles
	}
	return nil
}

func validateMultisig(b *tx.Body, c fileCounts) error {
	switch {
	case c.payment > 0:
		return ErrTooManyPaymentSigningFiles
	case c.stake > 0:
		return ErrTooManyStakeSigningFiles
	case c.drep > 0:
		return ErrTooManyDRepSigningFiles
	case c.committeeCold > 0:
		return ErrTooManyCommitteeColdFiles
	case c.committeeHot > 0:
		return ErrTooManyCommitteeHotFiles
	case c.poolCold > 0:
		return ErrTooManyPoolColdSigningFiles
	case len(b.Mint) == 0 && c.mint > 0:
		return ErrTooManyMintSigningFiles
	}
	return nil
}

// ValidateWitnessing checks that the signing files fit the transaction and
// the signing mode.
func ValidateWitnessing(p TxSigningParams) error {
	b := &p.Tx.Body
	if b.NetworkID != nil && (!b.NetworkID.IsUint64() || b.NetworkID.Uint64() != uint64(p.Network.NetworkID)) {
		return ErrNetworkIDMismatch
	}
	c := countFiles(p.SigningFiles)
	switch p.Mode {
	case SigningOrdinary:
		return validateOrdinary(b, c)
	case SigningPoolRegistrationAsOwner:
		return validatePoolOwner(c)
	case SigningPoolRegistrationAsOperator:
		return validatePoolOperator(c)
	case SigningMultisig:
		return validateMultisig(b, c)
	case SigningPlutus:
		if c.poolCold > 0 {
			return ErrTooManyPoolColdSigningFiles
		}
		return nil
	case SigningUnrestricted:
		if b.PoolRegistration() != nil {
			return ErrPoolRegistrationInUnrestricted
		}
		return nil
	}
	return ErrUnreachable
}
