// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package ledger

import (
	"fmt"

	"github.com/Liet-ada/cardano-hw-go/internal/cardano"
)

// What each app version can do, and the checks ledgerjs makes on a request
// before and after it reads the version.

// compatibility lists the features that differ between the app versions
// this package supports: 7.x, its reduced Nano S build (XS) and 8.x.
type compatibility struct {
	byronAddresses       bool
	poolRegistration     bool // as owner and as operator
	poolRetirement       bool
	nativeScriptHash     bool
	messageSigning       bool
	unrestricted         bool
	multipleVoters       bool
	multipleVotesPerVote bool
}

func (v Version) compatibility() compatibility {
	if !v.v7() {
		return compatibility{true, true, true, true, true, true, true, true}
	}
	c := compatibility{
		byronAddresses:   true,
		poolRegistration: true,
		poolRetirement:   true,
		nativeScriptHash: true,
		messageSigning:   v.atLeast(7, 1),
	}
	if v.AppXS {
		c.byronAddresses = false
		c.poolRegistration = false
		c.poolRetirement = false
		c.nativeScriptHash = false
	}
	return c
}

// SupportsUnrestricted reports whether the app can sign in unrestricted
// mode (which also needs expert mode enabled on the device).
func (v Version) SupportsUnrestricted() bool { return v.compatibility().unrestricted }

// ensureCompatible rejects apps older than 7.0. ledgerjs also talks to
// apps from 2.2 on, with older serializations; those apps cannot sign
// Conway-era transactions.
func ensureCompatible(v Version) error {
	if !v.atLeast(7, 0) {
		return &Error{Name: "DeviceVersionUnsupported", Message: fmt.Sprintf("Device app version %s unsupported, recommended version is 7.0.", v)}
	}
	return nil
}

func ensureExtendedPublicKeysSupported(v Version, _ []cardano.Path) error {
	return ensureCompatible(v)
}

func ensureAddressSupported(v Version, p AddressParams) error {
	if err := ensureCompatible(v); err != nil {
		return err
	}
	if p.Type == cardano.AddrByron && !v.compatibility().byronAddresses {
		return unsupported(v, "Byron address parameters")
	}
	return nil
}

func ensureNativeScriptHashSupported(v Version) error {
	if err := ensureCompatible(v); err != nil {
		return err
	}
	if !v.compatibility().nativeScriptHash {
		return unsupported(v, "Native script hash derivation")
	}
	return nil
}

func ensureOperationalCertificateSupported(v Version) error {
	if err := ensureCompatible(v); err != nil {
		return err
	}
	if !v.compatibility().poolRegistration {
		return unsupported(v, "Operational certificate signing")
	}
	return nil
}

func ensureMessageSigningSupported(v Version) error {
	if err := ensureCompatible(v); err != nil {
		return err
	}
	if !v.compatibility().messageSigning {
		return unsupported(v, "CIP-8 message signing")
	}
	return nil
}

const v7MaxPoolOwnersOrRelays = 1000

func ensureSignTxSupported(v Version, req *SignRequest) error {
	if err := ensureCompatible(v); err != nil {
		return err
	}
	c := v.compatibility()
	tx := &req.Tx
	switch {
	case req.Mode == ModePoolRegistrationOwner && !c.poolRegistration:
		return unsupported(v, "Pool registration as owner")
	case req.Mode == ModePoolRegistrationOperator && !c.poolRegistration:
		return unsupported(v, "Pool registration as operator")
	case req.Mode == ModeUnrestricted && !c.unrestricted:
		return unsupported(v, "Unrestricted transactions")
	}
	byron := func(o *Output) bool {
		return o != nil && o.Destination.DeviceOwned && o.Destination.Params.Type == cardano.AddrByron
	}
	hasByron := byron(tx.CollateralOutput)
	for i := range tx.Outputs {
		hasByron = hasByron || byron(&tx.Outputs[i])
	}
	if hasByron && !c.byronAddresses {
		return unsupported(v, "Byron address parameters")
	}
	for _, cert := range tx.Certificates {
		if cert.Type == CertPoolRegistration && !c.poolRegistration {
			return unsupported(v, "Pool registration certificate")
		}
	}
	if v.v7() {
		for _, cert := range tx.Certificates {
			if cert.Type != CertPoolRegistration {
				continue
			}
			if len(cert.Pool.Owners) > v7MaxPoolOwnersOrRelays {
				return unsupported(v, fmt.Sprintf("More than %d pool registration owners", v7MaxPoolOwnersOrRelays))
			}
			if len(cert.Pool.Relays) > v7MaxPoolOwnersOrRelays {
				return unsupported(v, fmt.Sprintf("More than %d pool registration relays", v7MaxPoolOwnersOrRelays))
			}
		}
	}
	for _, cert := range tx.Certificates {
		if cert.Type == CertPoolRetirement && !c.poolRetirement {
			return unsupported(v, "Pool retirement certificate")
		}
	}
	if len(tx.VotingProcedures) > 1 && !c.multipleVoters {
		return unsupported(v, "Multiple voters in voting procedures")
	}
	for _, vv := range tx.VotingProcedures {
		if len(vv.Votes) > 1 && !c.multipleVotesPerVote {
			return unsupported(v, "Multiple votes per voter in voting procedures")
		}
	}
	return nil
}

// Reasons of ledgerjs for a request it refuses for its signing mode.
const (
	reasonOrdinaryPoolRegistration     = "pool registration not allowed in TransactionSigningMode.ORDINARY_TRANSACTION"
	reasonOrdinaryStakeCredential      = "certificate stake credential must be given as a staking path in TransactionSigningMode.ORDINARY_TRANSACTION"
	reasonOrdinaryCommitteeCold        = "certificate constitutional committee cold credential must be given as a path in TransactionSigningMode.ORDINARY_TRANSACTION"
	reasonOrdinaryDRepCredential       = "certificate DRep credential must be given as a path in TransactionSigningMode.ORDINARY_TRANSACTION"
	reasonOrdinaryWithdrawal           = "withdrawal must be given as a path in TransactionSigningMode.ORDINARY_TRANSACTION"
	reasonOrdinaryCollateralInputs     = "collateral inputs not allowed in TransactionSigningMode.ORDINARY_TRANSACTION"
	reasonOrdinaryCollateralOutput     = "collateral output not allowed in TransactionSigningMode.ORDINARY_TRANSACTION"
	reasonOrdinaryTotalCollateral      = "total collateral not allowed in TransactionSigningMode.ORDINARY_TRANSACTION"
	reasonOrdinaryReferenceInputs      = "reference inputs not allowed in TransactionSigningMode.ORDINARY_TRANSACTION"
	reasonOrdinaryVoter                = "voter credential in voting procedures must be given as a path in TransactionSigningMode.ORDINARY_TRANSACTION"
	reasonMultisigDeviceOwnedAddress   = "outputs given by path not allowed in TransactionSigningMode.MULTISIG_TRANSACTION"
	reasonMultisigPoolRegistration     = "pool registration not allowed in TransactionSigningMode.MULTISIG_TRANSACTION"
	reasonMultisigPoolRetirement       = "pool retirement not allowed in TransactionSigningMode.MULTISIG_TRANSACTION"
	reasonMultisigCertificate          = "certificate credential must be a script hash in TransactionSigningMode.MULTISIG_TRANSACTION"
	reasonMultisigWithdrawal           = "withdrawal must be a script hash in TransactionSigningMode.MULTISIG_TRANSACTION"
	reasonMultisigCollateralInputs     = "collateral inputs not allowed in TransactionSigningMode.MULTISIG_TRANSACTION"
	reasonMultisigCollateralOutput     = "collateral output not allowed in TransactionSigningMode.MULTISIG_TRANSACTION"
	reasonMultisigTotalCollateral      = "total collateral not allowed in TransactionSigningMode.MULTISIG_TRANSACTION"
	reasonMultisigReferenceInputs      = "reference inputs not allowed in TransactionSigningMode.MULTISIG_TRANSACTION"
	reasonMultisigVoter                = "voter credential in voting procedures must be a script hash in TransactionSigningMode.MULTISIG_TRANSACTION"
	reasonOwnerInputWithPath           = "inputs with path not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OWNER"
	reasonOwnerDeviceOwnedAddress      = "outputs given by path are not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OWNER"
	reasonOwnerDatum                   = "datum in outputs not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OWNER"
	reasonOwnerReferenceScript         = "reference script in outputs not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OWNER"
	reasonOwnerSingleCertificate       = "single pool registration certificate is expected in TransactionSigningMode.POOL_REGISTRATION_AS_OWNER"
	reasonOwnerThirdPartyPoolKey       = "third party pool key is required in TransactionSigningMode.POOL_REGISTRATION_AS_OWNER"
	reasonOwnerSingleDeviceOwner       = "single device-owned pool owner is expected in TransactionSigningMode.POOL_REGISTRATION_AS_OWNER"
	reasonOwnerWithdrawals             = "withdrawals not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OWNER"
	reasonOwnerMint                    = "mint not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OWNER"
	reasonOwnerScriptDataHash          = "script data hash not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OWNER"
	reasonOwnerCollateralInputs        = "collateral inputs not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OWNER"
	reasonOwnerRequiredSigners         = "required signers not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OWNER"
	reasonOwnerCollateralOutput        = "collateral output not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OWNER"
	reasonOwnerTotalCollateral         = "total collateral not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OWNER"
	reasonOwnerReferenceInputs         = "reference inputs not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OWNER"
	reasonOwnerVotingProcedures        = "voting procedures not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OWNER"
	reasonOwnerTreasury                = "treasury amount not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OWNER"
	reasonOwnerDonation                = "treasury donation not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OWNER"
	reasonOperatorDatum                = "datum in outputs not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR"
	reasonOperatorReferenceScript      = "reference script in outputs not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR"
	reasonOperatorSingleCertificate    = "single pool registration certificate is expected in TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR"
	reasonOperatorDeviceOwnedPoolKey   = "device owned pool key is required in TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR"
	reasonOperatorDeviceOwnedPoolOwner = "device-owned pool owner not expected in TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR"
	reasonOperatorWithdrawals          = "withdrawals not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR"
	reasonOperatorMint                 = "mint not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR"
	reasonOperatorScriptDataHash       = "script data hash not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR"
	reasonOperatorCollateralInputs     = "collateral inputs not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR"
	reasonOperatorRequiredSigners      = "required signers not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR"
	reasonOperatorCollateralOutput     = "collateral output not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR"
	reasonOperatorTotalCollateral      = "total collateral not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR"
	reasonOperatorReferenceInputs      = "reference inputs not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR"
	reasonOperatorVotingProcedures     = "voting procedures not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR"
	reasonOperatorTreasury             = "treasury amount not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR"
	reasonOperatorDonation             = "treasury donation not allowed in TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR"
	reasonPlutusPoolRegistration       = "pool registration not allowed in TransactionSigningMode.PLUTUS_TRANSACTION"
	reasonUnrestrictedPoolRegistration = "pool registration not allowed in TransactionSigningMode.UNRESTRICTED_TRANSACTION"
	reasonAssetGroupEmpty              = "invalid asset group in multiasset token bundle - zero tokens"
	reasonTokenBundleEmpty             = "invalid multiasset token bundle - token bundle is not allowed to be empty"
	reasonInputsEmpty                  = "transaction must contain at least one input"
	reasonCollateralOutputDatum        = "collateral return output contains datum"
	reasonCollateralOutputScript       = "collateral return output contains reference script"
)

// stakeCertificate reports whether a certificate's credential is a stake
// credential.
func stakeCertificate(t uint8) bool {
	switch t {
	case CertStakeRegistration, CertStakeRegistrationConway, CertStakeDeregistration,
		CertStakeDeregistrationConway, CertStakeDelegation, CertVoteDelegation:
		return true
	}
	return false
}

func committeeCertificate(t uint8) bool {
	return t == CertAuthorizeCommitteeHot || t == CertResignCommitteeCold
}

func drepCertificate(t uint8) bool {
	return t == CertDRepRegistration || t == CertDRepDeregistration || t == CertDRepUpdate
}

// validateSignRequest makes ledgerjs's checks of a request for its signing
// mode, before anything is sent to the device.
func validateSignRequest(req *SignRequest) error {
	tx := &req.Tx
	check := func(ok bool, reason string) error {
		if !ok {
			return invalidData(reason)
		}
		return nil
	}
	all := func(n int, f func(int) bool) bool {
		for i := 0; i < n; i++ {
			if !f(i) {
				return false
			}
		}
		return true
	}
	certs := tx.Certificates
	noCert := func(t uint8) bool { return all(len(certs), func(i int) bool { return certs[i].Type != t }) }
	outputsThirdParty := all(len(tx.Outputs), func(i int) bool { return !tx.Outputs[i].Destination.DeviceOwned })
	noDatum := all(len(tx.Outputs), func(i int) bool { return !tx.Outputs[i].HasDatum })
	noScript := all(len(tx.Outputs), func(i int) bool { return !tx.Outputs[i].HasRefScript })
	withdrawalsAre := func(k CredentialKind) bool {
		return all(len(tx.Withdrawals), func(i int) bool { return tx.Withdrawals[i].Credential.Kind == k })
	}
	votersAre := func(types ...uint8) bool {
		return all(len(tx.VotingProcedures), func(i int) bool {
			for _, t := range types {
				if tx.VotingProcedures[i].Voter.Type == t {
					return true
				}
			}
			return false
		})
	}
	poolOwnersOnDevice := func(c Certificate) int {
		n := 0
		for _, o := range c.Pool.Owners {
			if o.Kind == CredKeyPath {
				n++
			}
		}
		return n
	}

	var checks []error
	add := func(ok bool, reason string) { checks = append(checks, check(ok, reason)) }
	addErr := func(err error) { checks = append(checks, err) }
	tokens := func(groups []AssetGroup) {
		for _, g := range groups {
			add(len(g.Tokens) > 0, reasonAssetGroupEmpty)
		}
	}
	output := func(o *Output) {
		tokens(o.Tokens)
		addErr(validateDestination(o.Destination))
	}
	// what ledgerjs checks as it parses the request, in its order
	add(len(tx.Inputs) > 0, reasonInputsEmpty)
	for i := range tx.Outputs {
		output(&tx.Outputs[i])
	}
	if tx.CIP36 != nil && tx.CIP36.Destination.DeviceOwned {
		addErr(validateAddress(tx.CIP36.Destination.Params))
	}
	if tx.HasMint {
		add(len(tx.Mint) > 0, reasonTokenBundleEmpty)
		tokens(tx.Mint)
	}
	if co := tx.CollateralOutput; co != nil {
		output(co)
		add(!co.HasDatum, reasonCollateralOutputDatum)
		add(!co.HasRefScript, reasonCollateralOutputScript)
	}
	switch req.Mode {
	case ModeOrdinary:
		add(noCert(CertPoolRegistration), reasonOrdinaryPoolRegistration)
		add(all(len(certs), func(i int) bool {
			return !stakeCertificate(certs[i].Type) || certs[i].StakeCredential.Kind == CredKeyPath
		}), reasonOrdinaryStakeCredential)
		add(all(len(certs), func(i int) bool {
			return !committeeCertificate(certs[i].Type) || certs[i].ColdCredential.Kind == CredKeyPath
		}), reasonOrdinaryCommitteeCold)
		add(all(len(certs), func(i int) bool {
			return !drepCertificate(certs[i].Type) || certs[i].DRepCredential.Kind == CredKeyPath
		}), reasonOrdinaryDRepCredential)
		add(withdrawalsAre(CredKeyPath), reasonOrdinaryWithdrawal)
		add(len(tx.Collateral) == 0, reasonOrdinaryCollateralInputs)
		add(tx.CollateralOutput == nil, reasonOrdinaryCollateralOutput)
		add(tx.TotalCollateral == nil, reasonOrdinaryTotalCollateral)
		add(len(tx.ReferenceInputs) == 0, reasonOrdinaryReferenceInputs)
		add(votersAre(VoterCommitteeKeyPath, VoterDRepKeyPath, VoterStakePoolKeyPath), reasonOrdinaryVoter)
	case ModeMultisig:
		add(outputsThirdParty, reasonMultisigDeviceOwnedAddress)
		add(noCert(CertPoolRegistration), reasonMultisigPoolRegistration)
		add(noCert(CertPoolRetirement), reasonMultisigPoolRetirement)
		add(all(len(certs), func(i int) bool {
			c := certs[i]
			switch {
			case stakeCertificate(c.Type):
				return c.StakeCredential.Kind == CredScriptHash
			case committeeCertificate(c.Type):
				return c.ColdCredential.Kind == CredScriptHash
			case drepCertificate(c.Type):
				return c.DRepCredential.Kind == CredScriptHash
			}
			return true
		}), reasonMultisigCertificate)
		add(withdrawalsAre(CredScriptHash), reasonMultisigWithdrawal)
		add(len(tx.Collateral) == 0, reasonMultisigCollateralInputs)
		add(tx.CollateralOutput == nil, reasonMultisigCollateralOutput)
		add(tx.TotalCollateral == nil, reasonMultisigTotalCollateral)
		add(len(tx.ReferenceInputs) == 0, reasonMultisigReferenceInputs)
		add(votersAre(VoterCommitteeScriptHash, VoterDRepScriptHash), reasonMultisigVoter)
	case ModePoolRegistrationOwner:
		add(all(len(tx.Inputs), func(i int) bool { return tx.Inputs[i].Path == nil }), reasonOwnerInputWithPath)
		add(outputsThirdParty, reasonOwnerDeviceOwnedAddress)
		add(noDatum, reasonOwnerDatum)
		add(noScript, reasonOwnerReferenceScript)
		add(len(certs) == 1, reasonOwnerSingleCertificate)
		for _, c := range certs {
			add(c.Type == CertPoolRegistration, reasonOwnerSingleCertificate)
			if c.Type == CertPoolRegistration {
				add(c.Pool.PoolKeyPath == nil, reasonOwnerThirdPartyPoolKey)
				add(poolOwnersOnDevice(c) == 1, reasonOwnerSingleDeviceOwner)
			}
		}
		add(len(tx.Withdrawals) == 0, reasonOwnerWithdrawals)
		add(!tx.HasMint, reasonOwnerMint)
		add(tx.ScriptDataHash == nil, reasonOwnerScriptDataHash)
		add(len(tx.Collateral) == 0, reasonOwnerCollateralInputs)
		add(len(tx.RequiredSigners) == 0, reasonOwnerRequiredSigners)
		add(tx.CollateralOutput == nil, reasonOwnerCollateralOutput)
		add(tx.TotalCollateral == nil, reasonOwnerTotalCollateral)
		add(len(tx.ReferenceInputs) == 0, reasonOwnerReferenceInputs)
		add(len(tx.VotingProcedures) == 0, reasonOwnerVotingProcedures)
		add(tx.Treasury == nil, reasonOwnerTreasury)
		add(tx.Donation == nil, reasonOwnerDonation)
	case ModePoolRegistrationOperator:
		add(noDatum, reasonOperatorDatum)
		add(noScript, reasonOperatorReferenceScript)
		add(len(certs) == 1, reasonOperatorSingleCertificate)
		for _, c := range certs {
			add(c.Type == CertPoolRegistration, reasonOperatorSingleCertificate)
			if c.Type == CertPoolRegistration {
				add(c.Pool.PoolKeyPath != nil, reasonOperatorDeviceOwnedPoolKey)
				add(poolOwnersOnDevice(c) == 0, reasonOperatorDeviceOwnedPoolOwner)
			}
		}
		add(len(tx.Withdrawals) == 0, reasonOperatorWithdrawals)
		add(!tx.HasMint, reasonOperatorMint)
		add(tx.ScriptDataHash == nil, reasonOperatorScriptDataHash)
		add(len(tx.Collateral) == 0, reasonOperatorCollateralInputs)
		add(len(tx.RequiredSigners) == 0, reasonOperatorRequiredSigners)
		add(tx.CollateralOutput == nil, reasonOperatorCollateralOutput)
		add(tx.TotalCollateral == nil, reasonOperatorTotalCollateral)
		add(len(tx.ReferenceInputs) == 0, reasonOperatorReferenceInputs)
		add(len(tx.VotingProcedures) == 0, reasonOperatorVotingProcedures)
		add(tx.Treasury == nil, reasonOperatorTreasury)
		add(tx.Donation == nil, reasonOperatorDonation)
	case ModePlutus:
		add(noCert(CertPoolRegistration), reasonPlutusPoolRegistration)
	case ModeUnrestricted:
		add(noCert(CertPoolRegistration), reasonUnrestrictedPoolRegistration)
	default:
		return invalidData("unknown signing mode")
	}
	for _, err := range checks {
		if err != nil {
			return err
		}
	}
	return nil
}

// isHexString is ledgerjs's isHexString: an even number of hex digits, in
// either case.
func isHexString(s string) bool {
	if len(s)%2 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return false
		}
	}
	return true
}

// validateAddress makes ledgerjs's checks of address parameters: the
// spending and staking parts the address type needs.
func validateAddress(p AddressParams) error {
	spending := "none"
	switch {
	case p.SpendingPath != nil:
		spending = "path"
	case p.SpendingScriptHash != nil:
		spending = "script"
	}
	switch p.Type {
	case cardano.AddrBasePaymentKeyStakeKey, cardano.AddrBasePaymentKeyStakeScript,
		cardano.AddrPointerKey, cardano.AddrEnterpriseKey, cardano.AddrByron:
		if spending != "path" {
			return invalidData("invalid address spending information")
		}
	case cardano.AddrBasePaymentScriptStakeKey, cardano.AddrBasePaymentScriptStakeScript,
		cardano.AddrPointerScript, cardano.AddrEnterpriseScript:
		if spending != "script" {
			return invalidData("invalid address spending information")
		}
	case cardano.AddrRewardKey, cardano.AddrRewardScript:
		if spending != "none" {
			return invalidData("invalid address spending information")
		}
	default:
		return invalidData("unknown address type")
	}
	ok := false
	switch p.Type {
	case cardano.AddrBasePaymentKeyStakeKey, cardano.AddrBasePaymentScriptStakeKey, cardano.AddrRewardKey:
		ok = p.Staking == StakingKeyPath || p.Staking == StakingKeyHash
	case cardano.AddrBasePaymentScriptStakeScript, cardano.AddrBasePaymentKeyStakeScript, cardano.AddrRewardScript:
		ok = p.Staking == StakingScriptHash
	case cardano.AddrByron, cardano.AddrEnterpriseKey, cardano.AddrEnterpriseScript:
		ok = p.Staking == StakingNone
	}
	if !ok {
		return invalidData("Invalid staking info in an output")
	}
	return nil
}

// validateDestination checks the destination of an output: an address of
// the device must be spent by one of its keys.
func validateDestination(d Destination) error {
	if !d.DeviceOwned {
		if len(d.Address) > maxAddressLength {
			return invalidData("invalid address in an output")
		}
		return nil
	}
	if err := validateAddress(d.Params); err != nil {
		return err
	}
	if d.Params.SpendingPath == nil {
		return invalidData("change address must have path as payment part")
	}
	return nil
}
