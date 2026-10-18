// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tx

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
)

// ValidationError is a way in which a transaction breaks CIP-21. A fixable
// one is solved by transforming the transaction.
type ValidationError struct {
	Fixable  bool
	Reason   string
	Position string
}

func (e ValidationError) String() string { return fmt.Sprintf("%s (%s)", e.Reason, e.Position) }

// Validation error reasons, as cardano-hw-interop-lib words them.
const (
	// unfixable
	ReasonUnsupportedTxUpdate                     = "The transaction body entry update must not be included"
	ReasonUnsupportedTxProposalProcedures         = "The transaction body entry proposal_procedures must not be included"
	ReasonUnsupportedCertGenesisKeyDelegation     = "Certificate of type genesis_key_delegation is not supported and must not be included"
	ReasonUnsupportedCertMoveInstantaneousRewards = "Certificate of type move_instantaneous_rewards_cert is not supported and must not be included"
	ReasonUnsupportedCertStakeVoteDeleg           = "Certificate of type stake_vote_deleg_cert is not supported and must not be included"
	ReasonUnsupportedCertStakeRegDeleg            = "Certificate of type stake_reg_deleg_cert is not supported and must not be included"
	ReasonUnsupportedCertVoteRegDeleg             = "Certificate of type vote_reg_deleg_cert is not supported and must not be included"
	ReasonUnsupportedCertStakeVoteRegDeleg        = "Certificate of type stake_vote_reg_deleg_cert is not supported and must not be included"
	ReasonIntegerNotInt64                         = "Hardware wallets support integers up to int64, integers from -2^63 to 2^63-1"
	ReasonUnsignedIntegerNotUint64                = "Hardware wallets support unsigned integers up to uint64, unsigned integers from 0 to 2^64-1"
	ReasonNumberOfElementsExceedsUint16           = "The number of transaction elements individually must not exceed UINT16_MAX, i.e. 65535"
	ReasonPoolRegistrationWithOtherCertificates   = "If a transaction contains a pool registration certificate, then it must not contain any other certificate"
	ReasonPoolRegistrationWithWithdrawals         = "If a transaction contains a pool registration certificate, then it must not contain any withdrawal"
	ReasonPoolRegistrationWithMintEntry           = "If a transaction contains a pool registration certificate, then it must not contain mint entry"
	ReasonPoolRegistrationWithPlutusOutputs       = "If a transaction contains a pool registration certificate, then it must not contain datums and reference scripts in outputs"
	ReasonPoolRegistrationWithScriptDataHash      = "If a transaction contains a pool registration certificate, then it must not contain script data hash"
	ReasonPoolRegistrationWithCollateralInputs    = "If a transaction contains a pool registration certificate, then it must not contain collateral inputs"
	ReasonPoolRegistrationWithRequiredSigners     = "If a transaction contains a pool registration certificate, then it must not contain required signers"
	ReasonPoolRegistrationWithCollateralReturn    = "If a transaction contains a pool registration certificate, then it must not contain collateral return output"
	ReasonPoolRegistrationWithTotalCollateral     = "If a transaction contains a pool registration certificate, then it must not contain total collateral"
	ReasonPoolRegistrationWithReferenceInputs     = "If a transaction contains a pool registration certificate, then it must not contain reference inputs"
	ReasonPoolRegistrationWithVotingProcedures    = "If a transaction contains a pool registration certificate, then it must not contain voting procedures"
	ReasonPoolRegistrationWithTreasury            = "If a transaction contains a pool registration certificate, then it must not contain treasury value entry"
	ReasonPoolRegistrationWithDonation            = "If a transaction contains a pool registration certificate, then it must not contain treasury donation entry"
	ReasonTooManyVotersInVotingProcedures         = "Only a single voter is allowed in voting procedures"
	ReasonInvalidNumberOfVotingProcedures         = "There must be exactly one voting procedure per voter"

	// fixable
	ReasonCBORIsNotCanonical                         = "CBOR is not canonical"
	ReasonOptionalEmptyListsAndMapsMustNotBeIncluded = "Optional empty lists and maps must not be included as part of the transaction body or its elements"
	ReasonOutputAmountWithoutTokensMustNotBeATuple   = "Output amount (value) without tokens must not be a tuple"
	ReasonInlineDatumMustNotBeEmptyIfDefined         = "Inline datum must not be empty if defined"
	ReasonReferenceScriptMustNotBeEmptyIfDefined     = "Reference script must not be empty if defined"
	ReasonCollateralReturnMustNotContainDatum        = "Collateral return must not contain datum"
	ReasonCollateralReturnMustNotContainRefScript    = "Collateral return must not contain reference script"
	ReasonTxInconsistentSetTags                      = "Inconsistent set tags 258 across the transaction body"
)

var fixableReasons = map[string]bool{
	ReasonCBORIsNotCanonical:                         true,
	ReasonOptionalEmptyListsAndMapsMustNotBeIncluded: true,
	ReasonOutputAmountWithoutTokensMustNotBeATuple:   true,
	ReasonInlineDatumMustNotBeEmptyIfDefined:         true,
	ReasonReferenceScriptMustNotBeEmptyIfDefined:     true,
	ReasonCollateralReturnMustNotContainDatum:        true,
	ReasonCollateralReturnMustNotContainRefScript:    true,
	ReasonTxInconsistentSetTags:                      true,
}

var (
	maxUint64 = new(big.Int).SetUint64(math.MaxUint64)
	minInt64  = big.NewInt(math.MinInt64)
	maxInt64  = big.NewInt(math.MaxInt64)
)

type validator struct{ errs []ValidationError }

func (v *validator) check(ok bool, reason, position string) {
	if !ok {
		v.errs = append(v.errs, ValidationError{fixableReasons[reason], reason, position})
	}
}

func (v *validator) uint64(n *big.Int, position string) {
	v.check(n.Sign() >= 0 && n.Cmp(maxUint64) <= 0, ReasonUnsignedIntegerNotUint64, position)
}

func (v *validator) int64(n *big.Int, position string) {
	v.check(n.Cmp(minInt64) >= 0 && n.Cmp(maxInt64) <= 0, ReasonIntegerNotInt64, position)
}

func (v *validator) list(n int, position string, required bool) {
	if !required {
		v.check(n > 0, ReasonOptionalEmptyListsAndMapsMustNotBeIncluded, position)
	}
	v.check(n <= math.MaxUint16, ReasonNumberOfElementsExceedsUint16, position)
}

func (v *validator) multiasset(m Multiasset, amount func(*big.Int, string), position string) {
	v.list(len(m), position, false)
	for _, g := range m {
		pid := hex.EncodeToString(g.PolicyID)
		v.list(len(g.Tokens), fmt.Sprintf("%s[%s]", position, pid), false)
		for _, t := range g.Tokens {
			amount(t.Amount, fmt.Sprintf("%s[%s][%s]", position, pid, hex.EncodeToString(t.AssetName)))
		}
	}
}

func (v *validator) outputAmount(a Amount, position string) {
	v.uint64(a.Coin, position+".amount")
	if a.HasMultiasset {
		v.check(len(a.Multiasset) > 0, ReasonOutputAmountWithoutTokensMustNotBeATuple, position+".amount")
		v.multiasset(a.Multiasset, v.uint64, position)
	}
}

func (v *validator) output(o Output, position string) {
	v.outputAmount(o.Amount, position)
	if o.Format == FormatMapBabbage {
		v.check(o.Datum == nil || o.Datum.Type != DatumInline || len(o.Datum.Bytes) > 0,
			ReasonInlineDatumMustNotBeEmptyIfDefined, position+".datum.bytes")
		v.check(!o.HasReferenceScript || len(o.ReferenceScript) > 0,
			ReasonReferenceScriptMustNotBeEmptyIfDefined, position+".reference_script")
	}
}

// collateralReturn mirrors the library: it never reports the amount of the
// collateral return, only datums and reference scripts.
func (v *validator) collateralReturn(o Output, position string) {
	if o.Format == FormatMapBabbage {
		v.check(o.Datum == nil, ReasonCollateralReturnMustNotContainDatum, position+".datum")
		v.check(!o.HasReferenceScript, ReasonCollateralReturnMustNotContainRefScript, position+".reference_script")
	}
}

func (v *validator) inputs(items []Input, position string, required bool) {
	v.list(len(items), position, required)
	for i, in := range items {
		v.uint64(in.Index, fmt.Sprintf("%s[%d].index", position, i))
	}
}

func (v *validator) certificates(certs []Certificate) {
	v.list(len(certs), "transaction_body.certificates", false)
	for i, c := range certs {
		pos := fmt.Sprintf("transaction_body.certificates[%d]", i)
		switch c.Type {
		case CertPoolRegistration:
			v.uint64(c.PoolParams.Pledge, pos+".pool_params.pledge")
			v.uint64(c.PoolParams.Cost, pos+".pool_params.cost")
			v.uint64(c.PoolParams.Margin[0], pos+".pool_params.margin[0]")
			v.uint64(c.PoolParams.Margin[1], pos+".pool_params.margin[1]")
		case CertPoolRetirement:
			v.uint64(c.Epoch, pos+".epoch")
		case CertGenesisKeyDelegation:
			v.check(false, ReasonUnsupportedCertGenesisKeyDelegation, pos)
		case CertMoveInstantaneousRewards:
			v.check(false, ReasonUnsupportedCertMoveInstantaneousRewards, pos)
		case CertStakeAndVoteDelegation:
			v.check(false, ReasonUnsupportedCertStakeVoteDeleg, pos)
		case CertStakeRegistrationAndDelegation:
			v.check(false, ReasonUnsupportedCertStakeRegDeleg, pos)
		case CertStakeRegistrationWithVoteDelegation:
			v.check(false, ReasonUnsupportedCertVoteRegDeleg, pos)
		case CertStakeRegistrationWithStakeAndVoteDeleg:
			v.check(false, ReasonUnsupportedCertStakeVoteRegDeleg, pos)
		case CertStakeRegistrationConway, CertStakeDeregistrationConway:
			v.uint64(c.Deposit, pos+".deposit")
		}
	}
}

func (v *validator) votingProcedures(vs []VoterVotes) {
	v.list(len(vs), "transaction_body.voting_procedures", true)
	v.check(len(vs) <= 1, ReasonTooManyVotersInVotingProcedures, "transaction_body.voting_procedures")
	for i, vv := range vs {
		v.check(len(vv.Votes) == 1, ReasonInvalidNumberOfVotingProcedures,
			fmt.Sprintf("transaction_body.voting_procedures[%d].votes", i))
		for j, vote := range vv.Votes {
			v.uint64(vote.GovActionID.Index,
				fmt.Sprintf("transaction_body.voting_procedures[%d].votes[%d].govActionId.index", i, j))
		}
	}
}

func (v *validator) poolRegistration(b *Body) {
	if b.PoolRegistration() == nil {
		return
	}
	v.check(len(b.Certificates.Items) == 1, ReasonPoolRegistrationWithOtherCertificates, "transaction_body.certificates")
	v.check(len(b.Withdrawals) == 0, ReasonPoolRegistrationWithWithdrawals, "transaction_body.withdrawals")
	noTokens := true
	for _, g := range b.Mint {
		if len(g.Tokens) > 0 {
			noTokens = false
		}
	}
	v.check(noTokens, ReasonPoolRegistrationWithMintEntry, "transaction_body.mint")
	plain := true
	for _, o := range b.Outputs {
		if o.Datum != nil || o.HasReferenceScript || o.DatumHash != nil {
			plain = false
		}
	}
	v.check(plain, ReasonPoolRegistrationWithPlutusOutputs, "transaction_body.outputs")
	v.check(b.ScriptDataHash == nil, ReasonPoolRegistrationWithScriptDataHash, "transaction_body.script_data_hash")
	v.check(b.CollateralInputs == nil, ReasonPoolRegistrationWithCollateralInputs, "transaction_body.collateral_inputs")
	v.check(b.RequiredSigners == nil, ReasonPoolRegistrationWithRequiredSigners, "transaction_body.required_signers")
	v.check(b.CollateralReturn == nil, ReasonPoolRegistrationWithCollateralReturn, "transaction_body.collateral_return_output")
	v.check(b.TotalCollateral == nil, ReasonPoolRegistrationWithTotalCollateral, "transaction_body.total_collateral")
	v.check(b.ReferenceInputs == nil, ReasonPoolRegistrationWithReferenceInputs, "transaction_body.reference_inputs")
	v.check(!b.HasVotingProcedures, ReasonPoolRegistrationWithVotingProcedures, "transaction_body.voting_procedures")
	v.check(b.Treasury == nil, ReasonPoolRegistrationWithTreasury, "transaction_body.treasury")
	v.check(b.Donation == nil, ReasonPoolRegistrationWithDonation, "transaction_body.donation")
}

func (v *validator) body(b *Body) {
	v.inputs(b.Inputs.Items, "transaction_body.inputs", true)
	v.list(len(b.Outputs), "transaction_body.outputs", true)
	for i, o := range b.Outputs {
		v.output(o, fmt.Sprintf("transaction_body.outputs[%d]", i))
	}
	v.uint64(b.Fee, "transaction_body.fee")
	if b.TTL != nil {
		v.uint64(b.TTL, "transaction_body.ttl")
	}
	if b.Certificates != nil {
		v.certificates(b.Certificates.Items)
	}
	if b.HasWithdrawals {
		v.list(len(b.Withdrawals), "transaction_body.withdrawals", false)
		for _, w := range b.Withdrawals {
			v.uint64(w.Amount, fmt.Sprintf("transaction_body.withdrawals[%s]", hex.EncodeToString(w.RewardAccount)))
		}
	}
	v.check(b.Update == nil, ReasonUnsupportedTxUpdate, "transaction_body.update")
	if b.ValidityIntervalStart != nil {
		v.uint64(b.ValidityIntervalStart, "transaction_body.validity_interval_start")
	}
	if b.HasMint {
		v.multiasset(b.Mint, v.int64, "transaction_body.mint")
	}
	if b.CollateralInputs != nil {
		v.inputs(b.CollateralInputs.Items, "transaction_body.collateral_inputs", false)
	}
	if b.RequiredSigners != nil {
		v.list(len(b.RequiredSigners.Items), "transaction_body.required_signers", false)
	}
	if b.NetworkID != nil {
		v.uint64(b.NetworkID, "transaction_body.network_id")
	}
	if b.CollateralReturn != nil {
		v.collateralReturn(*b.CollateralReturn, "transaction_body.collateral_return_output")
	}
	if b.TotalCollateral != nil {
		v.uint64(b.TotalCollateral, "transaction_body.total_collateral")
	}
	if b.ReferenceInputs != nil {
		v.inputs(b.ReferenceInputs.Items, "transaction_body.reference_inputs", false)
	}
	if b.HasVotingProcedures {
		v.votingProcedures(b.VotingProcedures)
	}
	v.check(b.ProposalProcedures == nil, ReasonUnsupportedTxProposalProcedures, "transaction_body.proposal_procedures")
	if b.Treasury != nil {
		v.uint64(b.Treasury, "transaction_body.treasury")
	}
	if b.Donation != nil {
		v.uint64(b.Donation, "transaction_body.donation")
	}

	v.poolRegistration(b)

	present, missing := false, false
	for _, tag := range b.sets() {
		if *tag {
			present = true
		} else {
			missing = true
		}
	}
	v.check(!(present && missing), ReasonTxInconsistentSetTags, "transaction_body")
}

func validateCommon(input, canonical []byte, b *Body) []ValidationError {
	v := &validator{}
	v.check(bytes.Equal(input, canonical), ReasonCBORIsNotCanonical, "transaction")
	v.body(b)
	return v.errs
}
