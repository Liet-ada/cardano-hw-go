// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tx

import (
	"math/big"

	"github.com/Liet-ada/cardano-hw-go/internal/cbor"
)

// bigValue encodes an integer of any size the way node-cbor does with
// collapsed bignums: a plain integer when it fits in 64 bits.
func bigValue(n *big.Int) cbor.Value {
	if n.Sign() >= 0 {
		if n.IsUint64() {
			return cbor.NewUint(n.Uint64())
		}
		return cbor.NewTag(cbor.TagPosBignum, cbor.NewBytes(n.Bytes()))
	}
	m := new(big.Int).Neg(n)
	m.Sub(m, big.NewInt(1))
	if m.IsUint64() {
		return cbor.Value{Kind: cbor.NegInt, Uint: m.Uint64()}
	}
	return cbor.NewTag(cbor.TagNegBignum, cbor.NewBytes(m.Bytes()))
}

func serializeSet[T any](s Set[T], item func(T) cbor.Value) cbor.Value {
	items := make([]cbor.Value, len(s.Items))
	for i, x := range s.Items {
		items[i] = item(x)
	}
	arr := cbor.NewArray(items...)
	if s.HasTag {
		return cbor.NewTag(cbor.TagSet, arr)
	}
	return arr
}

func serializeInput(in Input) cbor.Value {
	return cbor.NewArray(cbor.NewBytes(in.TxID), bigValue(in.Index))
}

func serializeMultiasset(m Multiasset) cbor.Value {
	policies := make([]cbor.Entry, len(m))
	for i, g := range m {
		tokens := make([]cbor.Entry, len(g.Tokens))
		for j, t := range g.Tokens {
			tokens[j] = cbor.Entry{Key: cbor.NewBytes(t.AssetName), Value: bigValue(t.Amount)}
		}
		policies[i] = cbor.Entry{Key: cbor.NewBytes(g.PolicyID), Value: cbor.NewMap(tokens...)}
	}
	return cbor.NewMap(policies...)
}

func serializeAmount(a Amount) cbor.Value {
	if !a.HasMultiasset {
		return bigValue(a.Coin)
	}
	return cbor.NewArray(bigValue(a.Coin), serializeMultiasset(a.Multiasset))
}

// SerializeOutput returns the CBOR of an output.
func SerializeOutput(o Output) cbor.Value {
	if o.Format == FormatArrayLegacy {
		items := []cbor.Value{cbor.NewBytes(o.Address), serializeAmount(o.Amount)}
		if o.DatumHash != nil {
			items = append(items, cbor.NewBytes(o.DatumHash))
		}
		return cbor.NewArray(items...)
	}
	entries := []cbor.Entry{
		{Key: cbor.NewUint(outKeyAddress), Value: cbor.NewBytes(o.Address)},
		{Key: cbor.NewUint(outKeyAmount), Value: serializeAmount(o.Amount)},
	}
	if o.Datum != nil {
		var d cbor.Value
		if o.Datum.Type == DatumHash {
			d = cbor.NewArray(cbor.NewUint(0), cbor.NewBytes(o.Datum.Hash))
		} else {
			d = cbor.NewArray(cbor.NewUint(1), cbor.NewTag(cbor.TagEncodedCBOR, cbor.NewBytes(o.Datum.Bytes)))
		}
		entries = append(entries, cbor.Entry{Key: cbor.NewUint(outKeyDatum), Value: d})
	}
	if o.HasReferenceScript {
		entries = append(entries, cbor.Entry{
			Key:   cbor.NewUint(outKeyReferenceScript),
			Value: cbor.NewTag(cbor.TagEncodedCBOR, cbor.NewBytes(o.ReferenceScript)),
		})
	}
	return cbor.NewMap(entries...)
}

func serializeCredential(c Credential) cbor.Value {
	return cbor.NewArray(cbor.NewUint(uint64(c.Type)), cbor.NewBytes(c.Hash))
}

func serializeDRep(d DRep) cbor.Value {
	if d.Type == DRepKeyHash || d.Type == DRepScriptHash {
		return cbor.NewArray(cbor.NewUint(uint64(d.Type)), cbor.NewBytes(d.Hash))
	}
	return cbor.NewArray(cbor.NewUint(uint64(d.Type)))
}

func serializeAnchor(a *Anchor) cbor.Value {
	if a == nil {
		return cbor.Null
	}
	return cbor.NewArray(cbor.NewText(a.URL), cbor.NewBytes(a.DataHash))
}

func nullableBytes(b []byte) cbor.Value {
	if b == nil {
		return cbor.Null
	}
	return cbor.NewBytes(b)
}

func serializeRelay(r Relay) cbor.Value {
	port := cbor.Null
	if r.Port != nil {
		port = cbor.NewUint(*r.Port)
	}
	t := cbor.NewUint(uint64(r.Type))
	switch r.Type {
	case RelaySingleHostAddress:
		return cbor.NewArray(t, port, nullableBytes(r.IPv4), nullableBytes(r.IPv6))
	case RelaySingleHostName:
		return cbor.NewArray(t, port, cbor.NewText(r.DNSName))
	}
	return cbor.NewArray(t, cbor.NewText(r.DNSName))
}

func serializePoolParams(p *PoolParams) []cbor.Value {
	relays := make([]cbor.Value, len(p.Relays))
	for i, r := range p.Relays {
		relays[i] = serializeRelay(r)
	}
	meta := cbor.Null
	if p.Metadata != nil {
		meta = cbor.NewArray(cbor.NewText(p.Metadata.URL), cbor.NewBytes(p.Metadata.Hash))
	}
	return []cbor.Value{
		cbor.NewBytes(p.Operator),
		cbor.NewBytes(p.VRFKeyHash),
		bigValue(p.Pledge),
		bigValue(p.Cost),
		cbor.NewTag(cbor.TagRational, cbor.NewArray(bigValue(p.Margin[0]), bigValue(p.Margin[1]))),
		cbor.NewBytes(p.RewardAccount),
		serializeSet(p.Owners, func(b []byte) cbor.Value { return cbor.NewBytes(b) }),
		cbor.NewArray(relays...),
		meta,
	}
}

func serializeCertificate(c Certificate) cbor.Value {
	t := cbor.NewUint(uint64(c.Type))
	arr := func(items ...cbor.Value) cbor.Value { return cbor.NewArray(append([]cbor.Value{t}, items...)...) }
	switch c.Type {
	case CertStakeRegistration, CertStakeDeregistration:
		return arr(serializeCredential(c.StakeCredential))
	case CertStakeDelegation:
		return arr(serializeCredential(c.StakeCredential), cbor.NewBytes(c.PoolKeyHash))
	case CertPoolRegistration:
		return arr(serializePoolParams(c.PoolParams)...)
	case CertPoolRetirement:
		return arr(cbor.NewBytes(c.PoolKeyHash), bigValue(c.Epoch))
	case CertGenesisKeyDelegation, CertMoveInstantaneousRewards:
		return arr(c.Rest...)
	case CertStakeRegistrationConway, CertStakeDeregistrationConway:
		return arr(serializeCredential(c.StakeCredential), bigValue(c.Deposit))
	case CertVoteDelegation:
		return arr(serializeCredential(c.StakeCredential), serializeDRep(c.DRep))
	case CertStakeAndVoteDelegation:
		return arr(serializeCredential(c.StakeCredential), cbor.NewBytes(c.PoolKeyHash), serializeDRep(c.DRep))
	case CertStakeRegistrationAndDelegation:
		return arr(serializeCredential(c.StakeCredential), cbor.NewBytes(c.PoolKeyHash), bigValue(c.Deposit))
	case CertStakeRegistrationWithVoteDelegation:
		return arr(serializeCredential(c.StakeCredential), serializeDRep(c.DRep), bigValue(c.Deposit))
	case CertStakeRegistrationWithStakeAndVoteDeleg:
		return arr(serializeCredential(c.StakeCredential), cbor.NewBytes(c.PoolKeyHash), serializeDRep(c.DRep), bigValue(c.Deposit))
	case CertAuthorizeCommitteeHot:
		return arr(serializeCredential(c.ColdCredential), serializeCredential(c.HotCredential))
	case CertResignCommitteeCold:
		return arr(serializeCredential(c.ColdCredential), serializeAnchor(c.Anchor))
	case CertDRepRegistration:
		return arr(serializeCredential(c.DRepCredential), bigValue(c.Deposit), serializeAnchor(c.Anchor))
	case CertDRepDeregistration:
		return arr(serializeCredential(c.DRepCredential), bigValue(c.Deposit))
	case CertDRepUpdate:
		return arr(serializeCredential(c.DRepCredential), serializeAnchor(c.Anchor))
	}
	panic("tx: serializing a certificate of unknown type")
}

func serializeVotingProcedures(vs []VoterVotes) cbor.Value {
	voters := make([]cbor.Entry, len(vs))
	for i, vv := range vs {
		votes := make([]cbor.Entry, len(vv.Votes))
		for j, v := range vv.Votes {
			votes[j] = cbor.Entry{
				Key:   cbor.NewArray(cbor.NewBytes(v.GovActionID.TxID), bigValue(v.GovActionID.Index)),
				Value: cbor.NewArray(cbor.NewUint(uint64(v.Procedure.Vote)), serializeAnchor(v.Procedure.Anchor)),
			}
		}
		voters[i] = cbor.Entry{
			Key:   cbor.NewArray(cbor.NewUint(uint64(vv.Voter.Type)), cbor.NewBytes(vv.Voter.Hash)),
			Value: cbor.NewMap(votes...),
		}
	}
	return cbor.NewMap(voters...)
}

// SerializeBody returns the CBOR of a body.
func SerializeBody(b *Body) cbor.Value {
	var e []cbor.Entry
	add := func(k uint64, v cbor.Value) { e = append(e, cbor.Entry{Key: cbor.NewUint(k), Value: v}) }

	add(keyInputs, serializeSet(b.Inputs, serializeInput))
	outs := make([]cbor.Value, len(b.Outputs))
	for i, o := range b.Outputs {
		outs[i] = SerializeOutput(o)
	}
	add(keyOutputs, cbor.NewArray(outs...))
	add(keyFee, bigValue(b.Fee))
	if b.TTL != nil {
		add(keyTTL, bigValue(b.TTL))
	}
	if b.Certificates != nil {
		add(keyCertificates, serializeSet(*b.Certificates, serializeCertificate))
	}
	if b.HasWithdrawals {
		w := make([]cbor.Entry, len(b.Withdrawals))
		for i, x := range b.Withdrawals {
			w[i] = cbor.Entry{Key: cbor.NewBytes(x.RewardAccount), Value: bigValue(x.Amount)}
		}
		add(keyWithdrawals, cbor.NewMap(w...))
	}
	if b.Update != nil {
		add(keyUpdate, *b.Update)
	}
	if b.AuxiliaryDataHash != nil {
		add(keyAuxiliaryDataHash, cbor.NewBytes(b.AuxiliaryDataHash))
	}
	if b.ValidityIntervalStart != nil {
		add(keyValidityIntervalStart, bigValue(b.ValidityIntervalStart))
	}
	if b.HasMint {
		add(keyMint, serializeMultiasset(b.Mint))
	}
	if b.ScriptDataHash != nil {
		add(keyScriptDataHash, cbor.NewBytes(b.ScriptDataHash))
	}
	if b.CollateralInputs != nil {
		add(keyCollateralInputs, serializeSet(*b.CollateralInputs, serializeInput))
	}
	if b.RequiredSigners != nil {
		add(keyRequiredSigners, serializeSet(*b.RequiredSigners, func(h []byte) cbor.Value { return cbor.NewBytes(h) }))
	}
	if b.NetworkID != nil {
		add(keyNetworkID, bigValue(b.NetworkID))
	}
	if b.CollateralReturn != nil {
		add(keyCollateralReturn, SerializeOutput(*b.CollateralReturn))
	}
	if b.TotalCollateral != nil {
		add(keyTotalCollateral, bigValue(b.TotalCollateral))
	}
	if b.ReferenceInputs != nil {
		add(keyReferenceInputs, serializeSet(*b.ReferenceInputs, serializeInput))
	}
	if b.HasVotingProcedures {
		add(keyVotingProcedures, serializeVotingProcedures(b.VotingProcedures))
	}
	if b.ProposalProcedures != nil {
		add(keyProposalProcedures, serializeSet(*b.ProposalProcedures, func(p ProposalProcedure) cbor.Value {
			return cbor.NewArray(bigValue(p.Deposit), cbor.NewBytes(p.RewardAccount), p.GovAction, serializeAnchor(&p.Anchor))
		}))
	}
	if b.Treasury != nil {
		add(keyTreasury, bigValue(b.Treasury))
	}
	if b.Donation != nil {
		add(keyDonation, bigValue(b.Donation))
	}
	return cbor.NewMap(e...)
}

// SerializeTx returns the CBOR of a transaction.
func SerializeTx(t *Transaction) cbor.Value {
	items := []cbor.Value{SerializeBody(&t.Body), t.WitnessSet}
	if t.ScriptValidity != nil {
		items = append(items, *t.ScriptValidity)
	}
	return cbor.NewArray(append(items, t.AuxiliaryData)...)
}
