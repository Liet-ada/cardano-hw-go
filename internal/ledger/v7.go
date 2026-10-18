// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package ledger

import (
	"fmt"

	"github.com/Liet-ada/cardano-hw-go/internal/cardano"
)

// The command set of Cardano app versions 7.x (Conway era), ported from
// ledgerjs-hw-app-cardano's interactions/v7.

// v7 stages of sign transaction.
const (
	v7Init            = 0x01
	v7AuxData         = 0x08
	v7Inputs          = 0x02
	v7Outputs         = 0x03
	v7Fee             = 0x04
	v7TTL             = 0x05
	v7Certificates    = 0x06
	v7Withdrawals     = 0x07
	v7ValidityStart   = 0x09
	v7Mint            = 0x0b
	v7ScriptDataHash  = 0x0c
	v7Collateral      = 0x0d
	v7RequiredSigners = 0x0e
	v7CollateralOut   = 0x12
	v7TotalCollateral = 0x10
	v7ReferenceInputs = 0x11
	v7Voting          = 0x13
	v7Treasury        = 0x15
	v7Donation        = 0x16
	v7Confirm         = 0x0a
	v7Witnesses       = 0x0f

	v7ChunkSize = 240
)

// v7 credential types: key path 0, script hash 1, key hash 2.
func v7Credential(c Credential) []byte {
	switch c.Kind {
	case CredKeyPath:
		return cat(u8(0), pathBytes(c.Path))
	case CredScriptHash:
		return cat(u8(1), c.Hash)
	}
	return cat(u8(2), c.Hash)
}

func v7Anchor(a *Anchor) []byte {
	if a == nil {
		return included(false)
	}
	return cat(included(true), a.Hash, []byte(a.URL))
}

func v7DRep(d DRep) []byte {
	switch d.Type {
	case DRepKeyPath:
		return cat(u8(d.Type), pathBytes(d.Path))
	case DRepKeyHash, DRepScriptHash:
		return cat(u8(d.Type), d.Hash)
	}
	return u8(d.Type)
}

func v7Destination(d Destination) ([]byte, error) {
	if !d.DeviceOwned {
		return cat(u8(1), u32(uint32(len(d.Address))), d.Address), nil
	}
	p, err := addressParamsBytes(d.Params)
	if err != nil {
		return nil, err
	}
	return cat(u8(2), p), nil
}

// v7Send sends one step of sign transaction, which returns nothing.
func (a *App) v7Send(p1, p2 byte, data []byte) ([]byte, error) {
	return a.send(insSignTx, p1, p2, data, 0)
}

func (a *App) v7TokenBundle(p1 byte, groups []AssetGroup, mint bool) error {
	for _, g := range groups {
		if _, err := a.v7Send(p1, 0x31, cat(g.PolicyID, u32(uint32(len(g.Tokens))))); err != nil {
			return err
		}
		for _, t := range g.Tokens {
			amount := u64(t.Amount)
			if mint {
				amount = i64(t.Mint)
			}
			if _, err := a.v7Send(p1, 0x32, cat(u32(uint32(len(t.AssetName))), t.AssetName, amount)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *App) v7Chunks(p1, p2 byte, data []byte) error {
	for start := v7ChunkSize; start < len(data); start += v7ChunkSize {
		end := min(len(data), start+v7ChunkSize)
		if _, err := a.v7Send(p1, p2, cat(u32(uint32(end-start)), data[start:end])); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) v7Output(p1 byte, o Output, withData bool) error {
	dest, err := v7Destination(o.Destination)
	if err != nil {
		return err
	}
	basic := cat(u8(o.Format), dest, u64(o.Amount), u32(uint32(len(o.Tokens))), included(o.HasDatum), included(o.HasRefScript))
	if _, err := a.v7Send(p1, 0x30, basic); err != nil {
		return err
	}
	if err := a.v7TokenBundle(p1, o.Tokens, false); err != nil {
		return err
	}
	if withData && o.HasDatum {
		var data []byte
		if o.DatumInline {
			first := o.Datum[:min(len(o.Datum), v7ChunkSize)]
			data = cat(u8(1), u32(uint32(len(o.Datum))), u32(uint32(len(first))), first)
		} else {
			data = cat(u8(0), o.Datum)
		}
		if _, err := a.v7Send(p1, 0x34, data); err != nil {
			return err
		}
		if o.DatumInline {
			if err := a.v7Chunks(p1, 0x35, o.Datum); err != nil {
				return err
			}
		}
	}
	if withData && o.HasRefScript {
		first := o.RefScript[:min(len(o.RefScript), v7ChunkSize)]
		if _, err := a.v7Send(p1, 0x36, cat(u32(uint32(len(o.RefScript))), u32(uint32(len(first))), first)); err != nil {
			return err
		}
		if err := a.v7Chunks(p1, 0x37, o.RefScript); err != nil {
			return err
		}
	}
	_, err = a.v7Send(p1, 0x33, nil)
	return err
}

func v7Certificate(c Certificate) ([]byte, error) {
	t := u8(c.Type)
	switch c.Type {
	case CertStakeRegistration, CertStakeDeregistration:
		return cat(t, v7Credential(c.StakeCredential)), nil
	case CertStakeRegistrationConway, CertStakeDeregistrationConway:
		return cat(t, v7Credential(c.StakeCredential), u64(c.Deposit)), nil
	case CertStakeDelegation:
		return cat(t, v7Credential(c.StakeCredential), c.PoolKeyHash), nil
	case CertVoteDelegation:
		return cat(t, v7Credential(c.StakeCredential), v7DRep(c.DRep)), nil
	case CertAuthorizeCommitteeHot:
		return cat(t, v7Credential(c.ColdCredential), v7Credential(c.HotCredential)), nil
	case CertResignCommitteeCold:
		return cat(t, v7Credential(c.ColdCredential), v7Anchor(c.Anchor)), nil
	case CertDRepRegistration:
		return cat(t, v7Credential(c.DRepCredential), u64(c.Deposit), v7Anchor(c.Anchor)), nil
	case CertDRepDeregistration:
		return cat(t, v7Credential(c.DRepCredential), u64(c.Deposit)), nil
	case CertDRepUpdate:
		return cat(t, v7Credential(c.DRepCredential), v7Anchor(c.Anchor)), nil
	case CertPoolRegistration:
		return t, nil
	case CertPoolRetirement:
		return cat(t, pathBytes(c.RetirementPath), u64(c.RetirementEpoch)), nil
	}
	return nil, fmt.Errorf("ledger: certificate type %d not supported by app v7", c.Type)
}

func optional(present bool, data []byte) []byte {
	if !present {
		return u8(1)
	}
	return cat(u8(2), data)
}

func (a *App) v7PoolRegistration(p *PoolParams) error {
	send := func(p2 byte, data []byte) error {
		_, err := a.v7Send(v7Certificates, p2, data)
		return err
	}
	if err := send(0x30, cat(u32(uint32(len(p.Owners))), u32(uint32(len(p.Relays))))); err != nil {
		return err
	}
	poolKey := cat(u8(2), p.PoolKeyHash)
	if p.PoolKeyPath != nil {
		poolKey = cat(u8(1), pathBytes(p.PoolKeyPath))
	}
	if err := send(0x31, poolKey); err != nil {
		return err
	}
	if err := send(0x32, p.VRFKeyHash); err != nil {
		return err
	}
	if err := send(0x33, cat(u64(p.Pledge), u64(p.Cost), u64(p.MarginNumerator), u64(p.MarginDenominator))); err != nil {
		return err
	}
	reward := cat(u8(2), p.RewardAccount)
	if p.RewardPath != nil {
		reward = cat(u8(1), pathBytes(p.RewardPath))
	}
	if err := send(0x34, reward); err != nil {
		return err
	}
	for _, o := range p.Owners {
		owner := cat(u8(2), o.Hash)
		if o.Kind == CredKeyPath {
			owner = cat(u8(1), pathBytes(o.Path))
		}
		if err := send(0x35, owner); err != nil {
			return err
		}
	}
	for _, r := range p.Relays {
		var data []byte
		switch r.Type {
		case 0:
			var port []byte
			if r.Port != nil {
				port = u16(*r.Port)
			}
			data = cat(u8(0), optional(r.Port != nil, port), optional(r.IPv4 != nil, r.IPv4), optional(r.IPv6 != nil, r.IPv6))
		case 1:
			var port []byte
			if r.Port != nil {
				port = u16(*r.Port)
			}
			data = cat(u8(1), optional(r.Port != nil, port), []byte(r.DNSName))
		default:
			data = cat(u8(2), []byte(r.DNSName))
		}
		if err := send(0x36, data); err != nil {
			return err
		}
	}
	meta := u8(1)
	if p.MetadataHash != nil {
		meta = cat(u8(2), p.MetadataHash, []byte(p.MetadataURL))
	}
	if err := send(0x37, meta); err != nil {
		return err
	}
	return send(0x38, nil)
}

func v7Voter(v Voter) []byte {
	switch v.Type {
	case VoterCommitteeKeyPath, VoterDRepKeyPath, VoterStakePoolKeyPath:
		return cat(u8(v.Type), pathBytes(v.Path))
	}
	return cat(u8(v.Type), v.Hash)
}

func (a *App) v7AuxData(tx *Tx) (hash, sig []byte, err error) {
	if tx.AuxDataHash != nil {
		_, err := a.v7Send(v7AuxData, 0x00, cat(u8(0), tx.AuxDataHash))
		return nil, nil, err
	}
	r := tx.CIP36
	if _, err := a.v7Send(v7AuxData, 0x00, u8(1)); err != nil {
		return nil, nil, err
	}
	if _, err := a.v7Send(v7AuxData, 0x36, cat(u8(2), u32(uint32(len(r.Delegations))))); err != nil {
		return nil, nil, err
	}
	for _, d := range r.Delegations {
		var data []byte
		if d.VoteKeyPath != nil {
			data = cat(u8(2), pathBytes(d.VoteKeyPath), u32(d.Weight))
		} else {
			data = cat(u8(1), d.VoteKey, u32(d.Weight))
		}
		if _, err := a.v7Send(v7AuxData, 0x37, data); err != nil {
			return nil, nil, err
		}
	}
	if _, err := a.v7Send(v7AuxData, 0x31, pathBytes(r.StakingPath)); err != nil {
		return nil, nil, err
	}
	dest, err := v7Destination(r.Destination)
	if err != nil {
		return nil, nil, err
	}
	if _, err := a.v7Send(v7AuxData, 0x32, dest); err != nil {
		return nil, nil, err
	}
	if _, err := a.v7Send(v7AuxData, 0x33, u64(r.Nonce)); err != nil {
		return nil, nil, err
	}
	if _, err := a.v7Send(v7AuxData, 0x35, cat(included(true), u64(r.VotingPurpose))); err != nil {
		return nil, nil, err
	}
	resp, err := a.send(insSignTx, v7AuxData, 0x34, nil, auxHashLength+signatureLength)
	if err != nil {
		return nil, nil, err
	}
	return resp[:auxHashLength], resp[auxHashLength:], nil
}

func (a *App) v7SignTx(req *SignRequest, witnesses []cardano.Path) (*SignedTx, error) {
	tx := &req.Tx
	options := uint64(0)
	if req.TagCborSets {
		options = 1
	}
	init := cat(
		u64(options),
		u8(tx.NetworkID), u32(tx.ProtocolMagic),
		included(tx.TTL != nil), included(tx.hasAuxData()), included(tx.ValidityStart != nil),
		included(tx.HasMint), included(tx.ScriptDataHash != nil), included(tx.IncludeNetworkID),
		included(tx.CollateralOutput != nil), included(tx.TotalCollateral != nil),
		included(tx.Treasury != nil), included(tx.Donation != nil),
		u8(req.Mode),
		u32(uint32(len(tx.Inputs))), u32(uint32(len(tx.Outputs))),
		u32(uint32(len(tx.Certificates))), u32(uint32(len(tx.Withdrawals))),
		u32(uint32(len(tx.Collateral))), u32(uint32(len(tx.RequiredSigners))),
		u32(uint32(len(tx.ReferenceInputs))), u32(uint32(len(tx.VotingProcedures))),
		u32(uint32(len(witnesses))),
	)
	if _, err := a.v7Send(v7Init, 0, init); err != nil {
		return nil, err
	}
	out := &SignedTx{}
	if tx.hasAuxData() {
		h, s, err := a.v7AuxData(tx)
		if err != nil {
			return nil, err
		}
		out.AuxDataHash, out.CIP36Signature = h, s
	}
	for _, in := range tx.Inputs {
		if _, err := a.v7Send(v7Inputs, 0, cat(in.TxHash, u32(in.Index))); err != nil {
			return nil, err
		}
	}
	for _, o := range tx.Outputs {
		if err := a.v7Output(v7Outputs, o, true); err != nil {
			return nil, err
		}
	}
	if _, err := a.v7Send(v7Fee, 0, u64(tx.Fee)); err != nil {
		return nil, err
	}
	if tx.TTL != nil {
		if _, err := a.v7Send(v7TTL, 0, u64(*tx.TTL)); err != nil {
			return nil, err
		}
	}
	for _, c := range tx.Certificates {
		data, err := v7Certificate(c)
		if err != nil {
			return nil, err
		}
		if _, err := a.v7Send(v7Certificates, 0, data); err != nil {
			return nil, err
		}
		if c.Type == CertPoolRegistration {
			if err := a.v7PoolRegistration(c.Pool); err != nil {
				return nil, err
			}
		}
	}
	for _, w := range tx.Withdrawals {
		if _, err := a.v7Send(v7Withdrawals, 0, cat(u64(w.Amount), v7Credential(w.Credential))); err != nil {
			return nil, err
		}
	}
	if tx.ValidityStart != nil {
		if _, err := a.send(insSignTx, v7ValidityStart, 0, u64(*tx.ValidityStart), anyLength); err != nil {
			return nil, err
		}
	}
	if tx.HasMint {
		if _, err := a.v7Send(v7Mint, 0x30, u32(uint32(len(tx.Mint)))); err != nil {
			return nil, err
		}
		if err := a.v7TokenBundle(v7Mint, tx.Mint, true); err != nil {
			return nil, err
		}
		if _, err := a.v7Send(v7Mint, 0x33, nil); err != nil {
			return nil, err
		}
	}
	if tx.ScriptDataHash != nil {
		if _, err := a.send(insSignTx, v7ScriptDataHash, 0, tx.ScriptDataHash, anyLength); err != nil {
			return nil, err
		}
	}
	for _, in := range tx.Collateral {
		if _, err := a.v7Send(v7Collateral, 0, cat(in.TxHash, u32(in.Index))); err != nil {
			return nil, err
		}
	}
	for _, s := range tx.RequiredSigners {
		data := cat(u8(1), s.Hash)
		if s.Path != nil {
			data = cat(u8(0), pathBytes(s.Path))
		}
		if _, err := a.v7Send(v7RequiredSigners, 0, data); err != nil {
			return nil, err
		}
	}
	if tx.CollateralOutput != nil {
		if err := a.v7Output(v7CollateralOut, *tx.CollateralOutput, false); err != nil {
			return nil, err
		}
	}
	if tx.TotalCollateral != nil {
		if _, err := a.v7Send(v7TotalCollateral, 0, u64(*tx.TotalCollateral)); err != nil {
			return nil, err
		}
	}
	for _, in := range tx.ReferenceInputs {
		if _, err := a.v7Send(v7ReferenceInputs, 0, cat(in.TxHash, u32(in.Index))); err != nil {
			return nil, err
		}
	}
	for _, vv := range tx.VotingProcedures {
		if len(vv.Votes) != 1 {
			return nil, assertion("too few / too many votes")
		}
		v := vv.Votes[0]
		data := cat(v7Voter(vv.Voter), v.GovActionTx, u32(v.GovActionIndex), u8(v.Option), v7Anchor(v.Anchor))
		if _, err := a.v7Send(v7Voting, 0, data); err != nil {
			return nil, err
		}
	}
	if tx.Treasury != nil {
		if _, err := a.v7Send(v7Treasury, 0, u64(*tx.Treasury)); err != nil {
			return nil, err
		}
	}
	if tx.Donation != nil {
		if _, err := a.v7Send(v7Donation, 0, u64(*tx.Donation)); err != nil {
			return nil, err
		}
	}
	h, err := a.send(insSignTx, v7Confirm, 0, nil, txHashLength)
	if err != nil {
		return nil, err
	}
	out.TxHash = h
	for _, p := range witnesses {
		sig, err := a.send(insSignTx, v7Witnesses, 0, pathBytes(p), signatureLength)
		if err != nil {
			return nil, err
		}
		out.Witnesses = append(out.Witnesses, PathSignature{p, sig})
	}
	return out, nil
}
