// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package ledger

import (
	"fmt"

	"github.com/Liet-ada/cardano-hw-go/internal/cardano"
)

// The command set of Cardano app versions 8 and newer, ported from
// ledgerjs-hw-app-cardano's interactions/v8: the transaction travels as one
// binary payload, in chunks.

const (
	v8SignWitness = 0x0f
	v8Init        = 0x10
	v8Chunk       = 0x11
	v8Confirm     = 0x12
	v8AuxData     = 0x13

	v8AuxDataInit       = 0x36
	v8AuxDataDelegation = 0x37

	v8ChunkSize = 250
)

// v8 credential types: key hash 0, script hash 1, key path 2.
func v8Credential(c Credential) []byte {
	switch c.Kind {
	case CredKeyPath:
		return cat(u8(2), pathBytes(c.Path))
	case CredScriptHash:
		return cat(u8(1), c.Hash)
	}
	return cat(u8(0), c.Hash)
}

func v8Anchor(a *Anchor) []byte {
	if a == nil {
		return included(false)
	}
	return cat(included(true), u16(uint16(len(a.URL))), []byte(a.URL), a.Hash)
}

func v8Destination(d Destination) ([]byte, error) {
	if !d.DeviceOwned {
		return cat(u8(1), u16(uint16(len(d.Address))), d.Address), nil
	}
	p, err := addressParamsBytes(d.Params)
	if err != nil {
		return nil, err
	}
	return cat(u8(2), p), nil
}

func v8Tokens(groups []AssetGroup, mint bool) ([]byte, error) {
	var out []byte
	for _, g := range groups {
		out = append(out, g.PolicyID...)
		out = append(out, u16(uint16(len(g.Tokens)))...)
		for _, t := range g.Tokens {
			if len(t.AssetName) > 255 {
				if mint {
					return nil, assertion("assetName too long")
				}
				return nil, assertion("invalid uint8")
			}
			out = append(out, byte(len(t.AssetName)))
			out = append(out, t.AssetName...)
			if mint {
				out = append(out, i64(t.Mint)...)
			} else {
				out = append(out, u64(t.Amount)...)
			}
		}
	}
	return out, nil
}

func v8Output(o Output) ([]byte, error) {
	dest, err := v8Destination(o.Destination)
	if err != nil {
		return nil, err
	}
	out := cat(dest, u64(o.Amount), u8(o.Format), included(o.HasDatum), included(o.HasRefScript), u16(uint16(len(o.Tokens))))
	tokens, err := v8Tokens(o.Tokens, false)
	if err != nil {
		return nil, err
	}
	out = append(out, tokens...)
	if o.HasDatum {
		if o.DatumInline {
			out = append(out, cat(u8(1), u16(uint16(len(o.Datum))), o.Datum)...)
		} else {
			out = append(out, cat(u8(0), o.Datum)...)
		}
	}
	if o.HasRefScript {
		out = append(out, cat(u16(uint16(len(o.RefScript))), o.RefScript)...)
	}
	if len(out) > 0xffff {
		return nil, assertion("output too large")
	}
	return cat(u16(uint16(len(out))), out), nil
}

func v8DRep(d DRep) []byte {
	switch d.Type {
	case DRepKeyPath:
		return cat(u8(d.Type), pathBytes(d.Path))
	case DRepKeyHash, DRepScriptHash:
		return cat(u8(d.Type), d.Hash)
	}
	return u8(d.Type)
}

func v8Relay(r Relay) ([]byte, error) {
	var port []byte
	if r.Port != nil {
		port = u16(*r.Port)
	}
	switch r.Type {
	case 0:
		return cat(u8(0), included(r.Port != nil), port, included(r.IPv4 != nil), r.IPv4, included(r.IPv6 != nil), r.IPv6), nil
	case 1:
		if len(r.DNSName) > 255 {
			return nil, assertion("dnsName too long")
		}
		return cat(u8(1), included(r.Port != nil), port, included(true), u8(uint8(len(r.DNSName))), []byte(r.DNSName)), nil
	}
	if len(r.DNSName) > 255 {
		return nil, assertion("dnsName too long")
	}
	return cat(u8(2), included(true), u8(uint8(len(r.DNSName))), []byte(r.DNSName)), nil
}

func v8PoolRegistration(p *PoolParams) ([]byte, error) {
	poolKey := Credential{Kind: CredKeyHash, Hash: p.PoolKeyHash}
	if p.PoolKeyPath != nil {
		poolKey = Credential{Kind: CredKeyPath, Path: p.PoolKeyPath}
	}
	reward := cat(u8(0), p.RewardAccount)
	if p.RewardPath != nil {
		reward = cat(u8(2), pathBytes(p.RewardPath))
	}
	out := cat(v8Credential(poolKey), p.VRFKeyHash, u64(p.Pledge), u64(p.Cost), u64(p.MarginNumerator), u64(p.MarginDenominator),
		reward, u16(uint16(len(p.Owners))), u16(uint16(len(p.Relays))), included(p.MetadataHash != nil))
	for _, o := range p.Owners {
		out = append(out, v8Credential(o)...)
	}
	for _, r := range p.Relays {
		b, err := v8Relay(r)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	if p.MetadataHash != nil {
		out = append(out, cat(u16(uint16(len(p.MetadataURL))), []byte(p.MetadataURL), p.MetadataHash)...)
	}
	return cat(u16(uint16(len(out))), out), nil
}

func v8Certificate(c Certificate) ([]byte, error) {
	t := u8(c.Type)
	switch c.Type {
	case CertStakeRegistration, CertStakeDeregistration:
		return cat(t, v8Credential(c.StakeCredential)), nil
	case CertStakeRegistrationConway, CertStakeDeregistrationConway:
		return cat(t, v8Credential(c.StakeCredential), u64(c.Deposit)), nil
	case CertStakeDelegation:
		return cat(t, v8Credential(c.StakeCredential), c.PoolKeyHash), nil
	case CertVoteDelegation:
		return cat(t, v8Credential(c.StakeCredential), v8DRep(c.DRep)), nil
	case CertAuthorizeCommitteeHot:
		return cat(t, v8Credential(c.ColdCredential), v8Credential(c.HotCredential)), nil
	case CertResignCommitteeCold:
		return cat(t, v8Credential(c.ColdCredential), v8Anchor(c.Anchor)), nil
	case CertDRepRegistration:
		return cat(t, v8Credential(c.DRepCredential), u64(c.Deposit), v8Anchor(c.Anchor)), nil
	case CertDRepDeregistration:
		return cat(t, v8Credential(c.DRepCredential), u64(c.Deposit)), nil
	case CertDRepUpdate:
		return cat(t, v8Credential(c.DRepCredential), v8Anchor(c.Anchor)), nil
	case CertPoolRegistration:
		p, err := v8PoolRegistration(c.Pool)
		return cat(t, p), err
	case CertPoolRetirement:
		return cat(t, v8Credential(Credential{Kind: CredKeyPath, Path: c.RetirementPath}), u64(c.RetirementEpoch)), nil
	}
	return nil, fmt.Errorf("ledger: certificate type %d not supported", c.Type)
}

func v8Voter(v Voter) []byte {
	switch v.Type {
	case VoterCommitteeKeyPath, VoterDRepKeyPath, VoterStakePoolKeyPath:
		return cat(u8(v.Type), pathBytes(v.Path))
	}
	return cat(u8(v.Type), v.Hash)
}

// v8RawTx is the binary payload of a transaction body.
func v8RawTx(tx *Tx) ([]byte, error) {
	var out []byte
	for _, in := range tx.Inputs {
		out = append(out, cat(in.TxHash, u32(in.Index))...)
	}
	for _, o := range tx.Outputs {
		b, err := v8Output(o)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	out = append(out, u64(tx.Fee)...)
	if tx.TTL != nil {
		out = append(out, u64(*tx.TTL)...)
	}
	for _, c := range tx.Certificates {
		b, err := v8Certificate(c)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	for _, w := range tx.Withdrawals {
		out = append(out, cat(u64(w.Amount), v8Credential(w.Credential))...)
	}
	if tx.ValidityStart != nil {
		out = append(out, u64(*tx.ValidityStart)...)
	}
	if tx.HasMint {
		b, err := v8Tokens(tx.Mint, true)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	out = append(out, tx.ScriptDataHash...)
	for _, in := range tx.Collateral {
		out = append(out, cat(in.TxHash, u32(in.Index))...)
	}
	for _, s := range tx.RequiredSigners {
		if s.Path != nil {
			out = append(out, cat(u8(0), pathBytes(s.Path))...)
		} else {
			out = append(out, cat(u8(1), s.Hash)...)
		}
	}
	if tx.CollateralOutput != nil {
		b, err := v8Output(*tx.CollateralOutput)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	if tx.TotalCollateral != nil {
		out = append(out, u64(*tx.TotalCollateral)...)
	}
	for _, in := range tx.ReferenceInputs {
		out = append(out, cat(in.TxHash, u32(in.Index))...)
	}
	for _, vv := range tx.VotingProcedures {
		out = append(out, v8Voter(vv.Voter)...)
		out = append(out, u16(uint16(len(vv.Votes)))...)
		for _, v := range vv.Votes {
			out = append(out, cat(v.GovActionTx, u32(v.GovActionIndex), u8(v.Option), v8Anchor(v.Anchor))...)
		}
	}
	if tx.Treasury != nil {
		out = append(out, u64(*tx.Treasury)...)
	}
	if tx.Donation != nil {
		out = append(out, u64(*tx.Donation)...)
	}
	if len(out) > 0xffff {
		return nil, assertion("invalid uint16")
	}
	return out, nil
}

func voteKey(path cardano.Path, key []byte) []byte {
	if path != nil {
		return cat(u8(2), pathBytes(path))
	}
	return cat(u8(0), key)
}

func (a *App) v8SignTx(req *SignRequest, witnesses []cardano.Path) (*SignedTx, error) {
	tx := &req.Tx
	raw, err := v8RawTx(tx)
	if err != nil {
		return nil, err
	}
	options := uint64(0)
	if req.TagCborSets {
		options = 1
	}
	init := cat(u64(options), u8(tx.NetworkID), u32(tx.ProtocolMagic), u8(req.Mode),
		u16(uint16(len(tx.Inputs))), u16(uint16(len(tx.Outputs))), included(tx.TTL != nil),
		u16(uint16(len(tx.Certificates))), u16(uint16(len(tx.Withdrawals))), included(tx.hasAuxData()))
	switch {
	case tx.AuxDataHash != nil:
		init = append(init, cat(u8(0), tx.AuxDataHash)...)
	case tx.CIP36 != nil:
		init = append(init, 1)
	}
	init = append(init, cat(included(tx.ValidityStart != nil), u16(uint16(len(tx.Mint))), included(tx.ScriptDataHash != nil),
		u16(uint16(len(tx.Collateral))), u16(uint16(len(tx.RequiredSigners))), included(tx.IncludeNetworkID),
		included(tx.CollateralOutput != nil), included(tx.TotalCollateral != nil), u16(uint16(len(tx.ReferenceInputs))),
		u16(uint16(len(tx.VotingProcedures))), included(tx.Treasury != nil), included(tx.Donation != nil),
		u16(uint16(len(witnesses))), u16(uint16(len(raw))))...)
	if _, err := a.send(insSignTx, v8Init, 0, init, 0); err != nil {
		return nil, err
	}
	out := &SignedTx{}
	if r := tx.CIP36; r != nil {
		dest, err := v8Destination(r.Destination)
		if err != nil {
			return nil, err
		}
		data := cat(u8(2), u16(uint16(len(r.Delegations))), voteKey(r.StakingPath, nil), dest, u64(r.Nonce), u64(r.VotingPurpose))
		// the last APDU returns the auxiliary data hash and the signature
		want := func(last bool) int {
			if last {
				return auxHashLength + signatureLength
			}
			return 0
		}
		resp, err := a.send(insSignTx, v8AuxData, v8AuxDataInit, data, want(len(r.Delegations) == 0))
		if err != nil {
			return nil, err
		}
		for i, d := range r.Delegations {
			last := i == len(r.Delegations)-1
			if resp, err = a.send(insSignTx, v8AuxData, v8AuxDataDelegation, cat(voteKey(d.VoteKeyPath, d.VoteKey), u32(d.Weight)), want(last)); err != nil {
				return nil, err
			}
		}
		out.AuxDataHash, out.CIP36Signature = resp[:auxHashLength], resp[auxHashLength:]
	}
	for off := 0; off < len(raw); {
		end := min(len(raw), off+v8ChunkSize)
		p1, want := byte(v8Chunk), 0
		if end == len(raw) {
			p1, want = v8Confirm, txHashLength
		}
		resp, err := a.send(insSignTx, p1, 0, raw[off:end], want)
		if err != nil {
			return nil, err
		}
		out.TxHash = resp
		off = end
	}
	for _, p := range witnesses {
		sig, err := a.send(insSignTx, v8SignWitness, 0, pathBytes(p), signatureLength)
		if err != nil {
			return nil, err
		}
		out.Witnesses = append(out.Witnesses, PathSignature{p, sig})
	}
	return out, nil
}
