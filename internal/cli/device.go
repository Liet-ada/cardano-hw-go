// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cli

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/Liet-ada/cardano-hw-go/internal/cardano"
	"github.com/Liet-ada/cardano-hw-go/internal/cbor"
	"github.com/Liet-ada/cardano-hw-go/internal/hw"
	"github.com/Liet-ada/cardano-hw-go/internal/js"
	"github.com/Liet-ada/cardano-hw-go/internal/tx"
)

// DeviceOpener finds and opens the connected hardware wallet.
type DeviceOpener interface {
	Open() (hw.Provider, error)
}

// Errors with cardano-hw-cli's wording.
var (
	errInvalidAddressParameters = errors.New("Invalid address parameters provided")
	errInvalidKeyGenInputs      = errors.New("Invalid key gen inputs error")
	errInvalidNodeKeyGenInputs  = errors.New("Invalid node key-gen inputs")
	errNotEnoughOutFiles        = errors.New("Not enough output files specified")
	errInvalidKesVKeyFile       = errors.New("Invalid KES verification key file")
	errInvalidIssueCounterFile  = errors.New("Invalid operational certificate issue counter file")
	errByronInCIP36             = errors.New("Byron addresses are not allowed for CIP36 registration")
	errInvalidCVoteDelegations  = errors.New("Invalid CIP36 delegations (either a single vote public key or several vote public keys with their weights are expected)")
	errInvalidCVotePublicKey    = errors.New("Invalid CIP36 vote public key")
	errInvalidMessage           = errors.New("Invalid message to sign, should be ASCII")
	errInvalidScriptHashHex     = errors.New("Invalid script hash hex")
)

// withDevice runs f with the device the command opened.
func (a *App) withDevice(f func(hw.Provider) error) error {
	if a.device == nil {
		return errors.New("no device open")
	}
	return f(a.device)
}

func readSigningFiles(paths []string) ([]cardano.SigningFile, error) {
	var out []cardano.SigningFile
	for _, p := range paths {
		f, err := cardano.ReadSigningFile(p)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

func parsePaths(ss []string) ([]cardano.Path, error) {
	var out []cardano.Path
	for _, s := range ss {
		p, err := cardano.ParsePath(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func derivationType(p *args) (hw.DerivationType, error) {
	s, _ := p.get("derivationType")
	return hw.ParseDerivationType(s)
}

// bigUint64 reads a number as cardano-hw-cli's BigInt does; one out of
// the range of 64 bits is refused here, where cardano-hw-cli only fails at
// the device.
func bigUint64(s string) (uint64, error) {
	n, err := jsBigInt(s)
	if err != nil {
		return 0, err
	}
	if n.Sign() < 0 || !n.IsUint64() {
		return 0, fmt.Errorf("number out of range: %s", s)
	}
	return n.Uint64(), nil
}

// network reads --mainnet or --testnet-magic; mainnet is the default. The
// magic is read by parseInt, as cardano-hw-cli does, so "1x" is 1.
// cardano-hw-cli goes on with a magic that is not a number, a value after
// --mainnet, or no network after --testnet-magic alone, and fails later
// in ways of its own; here they are refused.
func network(p *args) (cardano.Network, error) {
	v, ok := p.get("network")
	// the option given last decides, as both store the network
	last := ""
	for _, g := range p.given {
		if g.name == "--mainnet" || g.name == "--testnet-magic" {
			last = g.name
		}
	}
	if last == "--mainnet" && v != "mainnet" {
		return cardano.Network{}, fmt.Errorf("invalid network %q after --mainnet", v)
	}
	if !ok || v == "mainnet" {
		return cardano.Mainnet, nil
	}
	if v == "" {
		return cardano.Network{}, js.NewTypeError("Cannot read properties of undefined (reading 'networkId')")
	}
	magic := js.ParseInt(v)
	if math.IsNaN(magic) || magic < 0 || magic > math.MaxUint32 {
		return cardano.Network{}, fmt.Errorf("invalid protocol magic %q", v)
	}
	return cardano.Network{NetworkID: cardano.NetworkIDTestnet, ProtocolMagic: uint32(magic)}, nil
}

func parseScriptHash(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 28 {
		return nil, errInvalidScriptHashHex
	}
	return b, nil
}

func readEnvelope(path string) (cardano.Envelope, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return cardano.Envelope{}, err
	}
	var e cardano.Envelope
	return e, jsonUnmarshal(b, &e)
}

// deviceCommand runs a command that needs the device. As cardano-hw-cli
// does, the device is found before anything else of the command is done
// (the options were already read and checked as the command line was
// parsed), so with no device that is the error.
func (a *App) deviceCommand(p *args) (int, error) {
	if a.Devices == nil {
		return ExitError, errors.New("no device opener configured")
	}
	d, err := a.Devices.Open()
	if err != nil {
		return ExitSuccess, err
	}
	defer d.Close()
	a.device = d
	defer func() { a.device = nil }()
	switch p.cmd {
	case "key.verification-key":
		err = a.verificationKey(p)
	case "device.version":
		err = a.withDevice(func(d hw.Provider) error {
			v, err := d.Version()
			if err == nil {
				fmt.Fprintln(a.Stdout, v)
			}
			return err
		})
	case "address.show":
		err = a.showAddress(p)
	case "address.key-gen":
		err = a.keyGen(p)
	case "transaction.policyid":
		err = a.policyID(p)
	case "transaction.witness":
		err = a.witness(p)
	case "node.key-gen":
		err = a.nodeKeyGen(p)
	case "node.issue-op-cert":
		err = a.issueOpCert(p)
	case "vote.registration-metadata":
		err = a.cip36(p)
	case "message.sign":
		err = a.signMessage(p)
	default:
		err = errors.New("command undefined")
	}
	return ExitSuccess, err
}

func (a *App) showAddress(p *args) error {
	addrFile, _ := p.get("address")
	addr, err := readAddressFile(addrFile)
	if err != nil {
		return err
	}
	s := hw.ShowAddressParams{Address: addr}
	if v, ok := p.get("paymentPath"); ok {
		if s.PaymentPath, err = cardano.ParsePath(v); err != nil {
			return err
		}
	}
	if v, ok := p.get("paymentScriptHash"); ok {
		if s.PaymentScriptHash, err = parseScriptHash(v); err != nil {
			return err
		}
	}
	if v, ok := p.get("stakingPath"); ok {
		if s.StakingPath, err = cardano.ParsePath(v); err != nil {
			return err
		}
	}
	if v, ok := p.get("stakingScriptHash"); ok {
		if s.StakingScriptHash, err = parseScriptHash(v); err != nil {
			return err
		}
	}
	if s.DerivationType, err = derivationType(p); err != nil {
		return err
	}
	hasPayment := s.PaymentPath != nil || s.PaymentScriptHash != nil
	hasStaking := s.StakingPath != nil || s.StakingScriptHash != nil
	if !hasPayment && !hasStaking {
		return errInvalidAddressParameters
	}
	attrs, err := cardano.Attributes(s.Address)
	if err != nil {
		return err
	}
	ok := false
	switch attrs.Type {
	case cardano.AddrBasePaymentKeyStakeKey, cardano.AddrBasePaymentScriptStakeKey,
		cardano.AddrBasePaymentKeyStakeScript, cardano.AddrBasePaymentScriptStakeScript:
		ok = hasPayment && hasStaking
	case cardano.AddrEnterpriseKey, cardano.AddrEnterpriseScript:
		ok = hasPayment && !hasStaking
	case cardano.AddrRewardKey, cardano.AddrRewardScript:
		ok = hasStaking && !hasPayment
	}
	if !ok {
		return errInvalidAddressParameters
	}
	return a.withDevice(func(d hw.Provider) error {
		fmt.Fprintf(a.Stdout, "address: %s\n", s.Address)
		return d.ShowAddress(s)
	})
}

func (a *App) keyGen(p *args) error {
	paths, err := parsePaths(p.all("paths"))
	if err != nil {
		return err
	}
	hwsfiles, vkeys := p.all("hwSigningFiles"), p.all("verificationKeyFiles")
	if len(paths) < 1 || len(paths) != len(hwsfiles) || len(paths) != len(vkeys) {
		return errInvalidKeyGenInputs
	}
	dt, err := derivationType(p)
	if err != nil {
		return err
	}
	return a.withDevice(func(d hw.Provider) error {
		xpubs, err := d.XPubKeys(paths, dt)
		if err != nil {
			return err
		}
		for i, x := range xpubs {
			out, err := cardano.NewSigningFileOutput(x, paths[i])
			if err != nil {
				return err
			}
			if err := a.write(hwsfiles[i], out); err != nil {
				return err
			}
		}
		for i, x := range xpubs {
			out, err := cardano.NewVerificationKeyOutput(x, paths[i])
			if err != nil {
				return err
			}
			if err := a.write(vkeys[i], out); err != nil {
				return err
			}
		}
		return nil
	})
}

func (a *App) policyID(p *args) error {
	path, _ := p.get("nativeScript")
	script, err := cardano.ReadNativeScriptFile(path)
	if err != nil {
		return err
	}
	files, err := readSigningFiles(p.all("hwSigningFileData"))
	if err != nil {
		return err
	}
	dt, err := derivationType(p)
	if err != nil {
		return err
	}
	return a.withDevice(func(d hw.Provider) error {
		h, err := d.NativeScriptHash(script, files, hw.DisplayPolicyID, dt)
		if err == nil {
			fmt.Fprintln(a.Stdout, hex.EncodeToString(h))
		}
		return err
	})
}

func (a *App) witness(p *args) error {
	net, err := network(p)
	if err != nil {
		return err
	}
	txPath, _ := p.get("txFileData")
	f, err := cardano.ReadTxFile(txPath)
	if err != nil {
		return err
	}
	files, err := readSigningFiles(p.all("hwSigningFileData"))
	if err != nil {
		return err
	}
	change, err := readSigningFiles(p.all("changeOutputKeyFileData"))
	if err != nil {
		return err
	}
	dt, err := derivationType(p)
	if err != nil {
		return err
	}
	outFiles := p.all("outFiles")
	unrestricted := p.flags["allowUnrestrictedMode"]

	// The device re-serializes the body from the items it gets; only a
	// canonical transaction gives the same bytes, and so the same hash.
	r, err := a.checkValidation(f.CBOR, unrestricted, false)
	if err != nil {
		return err
	}
	if r.unfixable {
		return errTxContainsUnfixable
	}
	if r.fixable {
		return errTxContainsFixable
	}
	d, err := tx.Decode(f.CBOR)
	if err != nil {
		return err
	}
	mode, err := hw.DetermineSigningMode(&d.Tx.Body, files)
	if err != nil {
		return err
	}
	params := hw.TxSigningParams{
		Mode: mode, Tx: &d.Tx, BodyHash: tx.BodyHash(d.RawBody), SigningFiles: files,
		Network: net, Era: f.Era, DerivationType: dt,
	}
	return a.withDevice(func(dev hw.Provider) error {
		if mode == hw.SigningUnrestricted {
			if !unrestricted {
				return hw.ErrUnrestrictedModeRequired
			}
			ok, err := dev.SupportsUnrestricted()
			if err != nil {
				return err
			}
			if !ok {
				return hw.ErrUnrestrictedModeUnsupported
			}
		}
		if err := hw.ValidateWitnessing(params); err != nil {
			return err
		}
		witnesses, err := dev.WitnessTx(params, change)
		if err != nil {
			return err
		}
		// Byron witnesses first, as cardano-hw-cli lists them
		var ordered []hw.Witness
		for _, byron := range []bool{true, false} {
			for _, w := range witnesses {
				if w.Byron == byron {
					ordered = append(ordered, w)
				}
			}
		}
		outputs := make([]*cardano.Envelope, len(files))
		for i, sf := range files {
			for _, w := range ordered {
				if w.Path.Equal(sf.Path) {
					e := hw.WitnessOutput(f.Era, w)
					outputs[i] = &e
					break
				}
			}
		}
		if len(outputs) > len(outFiles) {
			fmt.Fprintln(a.Stdout, "Witness paths:")
			for _, w := range ordered {
				fmt.Fprintln(a.Stdout, jsPath(w.Path))
			}
			return errNotEnoughOutFiles
		}
		for i, out := range outFiles {
			if i < len(outputs) && outputs[i] != nil {
				if err := a.write(out, *outputs[i]); err != nil {
					return err
				}
			} else {
				fmt.Fprintf(a.Stdout, "Warning! A superfluous output file specified (%d of %d), the file was not written to.\n", i+1, len(outFiles))
			}
		}
		return nil
	})
}

// jsPath prints a path as JavaScript prints an array of numbers.
func jsPath(p cardano.Path) string {
	parts := make([]string, len(p))
	for i, n := range p {
		parts[i] = strconv.FormatUint(uint64(n), 10)
	}
	return strings.Join(parts, ",")
}

func (a *App) nodeKeyGen(p *args) error {
	paths, err := parsePaths(p.all("paths"))
	if err != nil {
		return err
	}
	hwsfiles, vkeys, counters := p.all("hwSigningFiles"), p.all("verificationKeyFiles"), p.all("issueCounterFiles")
	if len(hwsfiles) != len(paths) || len(vkeys) != len(paths) || len(counters) != len(paths) {
		return errInvalidNodeKeyGenInputs
	}
	for _, pa := range paths {
		if cardano.Classify(pa) != cardano.PathPoolColdKey {
			return errInvalidNodeKeyGenInputs
		}
	}
	return a.withDevice(func(d hw.Provider) error {
		for i, pa := range paths {
			xpubs, err := d.XPubKeys([]cardano.Path{pa}, hw.DerivationDefault)
			if err != nil {
				return err
			}
			x := xpubs[0]
			sf, err := cardano.NewSigningFileOutput(x, pa)
			if err != nil {
				return err
			}
			if err := a.write(hwsfiles[i], sf); err != nil {
				return err
			}
			vk, err := cardano.NewVerificationKeyOutput(x, pa)
			if err != nil {
				return err
			}
			if err := a.write(vkeys[i], vk); err != nil {
				return err
			}
			if err := a.write(counters[i], hw.OpCertCounterOutput(hw.OpCertCounter{Counter: 0, PoolColdKey: x[:32]})); err != nil {
				return err
			}
		}
		return nil
	})
}

func readIssueCounter(path string) (hw.OpCertCounter, error) {
	env, err := readEnvelope(path)
	if err != nil {
		return hw.OpCertCounter{}, err
	}
	if env.Type != "NodeOperationalCertificateIssueCounter" {
		return hw.OpCertCounter{}, errInvalidIssueCounterFile
	}
	b, err := hex.DecodeString(env.CBORHex)
	if err != nil {
		return hw.OpCertCounter{}, errInvalidIssueCounterFile
	}
	v, err := cbor.Decode(b)
	if err != nil || v.Kind != cbor.Array || len(v.Items) != 2 || v.Items[0].Kind != cbor.Uint ||
		v.Items[1].Kind != cbor.Bytes || len(v.Items[1].Bytes) != 32 {
		return hw.OpCertCounter{}, errInvalidIssueCounterFile
	}
	return hw.OpCertCounter{Counter: v.Items[0].Uint, PoolColdKey: v.Items[1].Bytes}, nil
}

func (a *App) issueOpCert(p *args) error {
	kesPath, _ := p.get("kesVKey")
	kes, err := readKesVKey(kesPath)
	if err != nil {
		return err
	}
	ps, _ := p.get("kesPeriod")
	period, err := bigUint64(ps)
	if err != nil {
		return fmt.Errorf("invalid KES period %q", ps)
	}
	files, err := readSigningFiles(p.all("hwSigningFileData"))
	if err != nil {
		return err
	}
	counterFile, _ := p.get("issueCounterFile")
	counter, err := readIssueCounter(counterFile)
	if err != nil {
		return err
	}
	return a.withDevice(func(d hw.Provider) error {
		cert, err := d.SignOperationalCertificate(kes, period, counter, files)
		if err != nil {
			return err
		}
		out, _ := p.get("outFile")
		if err := a.write(out, cardano.Envelope{Type: "NodeOperationalCertificate", Description: "", CBORHex: hex.EncodeToString(cert)}); err != nil {
			return err
		}
		counter.Counter++
		return a.write(counterFile, hw.OpCertCounterOutput(counter))
	})
}

// voteKeys reads the vote public keys in the order given, whatever option
// gave each.
func voteKeys(p *args) ([][]byte, error) {
	var keys [][]byte
	for _, g := range p.given {
		var k []byte
		var err error
		switch g.name {
		case "--vote-public-key-jcli":
			k, err = voteKeyJcli(g.value)
		case "--vote-public-key-string":
			k, err = voteKeyBech32(g.value)
		case "--vote-public-key-hwsfile":
			k, err = voteKeyHwsfile(g.value)
		case "--vote-public-key-file":
			k, err = voteKeyFile(g.value)
		default:
			continue
		}
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func (a *App) cip36(p *args) error {
	net, err := network(p)
	if err != nil {
		return err
	}
	keys, err := voteKeys(p)
	if err != nil {
		return err
	}
	var weights []uint64
	for _, w := range p.all("voteWeights") {
		n, err := bigUint64(w)
		if err != nil {
			return fmt.Errorf("invalid vote weight %q", w)
		}
		weights = append(weights, n)
	}
	stakePath, _ := p.get("hwStakeSigningFileData")
	stake, err := cardano.ReadSigningFile(stakePath)
	if err != nil {
		return err
	}
	address, _ := p.get("paymentAddress")
	ns, _ := p.get("nonce")
	nonce, err := bigUint64(ns)
	if err != nil {
		return fmt.Errorf("invalid nonce %q", ns)
	}
	purpose := uint64(0) // Catalyst
	if vs, ok := p.get("votingPurpose"); ok {
		if purpose, err = bigUint64(vs); err != nil {
			return fmt.Errorf("invalid voting purpose %q", vs)
		}
	}
	paymentFiles, err := readSigningFiles(p.all("paymentAddressSigningKeyData"))
	if err != nil {
		return err
	}
	dt, err := derivationType(p)
	if err != nil {
		return err
	}
	// the stake file is also an address file, so it need not be repeated
	addressFiles := append(paymentFiles, stake)
	for _, f := range addressFiles {
		if cardano.Classify(f.Path) == cardano.PathWalletSpendingKeyByron {
			return errByronInCIP36
		}
	}
	switch {
	case len(keys) == 1 && len(weights) == 0:
		weights = []uint64{1}
	case len(keys) > 0 && len(keys) == len(weights):
	default:
		return errInvalidCVoteDelegations
	}
	params := hw.CIP36Params{
		StakeSigningFile: stake, PaymentAddress: address, Nonce: nonce, VotingPurpose: purpose,
		Network: net, PaymentSigningFiles: addressFiles, DerivationType: dt,
	}
	for i, k := range keys {
		params.Delegations = append(params.Delegations, hw.VoteDelegation{VotePublicKey: k, Weight: weights[i]})
	}
	return a.withDevice(func(d hw.Provider) error {
		meta, err := d.SignCIP36Registration(params)
		if err != nil {
			return err
		}
		out, _ := p.get("outFile")
		return a.writeRaw(out, meta)
	})
}

func (a *App) signMessage(p *args) error {
	var message []byte
	if m, ok := p.get("message"); ok {
		for i := 0; i < len(m); i++ {
			if m[i] > 0x7f {
				return errInvalidMessage
			}
		}
		message = []byte(m)
	} else {
		h, _ := p.get("messageHex")
		b, err := hex.DecodeString(h)
		if err != nil {
			return fmt.Errorf("invalid message hex: %w", err)
		}
		message = b
	}
	fp, _ := p.get("hwSigningFileData")
	sf, err := cardano.ReadSigningFile(fp)
	if err != nil {
		return err
	}
	addrFiles, err := readSigningFiles(p.all("addressHwSigningFileData"))
	if err != nil {
		return err
	}
	dt, err := derivationType(p)
	if err != nil {
		return err
	}
	address, _ := p.get("address")
	params := hw.SignMessageParams{
		Message: message, SigningFile: sf, HashPayload: p.flags["hashPayload"],
		PreferHexDisplay: p.flags["preferHexDisplay"], Address: address, AddressFiles: addrFiles, DerivationType: dt,
	}
	return a.withDevice(func(d hw.Provider) error {
		s, err := d.SignMessage(params)
		if err != nil {
			return err
		}
		out, _ := p.get("outFile")
		return a.write(out, hw.NewSignedMessageOutput(message, params.HashPayload, s))
	})
}
