// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build emulators

package cli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"

	"github.com/Liet-ada/cardano-hw-go/internal/cardano"
	"github.com/Liet-ada/cardano-hw-go/internal/cbor"
	"github.com/Liet-ada/cardano-hw-go/internal/device"
	"github.com/Liet-ada/cardano-hw-go/internal/tx"
)

// These tests drive the Trezor emulator through the command line, with its
// debug link confirming every screen. Start it with the "all all ..." seed
// (emu.py --slip0014) and set TREZOR_EMULATOR to its address.

type emu struct {
	t   *testing.T
	dir string
}

func newEmu(t *testing.T) *emu {
	addr := os.Getenv("TREZOR_EMULATOR")
	if addr == "" {
		t.Skip("TREZOR_EMULATOR not set")
	}
	dir := t.TempDir()
	t.Setenv(device.EnvTrezorEmulator, addr)
	t.Setenv(device.EnvDebugLink, "1")
	t.Setenv(device.EnvStore, filepath.Join(dir, "thp.json"))
	return &emu{t, dir}
}

func (e *emu) path(name string) string { return filepath.Join(e.dir, name) }

// run runs a command and returns its exit code and output.
func (e *emu) run(args ...string) (int, string) {
	var out bytes.Buffer
	app := &App{Stdout: &out, Stderr: &out, Devices: &device.Opener{}}
	code := app.Run(args)
	return code, out.String()
}

func (e *emu) mustRun(args ...string) string {
	e.t.Helper()
	code, out := e.run(args...)
	if code != 0 {
		e.t.Fatalf("%v: exit %d: %s", args, code, out)
	}
	return out
}

// keys exports the signing files of paths, named after them.
func (e *emu) keys(paths map[string]string) {
	args := []string{"address", "key-gen"}
	for name, p := range paths {
		args = append(args, "--path", p, "--hw-signing-file", e.path(name+".hwsfile"), "--verification-key-file", e.path(name+".vkey"))
	}
	e.mustRun(args...)
}

func (e *emu) pub(name string) []byte {
	f, err := cardano.ReadSigningFile(e.path(name + ".hwsfile"))
	if err != nil {
		e.t.Fatal(err)
	}
	return f.PubKey()
}

func (e *emu) keyHash(name string) []byte { return cardano.KeyHash(e.pub(name)) }

func (e *emu) writeTx(name string, t cbor.Value) string {
	data := cbor.EncodeCanonical(t)
	if issues, err := tx.Validate(data); err != nil || len(issues) > 0 {
		e.t.Fatalf("test transaction %s: %v %v", name, err, issues)
	}
	b, _ := json.Marshal(cardano.Envelope{Type: "Unwitnessed Tx ConwayEra", Description: "", CBORHex: hex.EncodeToString(data)})
	p := e.path(name + ".tx")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		e.t.Fatal(err)
	}
	return p
}

// checkWitness checks a witness file against the transaction body.
func (e *emu) checkWitness(txName, witness string, wantPub []byte, byron bool) {
	e.t.Helper()
	f, err := cardano.ReadTxFile(e.path(txName + ".tx"))
	if err != nil {
		e.t.Fatal(err)
	}
	d, err := tx.Decode(f.CBOR)
	if err != nil {
		e.t.Fatal(err)
	}
	hash := tx.BodyHash(d.RawBody)
	var env cardano.Envelope
	b, err := os.ReadFile(witness)
	if err != nil {
		e.t.Fatal(err)
	}
	json.Unmarshal(b, &env)
	raw, _ := hex.DecodeString(env.CBORHex)
	v, err := cbor.Decode(raw)
	if err != nil {
		e.t.Fatal(err)
	}
	key, data := v.Items[0].Uint, v.Items[1].Items
	if (key == 2) != byron || !bytes.Equal(data[0].Bytes, wantPub) {
		e.t.Fatalf("witness %s: key %d, pub %x", witness, key, data[0].Bytes)
	}
	if !ed25519.Verify(data[0].Bytes, hash, data[1].Bytes) {
		e.t.Fatalf("witness %s does not sign the body", witness)
	}
}

func u(n uint64) cbor.Value          { return cbor.NewUint(n) }
func b(x []byte) cbor.Value          { return cbor.NewBytes(x) }
func arr(v ...cbor.Value) cbor.Value { return cbor.NewArray(v...) }
func mp(kv ...cbor.Value) cbor.Value {
	var e []cbor.Entry
	for i := 0; i+1 < len(kv); i += 2 {
		e = append(e, cbor.Entry{Key: kv[i], Value: kv[i+1]})
	}
	return cbor.NewMap(e...)
}
func rep(n int, x byte) []byte { return bytes.Repeat([]byte{x}, n) }

func input(x byte, i uint64) cbor.Value { return arr(b(rep(32, x)), u(i)) }

func baseAddr(pay, stake []byte) []byte { return cardano.BaseAddress(0, pay, stake, 0) }

func rewardAddr(stake []byte) []byte { return cardano.RewardAddress(stake, 0) }

func TestEmulatorFlows(t *testing.T) {
	e := newEmu(t)
	e.keys(map[string]string{
		"payment": "1852H/1815H/0H/0/0",
		"stake":   "1852H/1815H/0H/2/0",
	})
	other := cardano.EnterpriseAddress(rep(28, 0x42), 0)
	own := baseAddr(e.keyHash("payment"), e.keyHash("stake"))

	t.Run("ordinary", func(t *testing.T) {
		aux := mp(u(674), mp(cbor.NewText("msg"), arr(cbor.NewText("hello"))))
		auxHash := blake2b.Sum256(cbor.EncodeCanonical(aux))
		body := mp(
			u(0), cbor.NewTag(258, arr(input(1, 0), input(2, 3))),
			u(1), arr(
				arr(b(other), u(1500000)),
				mp(u(0), b(own), u(1), arr(u(3000000), mp(b(rep(28, 9)), mp(b([]byte("TOK")), u(5), b(nil), u(1))))),
			),
			u(2), u(190000),
			u(3), u(90000000),
			u(4), cbor.NewTag(258, arr(
				arr(u(7), arr(u(0), b(e.keyHash("stake"))), u(2000000)),
				arr(u(9), arr(u(0), b(e.keyHash("stake"))), arr(u(2))),
			)),
			u(5), mp(b(rewardAddr(e.keyHash("stake"))), u(1234)),
			u(7), b(auxHash[:]),
			u(8), u(1000),
		)
		p := e.writeTx("ordinary", arr(body, mp(), cbor.NewBool(true), aux))
		e.mustRun("transaction", "witness", "--testnet-magic", "1", "--tx-file", p,
			"--hw-signing-file", e.path("payment.hwsfile"), "--hw-signing-file", e.path("stake.hwsfile"),
			"--change-output-key-file", e.path("payment.hwsfile"), "--change-output-key-file", e.path("stake.hwsfile"),
			"--out-file", e.path("ordinary.payment.witness"), "--out-file", e.path("ordinary.stake.witness"))
		e.checkWitness("ordinary", e.path("ordinary.payment.witness"), e.pub("payment"), false)
		e.checkWitness("ordinary", e.path("ordinary.stake.witness"), e.pub("stake"), false)
	})

	t.Run("plutus", func(t *testing.T) {
		body := mp(
			u(0), arr(input(3, 0)),
			u(1), arr(
				mp(u(0), b(other), u(1), u(2000000), u(2), arr(u(0), b(rep(32, 7)))),
				mp(u(0), b(other), u(1), u(2000000), u(2), arr(u(1), cbor.NewTag(24, b(rep(1500, 0x40)))),
					u(3), cbor.NewTag(24, b(append([]byte{0x82, 0x02, 0x59, 0x04, 0x00}, rep(1024, 1)...)))),
			),
			u(2), u(400000),
			u(11), b(rep(32, 0x55)),
			u(13), arr(input(4, 1)),
			u(14), arr(b(e.keyHash("payment")), b(rep(28, 0x66))),
			u(15), u(0),
			u(16), arr(b(own), u(4000000)),
			u(17), u(600000),
			u(18), arr(input(5, 2)),
		)
		p := e.writeTx("plutus", arr(body, mp(), cbor.NewBool(true), cbor.Null))
		e.mustRun("transaction", "witness", "--testnet-magic", "1", "--tx-file", p,
			"--hw-signing-file", e.path("payment.hwsfile"),
			"--change-output-key-file", e.path("payment.hwsfile"), "--change-output-key-file", e.path("stake.hwsfile"),
			"--out-file", e.path("plutus.witness"))
		e.checkWitness("plutus", e.path("plutus.witness"), e.pub("payment"), false)
	})

	t.Run("pool registration as owner", func(t *testing.T) {
		ipv6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
		reg := arr(u(3), b(rep(28, 0x11)), b(rep(32, 0x22)), u(500000000), u(340000000),
			cbor.NewTag(30, arr(u(1), u(50))), b(rewardAddr(rep(28, 0x33))),
			arr(b(e.keyHash("stake")), b(rep(28, 0x44))),
			arr(
				arr(u(0), u(3001), b([]byte{192, 168, 0, 1}), b(ipv6)),
				arr(u(1), u(3002), cbor.NewText("relay.example.com")),
				arr(u(2), cbor.NewText("pool.example.com")),
			),
			arr(cbor.NewText("https://example.com/pool.json"), b(rep(32, 0x55))),
		)
		body := mp(u(0), arr(input(6, 0)), u(1), arr(arr(b(other), u(1000000))), u(2), u(300000), u(3), u(90000000), u(4), arr(reg))
		p := e.writeTx("pool", arr(body, mp(), cbor.NewBool(true), cbor.Null))
		e.mustRun("transaction", "witness", "--testnet-magic", "1", "--tx-file", p,
			"--hw-signing-file", e.path("stake.hwsfile"), "--out-file", e.path("pool.witness"))
		e.checkWitness("pool", e.path("pool.witness"), e.pub("stake"), false)
	})

	t.Run("multisig and mint", func(t *testing.T) {
		e.keys(map[string]string{
			"ms-payment": "1854H/1815H/0H/0/0",
			"ms-stake":   "1854H/1815H/0H/2/0",
			"mint":       "1855H/1815H/0H",
		})
		policy := cardano.NativeScript{Type: cardano.ScriptPubKey, KeyHash: e.keyHash("mint")}.Hash()
		body := mp(
			u(0), arr(input(7, 0)),
			u(1), arr(arr(b(other), arr(u(2000000), mp(b(policy), mp(b([]byte("NFT")), u(1)))))),
			u(2), u(200000),
			u(4), arr(arr(u(1), arr(u(1), b(rep(28, 0x77))))),
			u(9), mp(b(policy), mp(b([]byte("NFT")), u(1))),
		)
		p := e.writeTx("multisig", arr(body, mp(), cbor.NewBool(true), cbor.Null))
		e.mustRun("transaction", "witness", "--testnet-magic", "1", "--tx-file", p,
			"--hw-signing-file", e.path("ms-payment.hwsfile"), "--hw-signing-file", e.path("mint.hwsfile"),
			"--out-file", e.path("multisig.payment.witness"), "--out-file", e.path("multisig.mint.witness"))
		e.checkWitness("multisig", e.path("multisig.payment.witness"), e.pub("ms-payment"), false)
		e.checkWitness("multisig", e.path("multisig.mint.witness"), e.pub("mint"), false)
	})

	t.Run("byron", func(t *testing.T) {
		e.keys(map[string]string{"byron": "44H/1815H/0H/0/0"})
		f, _ := cardano.ReadSigningFile(e.path("byron.hwsfile"))
		pub, chain, _ := f.XPub()
		byronAddr := cardano.ByronAddress(append(append([]byte{}, pub...), chain...), 1)
		body := mp(u(0), arr(input(8, 0)), u(1), arr(arr(b(byronAddr), u(1000000)), arr(b(other), u(1000000))), u(2), u(200000), u(3), u(90000000))
		p := e.writeTx("byron", arr(body, mp(), cbor.NewBool(true), cbor.Null))
		e.mustRun("transaction", "witness", "--testnet-magic", "1", "--tx-file", p,
			"--hw-signing-file", e.path("byron.hwsfile"), "--change-output-key-file", e.path("byron.hwsfile"),
			"--out-file", e.path("byron.witness"))
		e.checkWitness("byron", e.path("byron.witness"), e.pub("byron"), true)
	})

	t.Run("show address", func(t *testing.T) {
		addr, _ := cardano.EncodeAddress(own)
		os.WriteFile(e.path("own.addr"), []byte(addr+"\n"), 0o600)
		out := e.mustRun("address", "show", "--payment-path", "1852H/1815H/0H/0/0", "--staking-path", "1852H/1815H/0H/2/0", "--address-file", e.path("own.addr"))
		if !strings.Contains(out, addr) {
			t.Fatalf("output %q", out)
		}
		code, out := e.run("address", "show", "--payment-path", "1852H/1815H/0H/0/7", "--staking-path", "1852H/1815H/0H/2/0", "--address-file", e.path("own.addr"))
		if code == 0 || !strings.Contains(out, "Address mismatch") {
			t.Fatalf("a wrong path passed: %d %s", code, out)
		}
	})

	t.Run("policyid", func(t *testing.T) {
		script := `{"type":"all","scripts":[{"type":"sig","keyHash":"` + hex.EncodeToString(e.keyHash("mint")) + `"},{"type":"before","slot":123456}]}`
		os.WriteFile(e.path("policy.script"), []byte(script), 0o600)
		out := e.mustRun("transaction", "policyid", "--script-file", e.path("policy.script"), "--hw-signing-file", e.path("mint.hwsfile"))
		want := cardano.NativeScript{Type: cardano.ScriptAll, Scripts: []cardano.NativeScript{
			{Type: cardano.ScriptPubKey, KeyHash: e.keyHash("mint")},
			{Type: cardano.ScriptInvalidHereafter, Slot: 123456},
		}}.Hash()
		if strings.TrimSpace(out) != hex.EncodeToString(want) {
			t.Fatalf("policy id %q, want %x", out, want)
		}
	})

	t.Run("message", func(t *testing.T) {
		addr, _ := cardano.EncodeAddress(own)
		e.mustRun("message", "sign", "--message", "Hello Cardano", "--signing-path-hwsfile", e.path("payment.hwsfile"),
			"--address", addr, "--address-hwsfile", e.path("payment.hwsfile"), "--address-hwsfile", e.path("stake.hwsfile"),
			"--out-file", e.path("message.json"))
		var m struct {
			SignatureHex, PublicKeyHex, COSESign1Hex string
		}
		data, _ := os.ReadFile(e.path("message.json"))
		var raw map[string]any
		json.Unmarshal(data, &raw)
		m.SignatureHex, m.PublicKeyHex, m.COSESign1Hex = raw["signatureHex"].(string), raw["publicKeyHex"].(string), raw["COSE_Sign1_hex"].(string)
		sign1, _ := hex.DecodeString(m.COSESign1Hex)
		v, err := cbor.Decode(sign1)
		if err != nil {
			t.Fatal(err)
		}
		// Sig_structure = ["Signature1", protected, external_aad, payload]
		toSign := cbor.Encode(arr(cbor.NewText("Signature1"), v.Items[0], b(nil), v.Items[2]))
		sig, _ := hex.DecodeString(m.SignatureHex)
		if !ed25519.Verify(e.pub("payment"), toSign, sig) {
			t.Fatal("the message signature does not verify")
		}
		e.mustRun("message", "sign", "--message-hex", "deadbeef", "--signing-path-hwsfile", e.path("stake.hwsfile"), "--out-file", e.path("message2.json"))
	})

	t.Run("cip36", func(t *testing.T) {
		// Trezor does not export vote keys (1694' paths); take one from elsewhere
		voteKey := cardano.Bech32Encode("cvote_vk", rep(32, 0x5a))
		addr, _ := cardano.EncodeAddress(own)
		e.mustRun("vote", "registration-metadata", "--testnet-magic", "1",
			"--vote-public-key-string", voteKey,
			"--stake-signing-key-hwsfile", e.path("stake.hwsfile"),
			"--payment-address", addr, "--payment-address-signing-key-hwsfile", e.path("payment.hwsfile"),
			"--nonce", "12345678", "--metadata-cbor-out-file", e.path("vote.cbor"))
		data, _ := os.ReadFile(e.path("vote.cbor"))
		v, err := cbor.Decode(data)
		if err != nil {
			t.Fatal(err)
		}
		reg, _ := v.Get(61284)
		sigMap, _ := v.Get(61285)
		sig, _ := sigMap.Get(1)
		h := blake2b.Sum256(cbor.Encode(mp(u(61284), reg)))
		if !ed25519.Verify(e.pub("stake"), h[:], sig.Bytes) {
			t.Fatal("the registration signature does not verify")
		}
	})

	t.Run("key path refused", func(t *testing.T) {
		code, out := e.run("address", "key-gen", "--path", "1694H/1815H/0H/0/0",
			"--hw-signing-file", e.path("vote.hwsfile"), "--verification-key-file", e.path("vote.vkey"))
		if code != 1 || out != "Error: Forbidden key path\n" {
			t.Fatalf("exit %d: %q", code, out)
		}
	})

	t.Run("rejections", func(t *testing.T) {
		t.Setenv(device.EnvDebugLink, "reject")
		addr, _ := cardano.EncodeAddress(own)
		os.WriteFile(e.path("own.addr"), []byte(addr+"\n"), 0o600)
		body := mp(u(0), arr(input(0xaa, 0)), u(1), arr(arr(b(other), u(1500000))), u(2), u(170000), u(3), u(1000))
		txFile := e.writeTx("rejected", arr(body, mp(), cbor.NewBool(true), cbor.Null))
		for _, c := range []struct {
			args []string
			want string
		}{
			{[]string{"address", "key-gen", "--path", "1852H/1815H/0H/0/1",
				"--hw-signing-file", e.path("r.hwsfile"), "--verification-key-file", e.path("r.vkey")},
				"Error: Extended public key export cancelled by user\n"},
			{[]string{"address", "show", "--payment-path", "1852H/1815H/0H/0/0", "--staking-path", "1852H/1815H/0H/2/0",
				"--address-file", e.path("own.addr")},
				"Error: Cancelled\n"},
			{[]string{"message", "sign", "--message", "no", "--signing-path-hwsfile", e.path("payment.hwsfile"),
				"--out-file", e.path("r.json")},
				"Error: Cancelled\n"},
			{[]string{"transaction", "witness", "--testnet-magic", "1", "--tx-file", txFile,
				"--hw-signing-file", e.path("payment.hwsfile"), "--out-file", e.path("r.witness")},
				"Error: Cancelled\n"},
		} {
			code, out := e.run(c.args...)
			if code != 1 || !strings.HasSuffix(out, c.want) {
				t.Errorf("%s %s: exit %d: %q, want %q at the end", c.args[0], c.args[1], code, out, c.want)
			}
		}
		for _, name := range []string{"r.hwsfile", "r.vkey", "r.json", "r.witness"} {
			if _, err := os.Stat(e.path(name)); err == nil {
				t.Errorf("%s written after a rejection", name)
			}
		}
	})

	t.Run("operational certificate unsupported", func(t *testing.T) {
		// Trezor exports no pool cold keys either: write the files by hand
		cold := cardano.SigningFileOutput{Type: "StakePoolHWSigningFile_ed25519", Description: "", Path: "1853H/1815H/0H/0H",
			CBORXPubKeyHex: "5840" + strings.Repeat("11", 64)}
		data, _ := cardano.MarshalOutput(cold)
		os.WriteFile(e.path("cold.hwsfile"), data, 0o600)
		os.WriteFile(e.path("cold.counter"), []byte(`{"type":"NodeOperationalCertificateIssueCounter","description":"","cborHex":"8200582011`+strings.Repeat("11", 31)+`"}`), 0o600)
		os.WriteFile(e.path("kes.vkey"), []byte(`{"type":"KesVerificationKey_ed25519_kes_2^6","description":"","cborHex":"5820`+strings.Repeat("ab", 32)+`"}`), 0o600)
		code, out := e.run("node", "issue-op-cert", "--kes-verification-key-file", e.path("kes.vkey"), "--kes-period", "100",
			"--operational-certificate-issue-counter-file", e.path("cold.counter"), "--hw-signing-file", e.path("cold.hwsfile"), "--out-file", e.path("opcert"))
		if code != 1 || !strings.Contains(out, "not supported by the chosen crypto provider") {
			t.Fatalf("exit %d: %s", code, out)
		}
	})
}
