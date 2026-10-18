// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cli

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Liet-ada/cardano-hw-go/internal/ledger/ledgersim"
)

// TestMessageHex checks that the message hex goes to the device's library
// as given, as in cardano-hw-cli: ledgerjs refuses what is not an even
// number of hex digits, and the output file holds the hex as written.
func TestMessageHex(t *testing.T) {
	t.Setenv("COLUMNS", "")
	var golden ledgerCase
	for _, c := range readLedgerCases(t) {
		if c.Name == "message-msg01@7.1.4" {
			golden = c
		}
	}
	if golden.Name == "" {
		t.Fatal("no case message-msg01@7.1.4")
	}
	const lower, upper = "68656c6c6f20776f726c64", "68656C6C6F20776F726C64"
	run := func(t *testing.T, messageHex string) (int, string, string, []string) {
		dir := t.TempDir()
		for name, h := range golden.Inputs {
			b, _ := hex.DecodeString(h)
			if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		t.Chdir(dir)
		sim, err := ledgersim.New(ledgersim.TestMnemonic, [4]byte{7, 1, 4})
		if err != nil {
			t.Fatal(err)
		}
		args := append([]string(nil), golden.Args...)
		for i, a := range args {
			if a == lower {
				args[i] = messageHex
			}
		}
		var stdout, stderr bytes.Buffer
		app := &App{Stdout: &stdout, Stderr: &stderr, Devices: simOpener{sim}}
		code := app.Run(args)
		out, _ := os.ReadFile(filepath.Join(dir, "msg.out"))
		var transcript []string
		for _, e := range sim.Transcript() {
			transcript = append(transcript, hex.EncodeToString(e.APDU)+" "+hex.EncodeToString(e.Response))
		}
		return code, stderr.String(), string(out), transcript
	}

	t.Run("upper case", func(t *testing.T) {
		code, stderr, out, transcript := run(t, upper)
		if code != 0 || stderr != "" {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		want := strings.Replace(mustHex(golden.Outputs["msg.out"]), lower, upper, 1)
		if out != want {
			t.Errorf("output:\n%s\nwant:\n%s", out, want)
		}
		if strings.Join(transcript, "\n") != strings.Join(golden.Transcript, "\n") {
			t.Errorf("APDUs differ from those of %s", golden.Name)
		}
	})
	for _, h := range []string{"abc", "0x68", "zz"} {
		t.Run(h, func(t *testing.T) {
			code, stderr, out, _ := run(t, h)
			want := "Error: The requested operation failed. Check that your Ledger device is connected, unlocked and with Cardano app running.\nDetails: InvalidData: CIP-8 message signing: invalid message hex string\n"
			if code != 1 || stderr != want {
				t.Errorf("exit %d, stderr:\n%s\nwant exit 1 and:\n%s", code, stderr, want)
			}
			if out != "" {
				t.Errorf("wrote %s", out)
			}
		})
	}
}
