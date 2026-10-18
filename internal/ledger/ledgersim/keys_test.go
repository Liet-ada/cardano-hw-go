// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package ledgersim

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/Liet-ada/cardano-hw-go/internal/cardano"
)

// Extended public keys of the test mnemonic from a real Ledger, as
// cardano-hw-cli's integration tests list them.
func TestLedgerDerivation(t *testing.T) {
	root, err := ledgerMaster(TestMnemonic, "")
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		"1852H/1815H/0H/0/0": "cd2b047d1a803eee059769cffb3dfd0a4b9327e55bc78aa962d9bd4f720db0b2914ba07fb381f23c5c09bce26587bdf359aab7ea8f4192adbf93a38fd893ccea",
		"1852H/1815H/0H/2/0": "66610efd336e1137c525937b76511fbcf2a0e6bcf0d340a67bcb39bc870d85e8e977e956d29810dbfbda9c8ea667585982454e401c68578623d4b86bc7eb7b58",
		"1852H/1815H/0H/0/1": "b3d5f4158f0c391ee2a28a2e285f218f3e895ff6ff59cb9369c64b03b5bab5eb27e1d1f3a3d0fafc0884e02a2d972e7e5b1be8a385ecc1bc75a977b4073dbd08",
		"1852H/1815H/0H/2/1": "80d04383c04191af5436d6a25b3d193003884f8c770d2c0db6c54a61bf524075199ff847eb73fea22b46ec74e91ff0588715ce946b7983c85ae4d35477019d4a",
	} {
		p, err := cardano.ParsePath(path)
		if err != nil {
			t.Fatal(err)
		}
		k := root.derive(p)
		if got := hex.EncodeToString(k.xpub()); got != want {
			t.Errorf("%s: got %s, want %s", path, got, want)
		}
		msg := []byte("message")
		if !ed25519.Verify(k.public(), msg, k.sign(msg)) {
			t.Errorf("%s: signature does not verify", path)
		}
	}
}
