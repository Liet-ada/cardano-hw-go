# cardano-hw-go

`cardano-hw-go` is a Go reimplementation of
[`cardano-hw-cli`](https://github.com/vacuumlabs/cardano-hw-cli), the command
line tool for using hardware wallets with Cardano: exporting public keys,
showing addresses on the device, signing transactions (witnesses), signing
messages, CIP-36 vote registrations, and pool operational certificates, and
validating and transforming transactions. It has the same commands, options,
files and exit codes as `cardano-hw-cli` 1.20.0-beta.4, and it is a drop-in
replacement: a program that calls `cardano-hw-cli` can call `cardano-hw-go`
with the same arguments.

Why it exists: `cardano-hw-cli` cannot use the Trezor Safe 7, which requires
the Trezor Host Protocol (THP), an encrypted channel set up with a pairing
code. `cardano-hw-go` implements THP from the Trezor specification.

For the sake of that parity, the help and usage messages name the program
`cardano-hw-cli`, not `cardano-hw-go`.

## What it is, and who it is for

`cardano-hw-go` is for anyone who signs Cardano transactions, messages or
CIP-36 vote registrations with a hardware wallet from the command line, and
who wants a single tool that works with current Trezors and Ledgers. It is
aimed at the same people as `cardano-hw-cli`, with the addition of the
Trezor Safe 7 (which `cardano-hw-cli` cannot talk to).

It talks to the device directly over USB. It does not use Trezor Bridge,
Trezor Suite or Ledger Live: on macOS it uses IOKit (cgo, linked only against
the system's IOKit and CoreFoundation frameworks); on Linux it builds without
cgo and uses usbfs for Trezor and hidraw for Ledger.

## Status

| Part | State |
|---|---|
| Command line | Same help, usage, errors and file handling as `cardano-hw-cli` 1.20.0-beta.4, checked against 486 recorded cases in `internal/cli/testdata/cli` |
| `transaction validate`, `transaction transform` | Same output as `cardano-hw-cli` 1.20.0-beta.4 on 5508 generated test transactions and on 30 real transactions of mainnet and preprod |
| Ledger | Same output, files and APDUs as `cardano-hw-cli` 1.20.0-beta.4 against a simulated Ledger, in hundreds of recorded cases (`internal/cli/testdata/ledger-*.json.gz`). On a real Ledger Nano S (app 7.1.4), `device version`, `address key-gen`, `node key-gen`, `address show`, `transaction witness`, `message sign` and the CIP-36 registration give the same keys, witnesses and errors as `cardano-hw-cli`. App v8 has not been tested on a device |
| Trezor (THP and Codec v1) | All commands pass against the emulators of the Trezor Safe 7 (THP) and of the Model T, Safe 3 and Safe 5 (Codec v1), firmware 2.13.0. On a real Safe 7 (firmware 2.12.5), pairing, `device version`, `address key-gen`, `address show`, `transaction witness`, `message sign` and CIP-36 on preprod work, and the signatures verify. Codec v1 has not been tested on a device |
| USB on macOS (IOKit) | Tested with a Trezor Safe 7 and a Ledger Nano S |
| USB on Linux | hidraw (Ledger) tested with a Ledger Nano S on Ubuntu; usbfs (Trezor) not yet tested on a device |
| Keystone | Not implemented |

## Supported devices

| Device | Protocol | Requirement | Tested |
|---|---|---|---|
| Trezor Safe 7 | THP | Firmware that speaks THP | Emulator (2.13.0) and a real device (2.12.5) |
| Trezor Model T, Safe 3, Safe 5 | Codec v1 | Firmware that speaks Codec v1 | Emulators (2.13.0); not yet on a device |
| Trezor Model One | — | Not supported | The tool refuses it ("the Trezor Model One does not support Cardano") |
| Ledger (any model) | APDU over HID | Cardano app 7.0 or newer (older apps are rejected); app 8 for unrestricted mode | Simulated Ledger; a real Nano S (app 7.1.4). App 8 not yet on a device |
| Keystone | — | Not implemented | — |

What each device does not do, as found in the code:

* A Trezor does not export vote keys (`1694'` paths; `address key-gen` on one
  is refused with "Forbidden key path"), does not sign operational
  certificates, does not sign a pool registration as operator, and does not
  sign transactions with voting procedures, a treasury item or a donation
  item. It also does not support the `--hashed` option of `message sign`,
  and it does not support unrestricted signing mode.
* The Ledger Nano S with the reduced app (`-NanoS`, reported by the device as
  the `XS` build) does not do Byron addresses, pool registration or pool
  retirement, native script hashes, or operational certificates. Message
  signing needs app 7.1 or newer. Unrestricted mode, and more than one voter
  or more than one vote per voter in voting procedures, need app 8.

## Install

Requirements:

* Go 1.26.8 or newer (the version in `go.mod`).
* On macOS, cgo is needed; it links only the system's IOKit and
  CoreFoundation frameworks. On Linux, the build uses no cgo.

There are no published binaries. Build from source:

```
make build
```

This writes `bin/cardano-hw-go`. To build with `go build` or `go install`
directly, pass `-trimpath`:

```
go build -trimpath -o cardano-hw-go ./cmd/cardano-hw-go
go install -trimpath github.com/Liet-ada/cardano-hw-go/cmd/cardano-hw-go
```

`-trimpath` keeps the build machine's file paths, and the user name in them,
out of the binary; without it, the binary records the path of every source
file, including the name of whoever built it. `make build` already uses it.

## Prepare the system

* Close Trezor Suite and Ledger Live while signing: a wallet that holds the
  USB interface stops `cardano-hw-go` from opening the device.
* On a Ledger, open the Cardano app on the device before running a command.
* On Linux, the user needs access to the USB devices. Install the udev rules
  that Trezor and Ledger publish (`51-trezor.rules` from Trezor and
  `20-hw1.rules` from Ledger). This project does not ship its own rules.

## First steps

A run through preprod (`--testnet-magic 1`) with a Trezor or a Ledger. The
`cardano-cli` steps (all with the `conway` era prefix) are outside this
program and are shown only to connect the pieces; adjust them to your
`cardano-cli` version.

```
# Export the payment and stake keys (confirm the export on the device).
cardano-hw-go address key-gen \
  --path 1852H/1815H/0H/0/0 --hw-signing-file payment.hwsfile --verification-key-file payment.vkey
cardano-hw-go address key-gen \
  --path 1852H/1815H/0H/2/0 --hw-signing-file stake.hwsfile --verification-key-file stake.vkey

# Build the address from the verification keys (outside this program).
cardano-cli conway address build \
  --payment-verification-key-file payment.vkey \
  --stake-verification-key-file stake.vkey \
  --testnet-magic 1 --out-file payment.addr

# Show the address on the device and check it matches the file.
cardano-hw-go address show \
  --payment-path 1852H/1815H/0H/0/0 --staking-path 1852H/1815H/0H/2/0 \
  --address-file payment.addr

# Build the transaction body (outside this program). The --tx-file of
# "transaction witness" is the unwitnessed transaction this writes.
cardano-cli conway transaction build-raw ... --out-file tx.raw

# Sign it on the device. The example transaction returns its change to the
# address above, so the change outputs are marked with the payment and stake
# signing files; that is what makes the device recognize them as its own.
cardano-hw-go transaction witness \
  --testnet-magic 1 --tx-file tx.raw \
  --hw-signing-file payment.hwsfile --out-file payment.witness \
  --change-output-key-file payment.hwsfile --change-output-key-file stake.hwsfile

# Join the witness into a signed transaction (outside this program).
cardano-cli conway transaction assemble \
  --tx-body-file tx.raw --witness-file payment.witness --out-file tx.signed

# Submit it (outside this program): with a running node, or a submit API.
cardano-cli conway transaction submit --tx-file tx.signed ...
```

## Command reference

The commands are exactly those of `cardano-hw-cli`. Run `cardano-hw-go
--help` or a subcommand with `--help` for the full usage; the output names the
program `cardano-hw-cli`. What follows summarises each command.

### Files

* A **hardware wallet signing file** (`.hwsfile`) is written by
  `address key-gen` and `node key-gen`. It holds a derivation path and the
  extended public key (64 bytes) for it, and no secret. Its `type` records the
  role of the key (payment, stake, and so on), which is checked against the
  path when the file is read back.
* A **verification key file** (`.vkey`) is a `cardano-cli` text envelope with
  the public key; `address key-gen` writes one next to each signing file.
* A **transaction file** is a `cardano-cli` text envelope (for example
  `Unwitnessed Tx ConwayEra`) whose `cborHex` is the transaction body. For
  `transaction witness`, `--tx-file` is the unwitnessed transaction written by
  `cardano-cli conway transaction build-raw`. The help still mentions
  `--cddl-format` for building it, because it copies `cardano-hw-cli`'s help.
* A **witness file** is a `cardano-cli` witness envelope; its type follows the
  transaction's era (`TxWitness ConwayEra` for a Conway-era transaction,
  `TxWitnessByron` for a Byron one).

### Derivation paths

Paths are written like `1852H/1815H/0H/0/0`, where `H` marks a hardened
index. The common ones:

* `1852H/1815H/0H/0/0` — payment (Shelley), `1852H/1815H/0H/2/0` — stake.
* `1853H/1815H/0H/0H` — pool cold key (for `node key-gen`).
* `44H/1815H/0H/0/0` — Byron payment.
* `1694H/1815H/0H/0/0` — CIP-36 vote key (a Trezor refuses to export it).
* `1854H/1815H/0H/0/0` — multisig payment, `1855H/1815H/0H` — minting key.

`--derivation-type` selects how a **Trezor** derives Cardano keys from the
seed: `LEDGER`, `ICARUS`, or `ICARUS_TREZOR` (the default). It is accepted on
`address key-gen`, `address show`, `transaction witness`, `transaction
policyid`, `message sign` and `vote registration-metadata`, and it applies only
to Trezor; a Ledger ignores it.

### `version`

Prints the version and the `cardano-hw-cli` version it is compatible with:

```
cardano-hw-go version
```

### `device version`

Prints the device or app version: `Trezor app version x.y.z` or
`Ledger app version x.y.z`.

```
cardano-hw-go device version
```

### `address key-gen`

Exports one or more extended public keys and writes a `.hwsfile` and a
`.vkey` for each. The number of `--path`, `--hw-signing-file` and
`--verification-key-file` arguments must match.

```
cardano-hw-go address key-gen \
  --path 1852H/1815H/0H/0/0 --hw-signing-file payment.hwsfile --verification-key-file payment.vkey
```

### `address show`

Shows the address from `--address-file` on the device. Give the payment and
staking parts as derivation paths or as script hashes, matching the address
type. With a Trezor, the program checks that the address the device derives is
the one in the file.

```
cardano-hw-go address show \
  --payment-path 1852H/1815H/0H/0/0 --staking-path 1852H/1815H/0H/2/0 \
  --address-file payment.addr
```

### `key verification-key`

Derives a `.vkey` from an existing `.hwsfile`, without asking the device.

```
cardano-hw-go key verification-key \
  --hw-signing-file payment.hwsfile --verification-key-file payment.vkey
```

### `transaction policyid`

Asks the device to compute the policy id of a native script file, so that the
policy id is shown on the device. `--hw-signing-file` names the keys the
script uses.

```
cardano-hw-go transaction policyid --script-file policy.script \
  --hw-signing-file payment.hwsfile
```

### `transaction witness`

Signs a transaction body on the device and writes one witness file per key.
`--mainnet` or `--testnet-magic` gives the network; `--change-output-key-file`
marks outputs that return to the wallet; `--out-file` is repeatable.

```
cardano-hw-go transaction witness \
  --testnet-magic 1 --tx-file tx.raw \
  --hw-signing-file payment.hwsfile --out-file payment.witness
```

### `transaction validate`

Validates a transaction body without a device and reports the CIP-21 issues
on stderr. It exits 0 when the transaction is valid and canonical, 2 when it
has unfixable issues, and 3 when it has fixable issues (run `transform`).

```
cardano-hw-go transaction validate --tx-file tx.raw
```

### `transaction transform`

Rewrites a transaction body so the hardware wallet can sign it, and writes the
result. It needs `--protocol-params-file` for transactions with Plutus scripts
and `--used-cost-model-languages` for reference-script-only transactions.

```
cardano-hw-go transaction transform --tx-file tx.raw --out-file tx.transformed
```

`--allow-unrestricted-mode` (on `validate`, `transform` and `witness`) permits
unrestricted signing mode for transactions that need it (Ledger app 8 or newer
with expert mode enabled on the device), and silently ignores a fixed set of
CIP-21 issues.

### `node key-gen`

Exports pool cold keys and writes a `.hwsfile`, a cold `.vkey` and an
operational-certificate issue-counter file per path.

```
cardano-hw-go node key-gen \
  --path 1853H/1815H/0H/0H --hw-signing-file pool.hwsfile \
  --cold-verification-key-file pool.vkey \
  --operational-certificate-issue-counter-file pool.counter
```

### `node issue-op-cert`

Signs a pool operational certificate with the cold key (a Trezor does not
support this). It reads the KES verification key, the KES period, the issue
counter and the cold signing file, and updates the counter.

```
cardano-hw-go node issue-op-cert \
  --kes-verification-key-file kes.vkey --kes-period 100 \
  --operational-certificate-issue-counter-file pool.counter \
  --hw-signing-file pool.hwsfile --out-file op.cert
```

### `vote registration-metadata`

Signs a CIP-36 vote registration and writes the metadata CBOR. Vote public
keys are given as bech32, ed25519-extended, `.hwsfile`, or `cardano-cli` files;
`--vote-weight` matches each. `--stake-signing-key-hwsfile` signs the
registration; `--payment-address` receives the rewards; `--nonce` is the
current slot.

```
cardano-hw-go vote registration-metadata \
  --testnet-magic 1 \
  --vote-public-key-string vote_vk1... \
  --stake-signing-key-hwsfile stake.hwsfile \
  --payment-address addr_test1... --nonce 12345678 \
  --metadata-cbor-out-file vote.cbor
```

### `message sign`

Signs a CIP-8 message. `--message` (ASCII) and `--message-hex` are mutually
exclusive; `--hashed` hashes the payload; `--address` and `--address-hwsfile`
set the address in the COSE header (otherwise the signing key hash is used).

```
cardano-hw-go message sign --message "Hello Cardano" \
  --signing-path-hwsfile payment.hwsfile --out-file message.json
```

## Pairing with a Trezor Safe 7 (THP)

The Safe 7, and any Trezor whose firmware uses THP, speaks THP, an encrypted
channel. The first time `cardano-hw-go` connects to one, it pairs:

1. The Trezor shows a six-digit code.
2. The program asks for it on the controlling terminal
   (`Enter the 6-digit code shown on the Trezor:`), so pairing works even when
   standard input and output are redirected. If there is no terminal at all,
   it tells you to run `cardano-hw-go device version` in a terminal once.
3. After the code is checked, the Trezor issues a pairing credential, which the
   program saves.

What is saved, and where: a JSON file with, for each paired Trezor, the
Trezor's static public key, this host's static private key, and the credential.
The credential is **not a key of the wallet** — it only lets this host reopen
the encrypted channel without the pairing code; every action still needs a
confirmation on the Trezor. The file lives in the user's config directory
(`os.UserConfigDir`): `~/Library/Application Support/cardano-hw-go/thp-credentials.json`
on macOS, and `~/.config/cardano-hw-go/thp-credentials.json` on Linux (or
`$XDG_CONFIG_HOME/cardano-hw-go/thp-credentials.json`). The directory is
created mode 0700 and the file is written 0600, so only its owner can read it.
On macOS it is marked as excluded from Time Machine backups.

After the first time, the program reopens the channel with the credential and
does not ask for the code again, but it still waits for the confirmation on the
device each time. The host name the Trezor shows when pairing, and keeps among
its paired hosts, defaults to `cardano-hw-go` (not the computer's name), and
can be changed with `CARDANO_HW_GO_HOST_NAME`.

If the Trezor forgets this host, the host presents its credential, the Trezor
answers that it is not paired, and the program pairs again. If the Trezor is
reset or wiped, its static key changes: the host does not recognize it, sends
no credential, and the Trezor asks to pair as on the first time. Either way the
program asks for the code and saves the new credential of that Trezor. There
is no need to delete the credentials file, and deleting it would remove the
credentials of every Trezor. A damaged credential entry is skipped so that it
does not block the other Trezors; its Trezor simply asks to pair again.

## Environment variables

The normal binary reads these:

| Variable | Use |
|---|---|
| `CARDANO_HW_GO_DEVICE` | `trezor`, `ledger` or `keystone`, to choose when several wallets are connected |
| `CARDANO_HW_GO_THP_STORE` | File that holds THP credentials (default: the user config directory) |
| `CARDANO_HW_GO_HOST_NAME` | Host name the Trezor shows when pairing and keeps among its paired hosts (default: `cardano-hw-go`) |

Only builds with `-tags emulators` (`make build-emulators`), for tests, know
the next three. The normal binary does not know them, so no environment
variable can point a real binary at a device that is not on USB:

| Variable | Use |
|---|---|
| `CARDANO_HW_GO_TREZOR_EMULATOR` | `host:port` of the Trezor emulator instead of USB |
| `CARDANO_HW_GO_LEDGER_SPECULOS` | `host:port` of the APDU port of a Speculos emulator (or a simulator speaking its protocol) instead of a USB Ledger |
| `CARDANO_HW_GO_DEBUGLINK` | `1` to answer the emulator's screens through its debug link, `reject` to refuse the screens of each operation |

## Exit codes

As `cardano-hw-cli` uses them (`internal/cli/cli.go`):

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Error |
| 2 | `transaction validate` found unfixable issues; also command-line (argparse) usage errors |
| 3 | `transaction validate` found fixable issues |

`transaction transform` reports unfixable issues as an error (exit 1) rather
than with a dedicated code.

## Security

The private keys never leave the device. The `.hwsfile` and `.vkey` files
contain only public keys.

The program checks what the device returns:

* **Transaction body hash.** After a device signs, the program compares the
  hash of the transaction body the device says it signed with the hash it
  computed itself (`Tx serialization mismatch` otherwise). This catches a
  device that signed a body different from the transaction file — for example,
  if the program and the device serialized it differently.
* **Each signature.** Every witness signature is verified with Ed25519 against
  the public key of the signing file and the body hash (`Signing public key
  mismatch` otherwise).
* **The address in `address show` (Trezor).** The Trezor derives the address
  from the paths itself; the program compares it with the address file and
  fails if they differ.
* **Message and CIP-36 outputs.** The address and public key the device returns
  for a message signature are checked, and the CIP-36 auxiliary-data hash the
  device signed is checked against the metadata the program encodes.

### Check the address on the device

THP authenticates a Trezor Safe 7 with the credential from pairing, but a
device posing as a Trezor on the USB path can always present itself as an
older Trezor, which speaks Codec v1 without encryption or authentication, and
answer with keys of its own. As with any hardware wallet, before receiving
funds, show the receiving address on the device (`address show`) and compare it
with the one you will use. The private keys never leave the device either way.

## Differences from `cardano-hw-cli`

Where `cardano-hw-cli` mishandles an input — crashing with a JavaScript error
instead of giving the error it has for the case, going on with a value it
should refuse, or reporting what the device answers as something else —
`cardano-hw-go` does what `cardano-hw-cli` means to do instead of copying the
defect. The list is in [`internal/defects/defects.go`](internal/defects/defects.go).
The tests that compare `cardano-hw-go` with recordings of `cardano-hw-cli`
expect the correction where a recording shows a defect, and each defect has a
test of its own. Examples:

* `transform-tagged-witnesses`: `transaction transform` on a transaction with
  a tagged set of vkey or bootstrap witnesses crashes in `cardano-hw-cli`
  (`shelleyWitnesses is not iterable`); `cardano-hw-go` gives the error
  `cardano-hw-cli` has for a signed transaction it cannot transform.
* `testnet-magic-missing`: `--testnet-magic` without a number leaves the
  network undefined and `cardano-hw-cli` crashes when it reads it;
  `cardano-hw-go` gives the error for a missing protocol magic.
* `trezor-address-not-checked`: `address show` with a Trezor shows the address
  the device derives but `cardano-hw-cli` never compares it with the address
  file; `cardano-hw-go` reports a mismatch when they differ.
* `trezor-key-failure-as-cancel`: `address key-gen` and `node key-gen` with a
  Trezor report any export failure, even a refused path, as "cancelled by the
  user"; `cardano-hw-go` reports the device's message.

## Development

```
make check          # gofmt, go vet (also for the Linux and emulator builds), go test -race
make fuzz           # each fuzz target for FUZZTIME (1m), including the cbor comparison with fxamacker/cbor
make build          # bin/cardano-hw-go
make build-emulators # bin/emulators/cardano-hw-go, which also opens emulators (tests only)
make emulator       # tests against the Trezor emulator, one package at a time
```

The tests compare `cardano-hw-go` with recordings of `cardano-hw-cli`
1.20.0-beta.4: `internal/cli/testdata/cli/cli-golden.json.gz` (486 command-line
cases with no device), `internal/cli/testdata/txs/txs-golden.json.gz`
(`validate` and `transform` on the transactions of `internal/cli/testdata/txs`),
and `internal/cli/testdata/ledger-*.json.gz` (Ledger cases with their APDU
transcripts). `internal/cli/testdata/txs/sources.txt` lists the 30 real
transactions and where they came from. The generated 5508-transaction corpus
comes from `internal/tx/corpus_test.go` (`TestGenerateCorpus`), which mutates
the transactions for differential testing.

To run the Trezor emulator tests, start the emulator with the
`"all all ..."` seed (`emu.py --slip0014`) and point `TREZOR_EMULATOR` at its
address, then `make emulator`. The tests drive the emulator through the
command line, confirming every screen through its debug link.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

The port of the JavaScript `argparse` package (`internal/cli/argparse.go` and
`internal/cli/helpformat.go`) is under the Python Software Foundation License
Version 2; its text is in [LICENSE-PSF](LICENSE-PSF) and the port is described
in [NOTICE](NOTICE).
