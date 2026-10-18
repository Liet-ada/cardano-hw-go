# cardano-hw-go

A Go reimplementation of [cardano-hw-cli](https://github.com/vacuumlabs/cardano-hw-cli): it signs Cardano transactions with hardware wallets, with the same commands, options, files and exit codes. It supports the Trezor Safe 7, which requires the Trezor Host Protocol (THP).

**Status:** under construction. Not ready for real funds.

| Part | State |
|---|---|
| Command line | Same help, usage and errors as cardano-hw-cli 1.20.0-beta.4, including how it reads and checks the files it is given |
| `transaction validate`, `transaction transform` | Same output as cardano-hw-cli 1.20.0-beta.4 on 5508 test transactions and on 30 of mainnet and preprod |
| Ledger (Cardano app v7 and v8) | Same output, files and APDUs as cardano-hw-cli 1.20.0-beta.4 against a simulated Ledger, on its Ledger test cases (whose keys and signatures come from a real device), on 30 transactions of mainnet and preprod and 1836 more; not yet tested on a device |
| Trezor (THP and Codec v1) | All commands pass against the Trezor Safe 7 emulator |
| USB on macOS (IOKit) | Builds; not yet tested on a device |
| Keystone | Not started |
| Linux (usbfs, hidraw) | Not started |

## Build

```
make check   # format, vet, tests with -race
make fuzz    # each fuzz target for FUZZTIME (1m), including a comparison with fxamacker/cbor
make build   # bin/cardano-hw-go
make build-emulators   # bin/emulators/cardano-hw-go, which also opens emulators (tests only)
```

Requires Go 1.26.8 or newer. On macOS, cgo links only the system's IOKit and CoreFoundation frameworks.

## Use

The commands are those of cardano-hw-cli, for example:

```
cardano-hw-go address key-gen --path 1852H/1815H/0H/0/0 --hw-signing-file payment.hwsfile --verification-key-file payment.vkey
cardano-hw-go transaction witness --testnet-magic 1 --tx-file tx.raw --hw-signing-file payment.hwsfile --out-file payment.witness
```

A Ledger needs the Cardano app 7.0 or newer, open on the device; close Ledger Live while signing. The first time it connects to a Trezor that uses THP, it pairs with the six-digit code the Trezor shows, asked on the terminal. It then keeps a pairing credential, which holds no wallet key: every action still needs confirmation on the device. Close Trezor Suite while signing, since it holds the USB interface.

Environment variables:

| Variable | Use |
|---|---|
| `CARDANO_HW_GO_DEVICE` | `trezor`, `ledger` or `keystone`, when several devices are connected |
| `CARDANO_HW_GO_THP_STORE` | file of THP credentials (default: the user config directory) |
| `CARDANO_HW_GO_HOST_NAME` | host name the Trezor shows when pairing and keeps among its paired hosts (default: `cardano-hw-go`, not the computer's name) |

Only builds with `-tags emulators` (`make build-emulators`), for tests, know these; no environment variable can point the normal binary at a device that is not on USB:

| Variable | Use |
|---|---|
| `CARDANO_HW_GO_TREZOR_EMULATOR` | `host:port` of the Trezor emulator instead of USB |
| `CARDANO_HW_GO_LEDGER_SPECULOS` | `host:port` of the APDU port of the Speculos emulator (or `internal/ledger/ledgersim`) instead of a USB Ledger |
| `CARDANO_HW_GO_DEBUGLINK` | `1` to answer the emulator's screens through its debug link |

## Differences from cardano-hw-cli

Where cardano-hw-cli mishandles an input, crashing with a JavaScript error or going on with a value it should refuse, cardano-hw-go does what cardano-hw-cli means to do instead of copying the defect. [internal/defects](internal/defects/defects.go) lists them. The tests that compare cardano-hw-go with recordings of cardano-hw-cli expect the correction where a recording shows a defect, and each defect has a test of its own.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
