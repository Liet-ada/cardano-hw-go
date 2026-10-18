// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Command cardano-hw-go signs Cardano transactions with hardware wallets. It
// takes the same commands and files as cardano-hw-cli.
package main

import (
	"os"

	"github.com/Liet-ada/cardano-hw-go/internal/cli"
	"github.com/Liet-ada/cardano-hw-go/internal/device"
)

func main() {
	app := &cli.App{Stdout: os.Stdout, Stderr: os.Stderr, Devices: &device.Opener{Messages: os.Stderr}}
	os.Exit(app.Run(os.Args[1:]))
}
