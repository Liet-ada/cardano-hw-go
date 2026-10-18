// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package device

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Liet-ada/cardano-hw-go/internal/trezor/thp"
)

// ErrNoTerminal reports that pairing needs a person at a terminal.
var ErrNoTerminal = errors.New("this computer is not paired with the Trezor yet; run `cardano-hw-go device version` in a terminal once to pair it with the code the Trezor shows")

// TerminalUI asks for the pairing code on the controlling terminal, so it
// works even when standard input and output are redirected.
type TerminalUI struct {
	Messages io.Writer // where to tell the person what to do
}

// PairingCode reads the six-digit code from the terminal.
func (u *TerminalUI) PairingCode(thp.PairingInfo) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", ErrNoTerminal
	}
	defer tty.Close()
	fmt.Fprint(tty, "Enter the 6-digit code shown on the Trezor: ")
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// ButtonRequest tells the person to look at the Trezor.
func (u *TerminalUI) ButtonRequest(code uint32, name string) {
	if u.Messages != nil {
		fmt.Fprintln(u.Messages, "Confirm on the Trezor.")
	}
}
