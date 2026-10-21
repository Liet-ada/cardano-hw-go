// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package trezor

import (
	"errors"
	"fmt"
	"testing"

	"github.com/Liet-ada/cardano-hw-go/internal/trezor"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/msg"
)

// TestDeviceError checks that failures of the Trezor read as
// trezor-connect words them, and stay failures underneath.
func TestDeviceError(t *testing.T) {
	for _, c := range []struct {
		f    trezor.Failure
		want string
	}{
		{trezor.Failure{Code: msg.FailureActionCancelled, Message: "Cancelled"}, "Cancelled"},
		{trezor.Failure{Code: msg.FailureDataError, Message: "Forbidden key path"}, "Forbidden key path"},
		{trezor.Failure{Code: msg.FailureActionCancelled}, "Action cancelled by user"},
		{trezor.Failure{Code: msg.FailureFirmwareError}, "Firmware installation failed"},
		{trezor.Failure{Code: msg.FailureProcessError}, "Failure_UnknownMessage"},
	} {
		f := c.f
		err := deviceError(fmt.Errorf("call: %w", &f))
		if err.Error() != c.want {
			t.Errorf("%+v: %q, want %q", c.f, err.Error(), c.want)
		}
		if trezor.Cancelled(err) != (c.f.Code == msg.FailureActionCancelled) {
			t.Errorf("%+v: Cancelled is %v", c.f, trezor.Cancelled(err))
		}
	}
	other := errors.New("usb: device disconnected")
	if err := deviceError(other); err != other {
		t.Errorf("an error that is no failure became %v", err)
	}
}
