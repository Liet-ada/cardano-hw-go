// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package ledger

import (
	"errors"
	"fmt"
)

// Error is an error with ledgerjs's name and message. It prints as
// JavaScript prints an error, "Name: message", which is how cardano-hw-cli
// shows it.
type Error struct {
	Name    string
	Message string
	// Code is the status word of a DeviceStatusError.
	Code uint16
}

func (e *Error) Error() string { return e.Name + ": " + e.Message }

// Status words with a meaning of their own.
const (
	swOK          = 0x9000
	swStillInCall = 0x6e04 // v7 ERR_STILL_IN_CALL, v8 SWO_STILL_IN_CALL_RESET_DONE
	swRejectedV7  = 0x6e09
	swRejectedV8  = 0x6985
)

// statusMessages are ledgerjs's descriptions of the status words of both
// command sets.
var statusMessages = map[uint16]string{
	0x5515: "Device is locked",
	0x6001: "Swap parameter validation failed.",
	0x6982: "Action denied by app's security policy, maybe wrong transaction signing mode?",
	0x6985: "Action rejected by user on device.",
	0x6a81: "Function not supported, is the Cardano app active on the device?",
	0x6b00: "Transaction parsing failed: invalid length.",
	0x6b01: "Transaction parsing failed.",
	0x6b02: "Transaction parsing failed: malformed init APDU.",
	0x6b05: "BIP44 path parsing failed.",
	0x6b06: "Address derivation failed: invalid address parameters.",
	0x6b10: "Operational certificate parsing failed: invalid KES key.",
	0x6b11: "Operational certificate parsing failed: invalid KES period.",
	0x6b12: "Operational certificate parsing failed: invalid issue counter.",
	0x6b13: "Operational certificate parsing failed: invalid pool key path.",
	0x6b14: "Operational certificate parsing failed: invalid length.",
	0x6b20: "Transaction parsing failed: invalid inputs.",
	0x6b21: "Transaction parsing failed: invalid outputs.",
	0x6b22: "Transaction parsing failed: invalid fee.",
	0x6b23: "Transaction parsing failed: invalid TTL.",
	0x6b24: "Transaction parsing failed: invalid certificates.",
	0x6b25: "Transaction parsing failed: invalid withdrawals.",
	0x6b28: "Transaction parsing failed: invalid validity interval start.",
	0x6b29: "Transaction parsing failed: invalid mint field.",
	0x6b2b: "Transaction parsing failed: invalid script data hash.",
	0x6b2d: "Transaction parsing failed: invalid collateral inputs.",
	0x6b2e: "Transaction parsing failed: invalid required signers.",
	0x6b30: "Transaction parsing failed: invalid collateral output.",
	0x6b31: "Transaction parsing failed: invalid total collateral.",
	0x6b32: "Transaction parsing failed: invalid reference inputs.",
	0x6b33: "Transaction parsing failed: invalid voting procedures.",
	0x6b35: "Transaction parsing failed: invalid treasury.",
	0x6b36: "Transaction parsing failed: invalid donation.",
	0x6b37: "Invalid network id.",
	0x6b38: "Invalid protocol magic.",
	0x6b39: "Transaction parsing failed: invalid optional field flag.",
	0x6b3a: "Transaction parsing failed: unexpected extra data.",
	0x6b3b: "Transaction parsing failed: invalid CBOR canonical ordering.",
	0x6b3c: "Transaction parsing failed: unknown signing mode.",
	0x6b3d: "Transaction parsing failed: signing mode is ambiguous.",
	0x6b41: "Native script parsing failed: invalid pubkey credential.",
	0x6b42: "Native script parsing failed: invalid script type.",
	0x6b43: "Native script parsing failed: invalid nesting depth.",
	0x6b44: "Native script parsing failed: invalid time lock.",
	0x6b45: "Native script parsing failed: nesting depth exceeds supported limit.",
	0x6b46: "Native script parsing failed: invalid script count.",
	0x6b47: "Native script parsing failed: invalid display format.",
	0x6b50: "CVote auxiliary data parsing failed.",
	0x6b51: "CVote parsing failed: invalid vote plan id.",
	0x6b52: "CVote parsing failed: invalid proposal index.",
	0x6b53: "CVote parsing failed: invalid payload type tag.",
	0x6b54: "CVote parsing failed: could not read remaining vote cast bytes.",
	0x6b60: "Message signing failed: invalid message length.",
	0x6b61: "Message signing failed: invalid signing path.",
	0x6b62: "Message signing failed: invalid hash payload flag.",
	0x6b63: "Message signing failed: invalid isAscii flag.",
	0x6b64: "Message signing failed: invalid address field type.",
	0x6b65: "Message signing failed: invalid address parameters.",
	0x6b66: "Message signing failed: invalid chunk size.",
	0x6b67: "Message signing failed: invalid chunk data.",
	0x6b68: "Message signing failed: chunk size validation failed.",
	0x6b69: "Message signing failed: message contains non-ASCII characters.",
	0x6b6a: "Message signing failed: invalid address field type value.",
	0x6b6b: "Message signing failed: confirm APDU must be empty.",
	0x6e00: "Wrong Ledger app",
	0x6e01: "App not selected on device.",
	0x6e07: "Invalid data supplied to Ledger",
	0x6e08: "Invalid derivation path supplied to Ledger",
	0x6e09: "Action rejected by user on device.",
	0x6e10: "Action denied by app's security policy, maybe wrong transaction signing mode?",
	0x6e11: "Device is locked",
	0x6e12: "Unsupported address type",
}

// StatusError is the error of a status word other than success.
func StatusError(sw uint16) *Error {
	m, ok := statusMessages[sw]
	if !ok {
		m = fmt.Sprintf("General error 0x%x. Please consult https://github.com/LedgerHQ/app-cardano-new/blob/master/src/cardano_swo.h", sw)
	}
	return &Error{Name: "DeviceStatusError", Message: m, Code: sw}
}

// InvalidData is ledgerjs's error for a request it refuses before sending
// it.
func InvalidData(reason string) *Error { return &Error{Name: "InvalidData", Message: reason} }

func invalidData(reason string) *Error { return InvalidData(reason) }

func errorBase(msg string) *Error { return &Error{Name: "ErrorBase", Message: msg} }

func assertion(msg string) *Error { return errorBase("Assertion failed: " + msg) }

func unsupported(v Version, what string) *Error {
	return &Error{Name: "DeviceVersionUnsupported", Message: fmt.Sprintf("%s not supported by Ledger app version %s.", what, v)}
}

// Rejected reports whether the person rejected the action on the device.
func Rejected(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Name == "DeviceStatusError" && (e.Code == swRejectedV7 || e.Code == swRejectedV8)
}
