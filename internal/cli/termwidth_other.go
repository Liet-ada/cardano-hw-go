// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build !darwin && !linux

package cli

// stdoutColumns is 0 where the terminal width is not known.
func stdoutColumns() int { return 0 }
