// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build !(darwin && cgo)

package device

// excludeFromBackup does nothing where there is no Time Machine.
func excludeFromBackup(string) {}
