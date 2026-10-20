// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build darwin && cgo

package device

/*
#cgo LDFLAGS: -framework CoreFoundation
#include <stdlib.h>
#include <string.h>
#include <CoreFoundation/CoreFoundation.h>

static CFURLRef bk_url(const char *path) {
	return CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (const UInt8 *)path, strlen(path), false);
}

// bk_exclude leaves path out of Time Machine backups. The mark is an
// attribute of the file, so it stays through a rename.
static Boolean bk_exclude(const char *path) {
	CFURLRef u = bk_url(path);
	if (!u) return false;
	Boolean ok = CFURLSetResourcePropertyForKey(u, kCFURLIsExcludedFromBackupKey, kCFBooleanTrue, NULL);
	CFRelease(u);
	return ok;
}

static Boolean bk_excluded(const char *path) {
	CFURLRef u = bk_url(path);
	if (!u) return false;
	CFTypeRef v = NULL;
	Boolean ok = CFURLCopyResourcePropertyForKey(u, kCFURLIsExcludedFromBackupKey, &v, NULL) && v == kCFBooleanTrue;
	if (v) CFRelease(v);
	CFRelease(u);
	return ok;
}
*/
import "C"

import "unsafe"

// excludeFromBackup leaves the file of the credentials out of Time Machine.
// It is best effort: a file system without extended attributes keeps the
// file all the same.
func excludeFromBackup(path string) {
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	C.bk_exclude(p)
}

// excludedFromBackup tells whether Time Machine leaves path out.
func excludedFromBackup(path string) bool {
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	return C.bk_excluded(p) != 0
}
