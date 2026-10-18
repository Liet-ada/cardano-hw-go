// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build darwin && cgo

package device

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <stdlib.h>
#include <string.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

static CFStringRef kc_str(const char *s) {
	return CFStringCreateWithCString(kCFAllocatorDefault, s, kCFStringEncodingUTF8);
}

// kc_query matches the generic passwords of service, and of account if it
// is not NULL.
static CFMutableDictionaryRef kc_query(const char *service, const char *account) {
	CFMutableDictionaryRef q = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
	CFStringRef s = kc_str(service);
	CFDictionarySetValue(q, kSecAttrService, s);
	CFRelease(s);
	if (account) {
		CFStringRef a = kc_str(account);
		CFDictionarySetValue(q, kSecAttrAccount, a);
		CFRelease(a);
	}
	return q;
}

// kc_save stores data as the password of (service, account), replacing
// the one there.
static OSStatus kc_save(const char *service, const char *account, const char *label, const void *data, int len) {
	CFDataRef d = CFDataCreate(kCFAllocatorDefault, data, len);
	CFMutableDictionaryRef q = kc_query(service, account);
	CFMutableDictionaryRef set = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(set, kSecValueData, d);
	OSStatus st = SecItemUpdate(q, set);
	if (st == errSecItemNotFound) {
		CFStringRef l = kc_str(label);
		CFDictionarySetValue(q, kSecAttrLabel, l);
		CFRelease(l);
		CFDictionarySetValue(q, kSecValueData, d);
		st = SecItemAdd(q, NULL);
	}
	CFRelease(set);
	CFRelease(q);
	CFRelease(d);
	return st;
}

// kc_load copies the password of (service, account) into a buffer the
// caller frees.
static OSStatus kc_load(const char *service, const char *account, void **out, int *len) {
	CFMutableDictionaryRef q = kc_query(service, account);
	CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
	CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
	CFTypeRef r = NULL;
	OSStatus st = SecItemCopyMatching(q, &r);
	CFRelease(q);
	if (st != errSecSuccess) return st;
	CFIndex n = CFDataGetLength((CFDataRef)r);
	*out = malloc(n ? n : 1);
	memcpy(*out, CFDataGetBytePtr((CFDataRef)r), n);
	*len = (int)n;
	CFRelease(r);
	return st;
}

// kc_accounts lists the accounts of service, one per line, in a string
// the caller frees. Attributes only: reading a password may ask the
// person, so each is read on its own.
static OSStatus kc_accounts(const char *service, char **out) {
	CFMutableDictionaryRef q = kc_query(service, NULL);
	CFDictionarySetValue(q, kSecReturnAttributes, kCFBooleanTrue);
	CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitAll);
	CFTypeRef r = NULL;
	OSStatus st = SecItemCopyMatching(q, &r);
	CFRelease(q);
	if (st == errSecItemNotFound) {
		*out = strdup("");
		return errSecSuccess;
	}
	if (st != errSecSuccess) return st;
	CFIndex n = CFArrayGetCount((CFArrayRef)r);
	char *buf = calloc(n * 257 + 1, 1);
	for (CFIndex i = 0; i < n; i++) {
		CFDictionaryRef item = CFArrayGetValueAtIndex((CFArrayRef)r, i);
		CFTypeRef a = CFDictionaryGetValue(item, kSecAttrAccount);
		char acc[256];
		if (a && CFGetTypeID(a) == CFStringGetTypeID() &&
			CFStringGetCString((CFStringRef)a, acc, sizeof acc, kCFStringEncodingUTF8)) {
			strcat(buf, acc);
			strcat(buf, "\n");
		}
	}
	CFRelease(r);
	*out = buf;
	return st;
}

static OSStatus kc_delete(const char *service, const char *account) {
	CFMutableDictionaryRef q = kc_query(service, account);
	OSStatus st = SecItemDelete(q);
	CFRelease(q);
	return st;
}

// kc_message describes st in a buffer the caller frees.
static char *kc_message(OSStatus st) {
	CFStringRef m = SecCopyErrorMessageString(st, NULL);
	char *buf = calloc(512, 1);
	if (m) {
		CFStringGetCString(m, buf, 512, kCFStringEncodingUTF8);
		CFRelease(m);
	}
	return buf;
}
*/
import "C"

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"unsafe"

	"github.com/Liet-ada/cardano-hw-go/internal/trezor/thp"
)

// KeychainService is the service of the keychain items that hold THP
// credentials.
const KeychainService = "cardano-hw-go"

// KeychainStore keeps THP credentials in the login keychain of macOS, one
// generic password per Trezor, whose account is the Trezor's static public
// key in hex. Other programs need the person's leave to read them.
type KeychainStore struct {
	Service string
}

// defaultStore is the keychain.
func defaultStore() (thp.Store, error) { return &KeychainStore{Service: KeychainService}, nil }

// keychainSecret is what an item holds besides its account.
type keychainSecret struct {
	HostStaticPrivateKey string `json:"host_static_private_key"`
	Credential           string `json:"credential"`
}

func keychainError(what string, st C.OSStatus) error {
	m := C.kc_message(st)
	defer C.free(unsafe.Pointer(m))
	return fmt.Errorf("keychain: %s: %s (%d)", what, C.GoString(m), int(st))
}

// Credentials returns the stored credentials.
func (s *KeychainStore) Credentials() ([]thp.Credential, error) {
	service := C.CString(s.Service)
	defer C.free(unsafe.Pointer(service))
	var list *C.char
	if st := C.kc_accounts(service, &list); st != C.errSecSuccess {
		return nil, keychainError("listing the credentials", st)
	}
	accounts := C.GoString(list)
	C.free(unsafe.Pointer(list))
	var out []thp.Credential
	for _, account := range strings.Fields(accounts) {
		trezorKey, err := hex.DecodeString(account)
		if err != nil {
			continue // not an item of ours
		}
		acc := C.CString(account)
		var data unsafe.Pointer
		var n C.int
		st := C.kc_load(service, acc, &data, &n)
		C.free(unsafe.Pointer(acc))
		if st != C.errSecSuccess {
			return nil, keychainError("reading a credential", st)
		}
		b := C.GoBytes(data, n)
		C.free(data)
		var sec keychainSecret
		if err := json.Unmarshal(b, &sec); err != nil {
			return nil, fmt.Errorf("keychain: credential of %s: %w", account, err)
		}
		hostKey, err1 := hex.DecodeString(sec.HostStaticPrivateKey)
		cred, err2 := hex.DecodeString(sec.Credential)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("keychain: credential of %s is not hex", account)
		}
		out = append(out, thp.Credential{TrezorStaticPublicKey: trezorKey, HostStaticPrivateKey: hostKey, Credential: cred})
	}
	return out, nil
}

// Save adds a credential, replacing any for the same Trezor.
func (s *KeychainStore) Save(c thp.Credential) error {
	data, err := json.Marshal(keychainSecret{hex.EncodeToString(c.HostStaticPrivateKey), hex.EncodeToString(c.Credential)})
	if err != nil {
		return err
	}
	service := C.CString(s.Service)
	defer C.free(unsafe.Pointer(service))
	account := C.CString(hex.EncodeToString(c.TrezorStaticPublicKey))
	defer C.free(unsafe.Pointer(account))
	label := C.CString("cardano-hw-go pairing with a Trezor")
	defer C.free(unsafe.Pointer(label))
	if st := C.kc_save(service, account, label, unsafe.Pointer(&data[0]), C.int(len(data))); st != C.errSecSuccess {
		return keychainError("saving the credential", st)
	}
	return nil
}

// remove deletes the credential of a Trezor, if there is one.
func (s *KeychainStore) remove(trezorStaticPublicKey []byte) error {
	service := C.CString(s.Service)
	defer C.free(unsafe.Pointer(service))
	account := C.CString(hex.EncodeToString(trezorStaticPublicKey))
	defer C.free(unsafe.Pointer(account))
	if st := C.kc_delete(service, account); st != C.errSecSuccess && st != C.errSecItemNotFound {
		return keychainError("deleting a credential", st)
	}
	return nil
}
