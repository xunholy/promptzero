package flipper

import (
	"strings"
	"testing"
)

// CryptoStoreKey validates slot, keyType, keySize, and keyHex before
// transport. Pre-fix, all four were forwarded verbatim to
// `crypto store_key`. An LLM passing keyType="aes256" (sounds plausible
// but isn't in the firmware allowlist) got back an opaque banner, while
// a hex/size mismatch silently corrupted the slot on some forks.

func TestValidateCryptoStoreKey_AcceptsValid(t *testing.T) {
	cases := []struct {
		slot    int
		keyType string
		keySize int
		hex     string
	}{
		{1, "master", 128, strings.Repeat("AB", 16)},
		{50, "simple", 128, strings.Repeat("cd", 16)},
		{100, "encrypted", 256, strings.Repeat("0F", 32)},
	}
	for _, c := range cases {
		if err := validateCryptoStoreKey(c.slot, c.keyType, c.keySize, c.hex); err != nil {
			t.Errorf("validateCryptoStoreKey(%d, %q, %d, %q) = %v; want nil",
				c.slot, c.keyType, c.keySize, c.hex, err)
		}
	}
}

func TestCryptoStoreKey_RejectsBadSlot(t *testing.T) {
	f := &Flipper{}
	for _, slot := range []int{-1, 0} {
		_, err := f.CryptoStoreKey(slot, "simple", 128, strings.Repeat("AB", 16))
		if err == nil {
			t.Errorf("expected error for slot=%d; got nil", slot)
			continue
		}
		if !strings.Contains(err.Error(), "slot") {
			t.Errorf("slot=%d err = %v; want slot validation error", slot, err)
		}
	}
}

func TestCryptoStoreKey_RejectsBadKeyType(t *testing.T) {
	f := &Flipper{}
	for _, kt := range []string{"aes256", "AES", "Master", "", "simple "} {
		_, err := f.CryptoStoreKey(1, kt, 128, strings.Repeat("AB", 16))
		if err == nil {
			t.Errorf("expected error for keyType=%q; got nil", kt)
			continue
		}
		if !strings.Contains(err.Error(), "key type") {
			t.Errorf("keyType=%q err = %v; want key type validation error", kt, err)
		}
	}
}

func TestCryptoStoreKey_RejectsBadKeySize(t *testing.T) {
	f := &Flipper{}
	for _, ks := range []int{0, 64, 192, 512, 1024} {
		hex32 := strings.Repeat("AB", ks/8) // matched-length hex for bogus size
		if hex32 == "" {
			hex32 = "AB"
		}
		_, err := f.CryptoStoreKey(1, "simple", ks, hex32)
		if err == nil {
			t.Errorf("expected error for keySize=%d; got nil", ks)
			continue
		}
		if !strings.Contains(err.Error(), "size") {
			t.Errorf("keySize=%d err = %v; want key size validation error", ks, err)
		}
	}
}

func TestCryptoStoreKey_RejectsHexLengthMismatch(t *testing.T) {
	f := &Flipper{}
	cases := []struct {
		keySize int
		hex     string
	}{
		{128, "DEADBEEF"},                      // 8 chars, want 32
		{128, strings.Repeat("AB", 32)},        // 64 chars, want 32
		{256, strings.Repeat("AB", 16)},        // 32 chars, want 64
		{256, strings.Repeat("AB", 64) + "EX"}, // 130 chars, want 64
	}
	for _, c := range cases {
		_, err := f.CryptoStoreKey(1, "simple", c.keySize, c.hex)
		if err == nil {
			t.Errorf("expected error for keySize=%d hex=%q; got nil", c.keySize, c.hex)
			continue
		}
		if !strings.Contains(err.Error(), "hex length") && !strings.Contains(err.Error(), "size") {
			t.Errorf("keySize=%d hex=%q err = %v; want hex-length error", c.keySize, c.hex, err)
		}
	}
}

func TestCryptoStoreKey_RejectsNonHexChars(t *testing.T) {
	f := &Flipper{}
	// 32 chars but with non-hex characters.
	bad := strings.Repeat("XY", 16)
	_, err := f.CryptoStoreKey(1, "simple", 128, bad)
	if err == nil {
		t.Fatal("expected error for non-hex chars; got nil")
	}
	if !strings.Contains(err.Error(), "hex") {
		t.Errorf("err = %v; want hex parse error", err)
	}
}
