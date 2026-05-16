package flipper

import (
	"context"
	"strings"
	"testing"
	"time"
)

// SubGHzChatDeviceCtx validates frequency the same way SubGHzTxKey
// has since v0.181. Pre-fix, the chat wrapper forwarded the freq
// straight to the firmware, which rejected out-of-band requests
// with an opaque "Frequency not allowed!" banner after a slow
// round-trip.
func TestSubGHzChatDeviceCtx_RejectsOutOfBandFrequency(t *testing.T) {
	f := &Flipper{}
	cases := []uint32{0, 100_000_000, 200_000_000, 500_000_000, 1_000_000_000}
	for _, freq := range cases {
		_, err := f.SubGHzChatDeviceCtx(context.Background(), freq, time.Second, 0)
		if err == nil {
			t.Errorf("expected error for freq=%d; got nil", freq)
			continue
		}
		if !strings.Contains(err.Error(), "frequency") {
			t.Errorf("freq=%d err = %v; want frequency validation error", freq, err)
		}
	}
}

// Crypto slot tests: slot must parse as decimal int in 1-100.

func TestValidateCryptoSlotString_AcceptsValid(t *testing.T) {
	for _, s := range []string{"1", "10", "99", "100", "  5  "} {
		if err := validateCryptoSlotString(s); err != nil {
			t.Errorf("validateCryptoSlotString(%q) = %v; want nil", s, err)
		}
	}
}

func TestValidateCryptoSlotString_Rejects(t *testing.T) {
	cases := []string{
		"",       // empty
		"   ",    // whitespace-only
		"0",      // reserved
		"-1",     // negative
		"101",    // out of range
		"1000",   // way out
		"mySlot", // non-numeric
		"slot0",  // non-numeric
		"1.5",    // float
		"1 2",    // not a single number
		"0x10",   // hex notation (firmware wants decimal)
	}
	for _, s := range cases {
		if err := validateCryptoSlotString(s); err == nil {
			t.Errorf("validateCryptoSlotString(%q) = nil; want error", s)
		}
	}
}

func TestCryptoEncrypt_RejectsBadSlot(t *testing.T) {
	f := &Flipper{}
	for _, slot := range []string{"", "mySlot", "0", "101"} {
		_, err := f.CryptoEncrypt(slot, "DEADBEEF")
		if err == nil {
			t.Errorf("expected error for slot=%q; got nil", slot)
			continue
		}
		if !strings.Contains(err.Error(), "slot") {
			t.Errorf("slot=%q err = %v; want slot validation error", slot, err)
		}
	}
}

func TestCryptoDecrypt_RejectsBadSlot(t *testing.T) {
	f := &Flipper{}
	_, err := f.CryptoDecrypt("mySlot", "DEADBEEF")
	if err == nil {
		t.Fatal("expected error for non-numeric slot; got nil")
	}
	if !strings.Contains(err.Error(), "slot") {
		t.Errorf("err = %v; want slot validation error", err)
	}
}

func TestCryptoHasKey_RejectsBadSlot(t *testing.T) {
	f := &Flipper{}
	_, err := f.CryptoHasKey("")
	if err == nil {
		t.Fatal("expected error for empty slot; got nil")
	}
	if !strings.Contains(err.Error(), "slot") {
		t.Errorf("err = %v; want slot validation error", err)
	}
}
