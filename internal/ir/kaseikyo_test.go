// SPDX-License-Identifier: AGPL-3.0-or-later

package ir

import (
	"strings"
	"testing"
)

// kaseikyoOK is a hand-constructed Kaseikyo frame (independently generated from
// the IRremote spec layout, separate from this package's code): vendor 0x2002
// (Panasonic), address 0x123, command 0x45 — frame bytes 022030124567, both
// parities valid.
const kaseikyoOK = "3456 1728 432 432 432 1296 432 432 432 432 432 432 432 432 432 432 432 432 432 432 432 432 432 432 432 432 432 432 432 1296 432 432 432 432 432 432 432 432 432 432 432 432 432 1296 432 1296 432 432 432 432 432 432 432 1296 432 432 432 432 432 1296 432 432 432 432 432 432 432 1296 432 432 432 1296 432 432 432 432 432 432 432 1296 432 432 432 1296 432 1296 432 1296 432 432 432 432 432 1296 432 1296 432 432"

// kaseikyoBadParity is the same frame with the frame-parity byte zeroed
// (022030124500) — header + 48-bit structure intact but the integrity gate fails.
const kaseikyoBadParity = "3456 1728 432 432 432 1296 432 432 432 432 432 432 432 432 432 432 432 432 432 432 432 432 432 432 432 432 432 432 432 1296 432 432 432 432 432 432 432 432 432 432 432 432 432 1296 432 1296 432 432 432 432 432 432 432 1296 432 432 432 432 432 1296 432 432 432 432 432 432 432 1296 432 432 432 1296 432 432 432 432 432 432 432 1296 432 432 432 432 432 432 432 432 432 432 432 432 432 432 432 432 432 432"

func TestDecodeKaseikyoPanasonic(t *testing.T) {
	r, err := DecodeRaw(kaseikyoOK)
	if err != nil {
		t.Fatalf("DecodeRaw: %v", err)
	}
	if r.Protocol != "Kaseikyo" {
		t.Fatalf("Protocol = %q, want Kaseikyo", r.Protocol)
	}
	if r.Vendor != 0x2002 || r.VendorName != "Panasonic / Matsushita" {
		t.Errorf("vendor = 0x%04X %q", r.Vendor, r.VendorName)
	}
	if r.Address != 0x123 || r.Command != 0x45 {
		t.Errorf("address=0x%X command=0x%X, want 0x123/0x45", r.Address, r.Command)
	}
	if !r.ChecksumValid || r.Bits != 48 {
		t.Errorf("checksumValid=%v bits=%d", r.ChecksumValid, r.Bits)
	}
	if r.RawBytesHex != "022030124567" {
		t.Errorf("raw = %q, want 022030124567", r.RawBytesHex)
	}
}

func TestKaseikyoVendorParityFormula(t *testing.T) {
	if got := kaseikyoVendorParity(0x2002); got != 0x0 {
		t.Errorf("vendorParity(0x2002)=%d, want 0", got)
	}
}

func TestKaseikyoParityFailReported(t *testing.T) {
	r, err := DecodeRaw(kaseikyoBadParity)
	if err != nil {
		t.Fatalf("DecodeRaw: %v", err)
	}
	if r.ChecksumValid {
		t.Errorf("expected parity failure")
	}
	if !strings.HasPrefix(r.Protocol, "Kaseikyo-like") {
		t.Errorf("Protocol = %q, want Kaseikyo-like (parity failed)", r.Protocol)
	}
}

func TestKaseikyoDoesNotBreakSamsung(t *testing.T) {
	// A Samsung-style header (4500/4500) must not be mis-routed to Kaseikyo.
	samsung := "4500 4500 " + strings.TrimSpace(strings.Repeat("560 560 ", 32))
	r, err := DecodeRaw(samsung)
	if err == nil && strings.HasPrefix(r.Protocol, "Kaseikyo") {
		t.Errorf("Samsung header mis-routed to Kaseikyo: %q", r.Protocol)
	}
}
