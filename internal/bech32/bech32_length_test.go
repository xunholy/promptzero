// SPDX-License-Identifier: AGPL-3.0-or-later

package bech32_test

import (
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/bech32"
)

// TestLongLightningInvoiceDecodes anchors the fix against a real BOLT-11
// vector (the canonical amountless donation invoice from the Lightning
// BOLT-11 spec, 243 chars). Before the fix the blanket 90-char ceiling
// rejected it outright with "length out of range", making the lnbc
// branch of interpret() unreachable dead code.
func TestLongLightningInvoiceDecodes(t *testing.T) {
	const inv = "lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rkx3yf5tcsyz3d73gafnh3cax9rn449d9p5uxz9ezhhypd0elx87sjle52x86fux2ypatgddc6k63n7erqz25le42c4u4ecky03ylcqca784w"
	if len(inv) <= 90 {
		t.Fatalf("test vector is only %d chars — it must exceed 90 to exercise the fix", len(inv))
	}
	r, err := bech32.Decode(inv)
	if err != nil {
		t.Fatalf("Decode(real BOLT-11 invoice): %v", err)
	}
	if !r.ChecksumValid || r.Variant != "bech32" {
		t.Errorf("variant=%q valid=%v; want bech32 valid", r.Variant, r.ChecksumValid)
	}
	if r.HRP != "lnbc" {
		t.Errorf("HRP=%q; want lnbc", r.HRP)
	}
	if r.Type != "Lightning invoice" {
		t.Errorf("Type=%q; want %q", r.Type, "Lightning invoice")
	}
}

// TestLongNonSegwitRoundTrip proves a valid-checksum bech32 string well
// over 90 chars decodes cleanly when its HRP is not a SegWit network —
// the general case (Lightning, Nostr TLV, Cosmos) the 90-char cap must
// no longer block. Built with the test-side encoder so the checksum is
// unquestionably valid.
func TestLongNonSegwitRoundTrip(t *testing.T) {
	data := make([]int, 200) // all-zero 5-bit symbols → 'q…'
	s := encode("lnbc", data, false)
	if len(s) <= 90 {
		t.Fatalf("encoded string is %d chars — expected >90", len(s))
	}
	r, err := bech32.Decode(s)
	if err != nil {
		t.Fatalf("Decode(%d-char non-SegWit string): %v", len(s), err)
	}
	if !r.ChecksumValid || r.Variant != "bech32" {
		t.Errorf("variant=%q valid=%v; want bech32 valid", r.Variant, r.ChecksumValid)
	}
}

// TestSegwitLengthCapPreserved locks in that the BIP-173 90-char ceiling
// still rejects an over-long SegWit address (HRP bc) — the fix narrows
// the cap to SegWit HRPs, it must not remove it. A >90-char bc1 string
// is invalid per spec regardless of checksum.
func TestSegwitLengthCapPreserved(t *testing.T) {
	data := make([]int, 90) // 2 (hrp) + 1 (sep) + 90 + 6 (checksum) = 99 > 90
	s := encode("bc", data, false)
	if len(s) <= 90 {
		t.Fatalf("encoded string is %d chars — expected >90 to exercise the cap", len(s))
	}
	_, err := bech32.Decode(s)
	if err == nil {
		t.Fatalf("Decode(%d-char bc address) = nil error; want SegWit length rejection", len(s))
	}
	if !strings.Contains(err.Error(), "SegWit") {
		t.Errorf("error = %q; want it to name the SegWit length cap", err)
	}
}

// TestDoSGuardRejectsOversize confirms the generous hard ceiling still
// bounds allocation on pathological input, even for a non-SegWit HRP.
func TestDoSGuardRejectsOversize(t *testing.T) {
	s := "lnbc1" + strings.Repeat("q", 5000)
	if _, err := bech32.Decode(s); err == nil {
		t.Fatalf("Decode(%d-char string) = nil error; want DoS-guard rejection", len(s))
	}
}
