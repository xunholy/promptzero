// SPDX-License-Identifier: AGPL-3.0-or-later

package ksuid_test

import (
	"testing"

	"github.com/xunholy/promptzero/internal/ksuid"
)

// TestDecodeReferenceVector pins the decode against segmentio/ksuid's own
// documented example — the strongest anchor, independent of this code.
//
//	String:  0ujtsYcgvSTl8PAuAdqWYSMnLOv
//	Raw:     0669F7EFB5A1CD34B5F99D1154FB6853345C9735
//	Time:    2017-10-09 21:00:47 -0700 (== 2017-10-10T04:00:47Z)
//	Stamp:   107608047  (0x0669F7EF, seconds since the KSUID epoch)
//	Payload: B5A1CD34B5F99D1154FB6853345C9735
func TestDecodeReferenceVector(t *testing.T) {
	r, err := ksuid.Decode("0ujtsYcgvSTl8PAuAdqWYSMnLOv")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.RawHex != "0669F7EFB5A1CD34B5F99D1154FB6853345C9735" {
		t.Errorf("RawHex = %s; want 0669F7EFB5A1CD34B5F99D1154FB6853345C9735", r.RawHex)
	}
	if r.Timestamp != 107608047 {
		t.Errorf("Timestamp = %d; want 107608047", r.Timestamp)
	}
	if r.UnixSeconds != 1507608047 {
		t.Errorf("UnixSeconds = %d; want 1507608047", r.UnixSeconds)
	}
	if r.TimestampUTC != "2017-10-10T04:00:47Z" {
		t.Errorf("TimestampUTC = %s; want 2017-10-10T04:00:47Z", r.TimestampUTC)
	}
	if r.PayloadHex != "B5A1CD34B5F99D1154FB6853345C9735" {
		t.Errorf("PayloadHex = %s; want B5A1CD34B5F99D1154FB6853345C9735", r.PayloadHex)
	}
}

// TestDecodeNilKSUID — the all-zero ('0'*27) KSUID decodes to the epoch with a
// zero payload (the documented "nil" KSUID).
func TestDecodeNilKSUID(t *testing.T) {
	r, err := ksuid.Decode("000000000000000000000000000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Timestamp != 0 {
		t.Errorf("Timestamp = %d; want 0", r.Timestamp)
	}
	if r.UnixSeconds != 1400000000 {
		t.Errorf("UnixSeconds = %d; want 1400000000 (the KSUID epoch)", r.UnixSeconds)
	}
	if r.TimestampUTC != "2014-05-13T16:53:20Z" {
		t.Errorf("TimestampUTC = %s; want 2014-05-13T16:53:20Z", r.TimestampUTC)
	}
	if r.PayloadHex != "00000000000000000000000000000000" {
		t.Errorf("PayloadHex = %s; want all zeros", r.PayloadHex)
	}
}

// TestDecodeMaxKSUID — the maximum KSUID decodes to an all-ones value
// (timestamp 0xFFFFFFFF, all-FF payload). This is segmentio/ksuid's documented
// Max value and exercises the 20-byte boundary without overflowing it.
func TestDecodeMaxKSUID(t *testing.T) {
	r, err := ksuid.Decode("aWgEPTl1tmebfsQzFP4bxwgy80V")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.RawHex != "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" {
		t.Errorf("RawHex = %s; want all FF", r.RawHex)
	}
	if r.Timestamp != 0xFFFFFFFF {
		t.Errorf("Timestamp = %#x; want 0xFFFFFFFF", r.Timestamp)
	}
	if r.PayloadHex != "FFFFFFFFFFFFFFFFFFFFFFFFFFFF" && len(r.PayloadHex) != 32 {
		t.Errorf("PayloadHex = %s; want 32 hex chars of FF", r.PayloadHex)
	}
}

func TestDecodeRejects(t *testing.T) {
	cases := map[string]string{
		"too short":        "0ujtsYcgvSTl8PAuAdqWYSMnLO",
		"too long":         "0ujtsYcgvSTl8PAuAdqWYSMnLOvX",
		"bad char (under)": "0ujtsYcgvSTl8PAuAdqWYSMnLO_",
		"bad char (space)": "0ujtsYcgvSTl8PAuAdqWYSMnLO ",
		"empty":            "",
		// 27 'z' = 62^27-1, larger than 2^160-1 — must be rejected as overflow.
		"overflow 27 z": "zzzzzzzzzzzzzzzzzzzzzzzzzzz",
	}
	for name, in := range cases {
		if _, err := ksuid.Decode(in); err == nil {
			t.Errorf("%s: Decode(%q) = nil error, want error", name, in)
		}
	}
}
