// SPDX-License-Identifier: AGPL-3.0-or-later

package uds

import (
	"strings"
	"testing"
)

// Each bit decoded in isolation, asserting the exact flag per ISO 14229-1 Annex
// D.2. The decode is a direct mask of the published table, so these single-bit
// vectors are authoritative.
func TestDecodeDTCStatus_SingleBits(t *testing.T) {
	cases := []struct {
		hex  string
		flag string
	}{
		{"01", "testFailed"},
		{"02", "testFailedThisOperationCycle"},
		{"04", "pendingDTC"},
		{"08", "confirmedDTC"},
		{"10", "testNotCompletedSinceLastClear"},
		{"20", "testFailedSinceLastClear"},
		{"40", "testNotCompletedThisOperationCycle"},
		{"80", "warningIndicatorRequested"},
	}
	for _, c := range cases {
		t.Run(c.flag, func(t *testing.T) {
			s, err := DecodeDTCStatusHex(c.hex)
			if err != nil {
				t.Fatalf("DecodeDTCStatusHex(%q): %v", c.hex, err)
			}
			if len(s.SetFlags) != 1 || s.SetFlags[0] != c.flag {
				t.Errorf("%s: set_flags = %v, want [%q]", c.hex, s.SetFlags, c.flag)
			}
		})
	}
}

// Realistic combined values + the severity headline.
func TestDecodeDTCStatus_Summaries(t *testing.T) {
	cases := []struct {
		hex     string
		summary string
		nFlags  int
	}{
		{"00", "no status bits set", 0},
		{"09", "confirmed (stored) fault", 2},                            // testFailed + confirmedDTC
		{"04", "pending fault (not yet confirmed)", 1},                   // pendingDTC only
		{"01", "test currently failing (not pending/confirmed)", 1},      // testFailed only
		{"2F", "confirmed (stored) fault", 5},                            // 01+02+04+08+20 (confirmed wins)
		{"10", "test-status bits only (no failed/pending/confirmed)", 1}, // not-completed only
	}
	for _, c := range cases {
		s, err := DecodeDTCStatusHex(c.hex)
		if err != nil {
			t.Fatalf("DecodeDTCStatusHex(%q): %v", c.hex, err)
		}
		if s.Summary != c.summary {
			t.Errorf("%s: summary = %q, want %q", c.hex, s.Summary, c.summary)
		}
		if len(s.SetFlags) != c.nFlags {
			t.Errorf("%s: %d flags, want %d (%v)", c.hex, len(s.SetFlags), c.nFlags, s.SetFlags)
		}
	}
}

// The MIL/warning-indicator suffix is appended when bit 7 is set.
func TestDecodeDTCStatus_WarningIndicator(t *testing.T) {
	s, err := DecodeDTCStatusHex("88") // confirmedDTC + warningIndicatorRequested
	if err != nil {
		t.Fatal(err)
	}
	if !s.ConfirmedDTC || !s.WarningIndicatorRequested {
		t.Fatalf("0x88: expected confirmed + warning, got %+v", s)
	}
	if !strings.Contains(s.Summary, "warning indicator (MIL) requested") {
		t.Errorf("0x88: summary = %q, want the MIL suffix", s.Summary)
	}
}

func TestDecodeDTCStatus_Rejects(t *testing.T) {
	for _, bad := range []string{"", "0809", "zz"} {
		if _, err := DecodeDTCStatusHex(bad); err == nil {
			t.Errorf("DecodeDTCStatusHex(%q): expected error, got nil", bad)
		}
	}
}
