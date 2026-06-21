// SPDX-License-Identifier: AGPL-3.0-or-later

package uds

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// DTCStatus is a decoded UDS DTC status byte — the 8-bit DTCStatusMask that
// service 0x19 (ReadDTCInformation) returns alongside every DTC. The eight bits
// are defined in ISO 14229-1 Annex D.2 (statusOfDTC); together they say whether
// a fault is currently failing, pending, confirmed/stored, and whether the MIL
// (warning indicator) is requested.
type DTCStatus struct {
	Raw string `json:"raw"` // 0xNN

	TestFailed                         bool `json:"test_failed"`                             // bit 0 (0x01)
	TestFailedThisOperationCycle       bool `json:"test_failed_this_operation_cycle"`        // bit 1 (0x02)
	PendingDTC                         bool `json:"pending_dtc"`                             // bit 2 (0x04)
	ConfirmedDTC                       bool `json:"confirmed_dtc"`                           // bit 3 (0x08)
	TestNotCompletedSinceLastClear     bool `json:"test_not_completed_since_last_clear"`     // bit 4 (0x10)
	TestFailedSinceLastClear           bool `json:"test_failed_since_last_clear"`            // bit 5 (0x20)
	TestNotCompletedThisOperationCycle bool `json:"test_not_completed_this_operation_cycle"` // bit 6 (0x40)
	WarningIndicatorRequested          bool `json:"warning_indicator_requested"`             // bit 7 (0x80)

	// SetFlags lists the names of the set bits, low to high — a one-glance read.
	SetFlags []string `json:"set_flags"`

	// Summary is the single most operator-relevant takeaway: is the fault
	// confirmed (stored), pending, currently failing, or clean.
	Summary string `json:"summary"`
}

// dtcStatusBit pairs a mask with its ISO 14229-1 name, low bit to high.
var dtcStatusBits = []struct {
	mask byte
	name string
}{
	{0x01, "testFailed"},
	{0x02, "testFailedThisOperationCycle"},
	{0x04, "pendingDTC"},
	{0x08, "confirmedDTC"},
	{0x10, "testNotCompletedSinceLastClear"},
	{0x20, "testFailedSinceLastClear"},
	{0x40, "testNotCompletedThisOperationCycle"},
	{0x80, "warningIndicatorRequested"},
}

// DecodeDTCStatus decodes a single UDS DTC status byte per ISO 14229-1 Annex
// D.2. Every value 0x00..0xFF is structurally valid (all eight bits are
// defined), so there is no failure mode beyond a wrong byte count at the tool
// layer.
func DecodeDTCStatus(b byte) *DTCStatus {
	s := &DTCStatus{
		Raw:                                fmt.Sprintf("0x%02X", b),
		TestFailed:                         b&0x01 != 0,
		TestFailedThisOperationCycle:       b&0x02 != 0,
		PendingDTC:                         b&0x04 != 0,
		ConfirmedDTC:                       b&0x08 != 0,
		TestNotCompletedSinceLastClear:     b&0x10 != 0,
		TestFailedSinceLastClear:           b&0x20 != 0,
		TestNotCompletedThisOperationCycle: b&0x40 != 0,
		WarningIndicatorRequested:          b&0x80 != 0,
		SetFlags:                           []string{},
	}
	for _, bit := range dtcStatusBits {
		if b&bit.mask != 0 {
			s.SetFlags = append(s.SetFlags, bit.name)
		}
	}

	// Headline by severity: a confirmed (stored) DTC is the strongest state,
	// then pending, then currently-failing; 0x00 means no bits set.
	switch {
	case s.ConfirmedDTC:
		s.Summary = "confirmed (stored) fault"
	case s.PendingDTC:
		s.Summary = "pending fault (not yet confirmed)"
	case s.TestFailed:
		s.Summary = "test currently failing (not pending/confirmed)"
	case b == 0x00:
		s.Summary = "no status bits set"
	default:
		s.Summary = "test-status bits only (no failed/pending/confirmed)"
	}
	if s.WarningIndicatorRequested {
		s.Summary += "; warning indicator (MIL) requested"
	}
	return s
}

// DecodeDTCStatusHex decodes a single status byte supplied as hex (':' / '-' /
// '_' / whitespace and a '0x' prefix tolerated).
func DecodeDTCStatusHex(s string) (*DTCStatus, error) {
	clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "", "\n", "", "\t", "").Replace(s)
	clean = strings.TrimPrefix(strings.TrimPrefix(clean, "0x"), "0X")
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("uds: invalid hex: %w", err)
	}
	if len(b) != 1 {
		return nil, fmt.Errorf("uds: DTC status mask must be exactly 1 byte, got %d", len(b))
	}
	return DecodeDTCStatus(b[0]), nil
}
