// SPDX-License-Identifier: AGPL-3.0-or-later

package adsb

import "testing"

// TestDecodeBDS30_ThreatICAO anchors the TTI=1 (ICAO threat) path to the
// pyModeS v3 reference MB field 30E0000686CB0C: a corrective downward RA
// against threat aircraft A1B2C3.
func TestDecodeBDS30_ThreatICAO(t *testing.T) {
	b := DecodeBDS30(mustHex(t, "30E0000686CB0C"))
	if !b.IsBDS30 {
		t.Error("golden vector should pass is30")
	}
	ra := b.ResolutionAdvisory
	if !ra.Issued || !ra.Corrective || !ra.DownwardSense {
		t.Errorf("ARA = %+v, want issued+corrective+downward_sense", ra)
	}
	if ra.IncreasedRate || ra.SenseReversal || ra.Positive {
		t.Errorf("ARA has unexpected flags set: %+v", ra)
	}
	if b.ThreatTypeIndicator != 1 || b.ThreatICAO != "A1B2C3" {
		t.Errorf("threat = TTI %d / %q, want 1 / A1B2C3", b.ThreatTypeIndicator, b.ThreatICAO)
	}
}

// TestDecodeBDS30_ThreatAltRangeBearing anchors the TTI=2 path to the
// pyModeS v3 reference MB field 309800C9532CDF: an increased-rate sense-
// reversal RA with no-left/no-right complements, threat at 16025 ft, 5.0 NM,
// bearing 183 deg. The altitude reuses the package AC13 decoder.
func TestDecodeBDS30_ThreatAltRangeBearing(t *testing.T) {
	b := DecodeBDS30(mustHex(t, "309800C9532CDF"))
	if !b.IsBDS30 {
		t.Error("golden vector should pass is30")
	}
	ra := b.ResolutionAdvisory
	if !ra.Issued || !ra.IncreasedRate || !ra.SenseReversal {
		t.Errorf("ARA = %+v, want issued+increased_rate+sense_reversal", ra)
	}
	rac := b.ResolutionAdvisoryComplement
	if !rac.NoLeft || !rac.NoRight || rac.NoBelow || rac.NoAbove {
		t.Errorf("RAC = %+v, want no_left+no_right only", rac)
	}
	if b.ThreatTypeIndicator != 2 {
		t.Fatalf("TTI = %d, want 2", b.ThreatTypeIndicator)
	}
	if b.ThreatAltitudeFt == nil || *b.ThreatAltitudeFt != 16025 {
		t.Errorf("threat altitude = %v, want 16025", b.ThreatAltitudeFt)
	}
	if b.ThreatRangeNM == nil || *b.ThreatRangeNM != 5.0 {
		t.Errorf("threat range = %v, want 5.0", b.ThreatRangeNM)
	}
	if b.ThreatBearingDeg == nil || *b.ThreatBearingDeg != 183 {
		t.Errorf("threat bearing = %v, want 183", b.ThreatBearingDeg)
	}
}

// TestIs30_Rejections mirrors pyModeS is_bds30 negatives: all-zero, a wrong
// BDS identifier (first byte not 0x30), and the reserved threat type 3.
func TestIs30_Rejections(t *testing.T) {
	if DecodeBDS30(mustHex(t, "00000000000000")).IsBDS30 {
		t.Error("all-zero MB must not pass is30")
	}
	// First byte 0x31 (not 0x30) — wrong BDS identifier.
	if DecodeBDS30(mustHex(t, "31E0000686CB0C")).IsBDS30 {
		t.Error("non-0x30 identifier must not pass is30")
	}
	// Threat type 3 (reserved): bits 28-29 = 11 (golden byte3 0x06 -> 0x0E).
	// Oracle-confirmed is_bds30 false.
	if DecodeBDS30(mustHex(t, "30E0000E86CB0C")).IsBDS30 {
		t.Error("reserved threat type 3 must not pass is30")
	}
}
