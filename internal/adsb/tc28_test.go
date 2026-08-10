// SPDX-License-Identifier: AGPL-3.0-or-later

package adsb

import "testing"

// TestTC28_EmergencyStatus anchors the TC 28 subtype-1 decode to the
// pyModeS reference (emergency_state + emergency_squawk): frame
// 8D000000E1355500000000000000 → General emergency, squawk 0077.
func TestTC28_EmergencyStatus(t *testing.T) {
	f, err := Decode("8D000000E1355500000000000000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if f.ADSB == nil || f.ADSB.AircraftStatus == nil {
		t.Fatal("no AircraftStatus decoded for TC 28")
	}
	as := f.ADSB.AircraftStatus
	if as.Subtype != 1 {
		t.Errorf("subtype = %d, want 1", as.Subtype)
	}
	if as.EmergencyState == nil || *as.EmergencyState != 1 || as.EmergencyStateName != "General emergency" {
		t.Errorf("emergency = %v (%q), want 1 (General emergency)", as.EmergencyState, as.EmergencyStateName)
	}
	if as.Squawk != "0077" {
		t.Errorf("squawk = %q, want 0077", as.Squawk)
	}
	if as.ACASResolutionAdvisory != nil {
		t.Error("subtype 1 must not carry an ACAS RA")
	}
}

// TestTC28_ACASRABroadcast verifies the subtype-2 path reuses the ACAS RA
// decoder: an ME whose bit-8-onward payload matches the BDS 3,0 vector
// (issued/corrective/downward RA, threat ICAO A1B2C3) must decode the same
// RA fields — and must NOT carry an is_bds30 flag (TC/subtype identify it).
func TestTC28_ACASRABroadcast(t *testing.T) {
	f, err := Decode("8D000000E2E0000686CB0C000000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	as := f.ADSB.AircraftStatus
	if as == nil || as.Subtype != 2 {
		t.Fatalf("subtype = %v, want 2", as)
	}
	ra := as.ACASResolutionAdvisory
	if ra == nil {
		t.Fatal("subtype 2 should carry an ACAS RA")
	}
	if !ra.ResolutionAdvisory.Issued || !ra.ResolutionAdvisory.Corrective || !ra.ResolutionAdvisory.DownwardSense {
		t.Errorf("ARA = %+v, want issued+corrective+downward", ra.ResolutionAdvisory)
	}
	if ra.ThreatTypeIndicator != 1 || ra.ThreatICAO != "A1B2C3" {
		t.Errorf("threat = TTI %d / %q, want 1 / A1B2C3", ra.ThreatTypeIndicator, ra.ThreatICAO)
	}
	if as.EmergencyState != nil {
		t.Error("subtype 2 must not carry an emergency state")
	}
}
