// SPDX-License-Identifier: AGPL-3.0-or-later

package adsb

import (
	"math"
	"testing"
)

// TestTC29_TargetState anchors the TC 29 subtype-1 decode to the pyModeS
// bds62 oracle: frame 8D000000EA3AA7DE00034C000000 → selected altitude
// 29984 ft (MCP/FCU), baro 1000 mb, selected heading 180 deg, with
// autopilot / altitude-hold / LNAV engaged, VNAV / approach off, TCAS
// operational.
func TestTC29_TargetState(t *testing.T) {
	f, err := Decode("8D000000EA3AA7DE00034C000000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if f.ADSB == nil || f.ADSB.TargetState == nil {
		t.Fatal("no TargetState decoded for TC 29")
	}
	ts := f.ADSB.TargetState
	if ts.Subtype != 1 {
		t.Fatalf("subtype = %d, want 1", ts.Subtype)
	}
	if ts.SelectedAltitudeFt == nil || *ts.SelectedAltitudeFt != 29984 || ts.SelectedAltitudeSource != "MCP/FCU" {
		t.Errorf("selected altitude = %v (%q), want 29984 (MCP/FCU)", ts.SelectedAltitudeFt, ts.SelectedAltitudeSource)
	}
	if ts.BaroPressureSettingMb == nil || math.Abs(*ts.BaroPressureSettingMb-1000.0) > 1e-9 {
		t.Errorf("baro = %v, want 1000", ts.BaroPressureSettingMb)
	}
	if ts.SelectedHeadingDeg == nil || math.Abs(*ts.SelectedHeadingDeg-180.0) > 1e-9 {
		t.Errorf("selected heading = %v, want 180", ts.SelectedHeadingDeg)
	}
	if !ts.ModeValid {
		t.Fatal("mode_valid should be true")
	}
	checkBool := func(name string, got *bool, want bool) {
		if got == nil || *got != want {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	checkBool("autopilot", ts.Autopilot, true)
	checkBool("vnav", ts.VNAV, false)
	checkBool("altitude_hold", ts.AltitudeHold, true)
	checkBool("approach", ts.Approach, false)
	checkBool("lnav", ts.LNAV, true)
	checkBool("tcas_operational", ts.TCASOperational, true)
}

// TestTC29_Subtype0Deferred verifies an ADS-B v1 (subtype 0) target-state
// message is identified but not field-decoded, with a note rather than a
// guessed value.
func TestTC29_Subtype0Deferred(t *testing.T) {
	// TC=29 (0b11101), subtype 0: first ME byte 0b11101_00_0 = 0xE8, rest 0.
	// Frame = 8D + ICAO(6) + ME(14: E8 followed by zeros) + PI(6).
	f, err := Decode("8D000000E8000000000000000000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	ts := f.ADSB.TargetState
	if ts == nil || ts.Subtype != 0 {
		t.Fatalf("TargetState subtype = %v, want 0", ts)
	}
	if ts.SelectedAltitudeFt != nil || ts.Note == "" {
		t.Errorf("subtype 0 must be deferred with a note, not decoded: %+v", ts)
	}
}
