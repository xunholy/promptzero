// SPDX-License-Identifier: AGPL-3.0-or-later

package adsb

import (
	"math"
	"testing"
)

// The Comm-B BDS register vectors below are the official pyModeS reference
// test messages (tests/test_commb.py at tag v2.18) — real DF20 Comm-B
// replies with independently-published expected field values. Each frame
// validates under exactly one BDS gate (verified against pyModeS infer()).

func mustCommB(t *testing.T, hexFrame string) *CommB {
	t.Helper()
	f, err := Decode(hexFrame)
	if err != nil {
		t.Fatalf("Decode(%s): %v", hexFrame, err)
	}
	if f.CommB == nil {
		t.Fatalf("Decode(%s): no Comm-B", hexFrame)
	}
	return f.CommB
}

func onlyRegister(t *testing.T, cb *CommB, want string) {
	t.Helper()
	if len(cb.InferredRegisters) != 1 || cb.InferredRegisters[0] != want {
		t.Fatalf("inferred = %v, want [%s]", cb.InferredRegisters, want)
	}
}

func approx(t *testing.T, got *float64, want float64, field string) {
	t.Helper()
	if got == nil {
		t.Errorf("%s = nil, want %v", field, want)
		return
	}
	if math.Abs(*got-want) > 1e-9 {
		t.Errorf("%s = %v, want %v", field, *got, want)
	}
}

func eqInt(t *testing.T, got *int, want int, field string) {
	t.Helper()
	if got == nil {
		t.Errorf("%s = nil, want %d", field, want)
		return
	}
	if *got != want {
		t.Errorf("%s = %d, want %d", field, *got, want)
	}
}

func TestCommBBDS20Identification(t *testing.T) {
	for _, c := range []struct{ frame, cs string }{
		{"A000083E202CC371C31DE0AA1CCF", "KLM1017_"},
		{"A0001993202422F2E37CE038738E", "IBK2873_"},
	} {
		cb := mustCommB(t, c.frame)
		onlyRegister(t, cb, "BDS20")
		if cb.BDS20 == nil || cb.BDS20.Callsign != c.cs {
			t.Errorf("%s callsign = %v, want %s", c.frame, cb.BDS20, c.cs)
		}
	}
}

func TestCommBBDS40VerticalIntention(t *testing.T) {
	cb := mustCommB(t, "A000029C85E42F313000007047D3")
	onlyRegister(t, cb, "BDS40")
	eqInt(t, cb.BDS40.MCPSelectedAltitudeFt, 3008, "mcp")
	eqInt(t, cb.BDS40.FMSSelectedAltitudeFt, 3008, "fms")
	approx(t, cb.BDS40.BarometricPressureMB, 1020.0, "baro")
}

func TestCommBBDS50TrackTurn(t *testing.T) {
	cb := mustCommB(t, "A000139381951536E024D4CCF6B5")
	onlyRegister(t, cb, "BDS50")
	approx(t, cb.BDS50.RollAngleDeg, 2.109375, "roll")
	approx(t, cb.BDS50.TrueTrackDeg, 114.2578125, "trk")
	eqInt(t, cb.BDS50.GroundSpeedKts, 438, "gs")
	approx(t, cb.BDS50.TrackAngleRate, 0.125, "rtrk")
	eqInt(t, cb.BDS50.TrueAirspeedKts, 424, "tas")

	// Second vector exercises signed roll/track-rate.
	cb2 := mustCommB(t, "A0001691FFD263377FFCE02B2BF9")
	onlyRegister(t, cb2, "BDS50")
	approx(t, cb2.BDS50.RollAngleDeg, -0.3515625, "roll")
	approx(t, cb2.BDS50.TrueTrackDeg, 53.61328125, "trk")
	eqInt(t, cb2.BDS50.GroundSpeedKts, 442, "gs")
	// This vector's track-angle-rate field is the all-ones "no valid data"
	// sentinel (d[36:45] == 111111111), so it decodes to nil per the
	// pyModeS v2.18 guard rather than a spurious -0.03125.
	if cb2.BDS50.TrackAngleRate != nil {
		t.Errorf("rtrk = %v, want nil (all-ones sentinel)", *cb2.BDS50.TrackAngleRate)
	}
	eqInt(t, cb2.BDS50.TrueAirspeedKts, 448, "tas")
}

func TestCommBBDS60HeadingSpeed(t *testing.T) {
	cb := mustCommB(t, "A00004128F39F91A7E27C46ADC21")
	onlyRegister(t, cb, "BDS60")
	approx(t, cb.BDS60.MagneticHeadingDeg, 42.71484375, "hdg")
	eqInt(t, cb.BDS60.IndicatedAirspeed, 252, "ias")
	approx(t, cb.BDS60.Mach, 0.42, "mach")
	eqInt(t, cb.BDS60.VerticalRateBaroFPM, -1920, "vr_baro")
	eqInt(t, cb.BDS60.VerticalRateInsFPM, -1920, "vr_ins")
}

// TestCommBDF21 confirms DF21 (identity reply) also gets a Comm-B decode.
func TestCommBDF21(t *testing.T) {
	// Reuse the BDS40 MB field under a DF21 header (A8.. = DF21).
	f, err := Decode("A800029C85E42F313000007047D3")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if f.DF != 21 || f.CommB == nil {
		t.Fatalf("DF=%d CommB=%v, want DF21 with Comm-B", f.DF, f.CommB)
	}
	onlyRegister(t, f.CommB, "BDS40")
}

// TestCommBAllZero handles an empty MB field.
func TestCommBAllZero(t *testing.T) {
	f, err := Decode("A000000000000000000000000000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if f.CommB == nil || len(f.CommB.InferredRegisters) != 0 {
		t.Errorf("all-zero MB: inferred = %v, want empty", f.CommB.InferredRegisters)
	}
}

// TestCommBOnlyForDF2021 confirms DF17 frames don't get a Comm-B decode.
func TestCommBOnlyForDF2021(t *testing.T) {
	f, err := Decode("8D406B902015A678D4D220AA4BDA")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if f.CommB != nil {
		t.Errorf("DF17 should have no Comm-B, got %+v", f.CommB)
	}
}
