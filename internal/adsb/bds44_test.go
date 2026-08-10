// SPDX-License-Identifier: AGPL-3.0-or-later

package adsb

import (
	"encoding/hex"
	"math"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestDecodeBDS44_GoldenVector anchors the decode to the pyModeS reference
// MB field 185BD5CF400000: figure of merit 1, wind 22 kt at 344.53125 deg,
// static air temperature -48.75 C, no pressure/turbulence/humidity.
func TestDecodeBDS44_GoldenVector(t *testing.T) {
	b := DecodeBDS44(mustHex(t, "185BD5CF400000"))
	if !b.IsBDS44 {
		t.Error("golden vector should pass is44")
	}
	if b.FigureOfMerit != 1 {
		t.Errorf("FOM = %d, want 1", b.FigureOfMerit)
	}
	if b.WindSpeedKt == nil || *b.WindSpeedKt != 22 {
		t.Errorf("wind speed = %v, want 22", b.WindSpeedKt)
	}
	if b.WindDirectionDeg == nil || math.Abs(*b.WindDirectionDeg-344.53125) > 1e-5 {
		t.Errorf("wind direction = %v, want 344.53125", b.WindDirectionDeg)
	}
	if math.Abs(b.StaticAirTemperatureC-(-48.75)) > 1e-9 {
		t.Errorf("SAT = %v, want -48.75", b.StaticAirTemperatureC)
	}
	if b.StaticPressureHpa != nil || b.Turbulence != nil || b.HumidityPct != nil {
		t.Errorf("expected no pressure/turbulence/humidity; got %v/%v/%v", b.StaticPressureHpa, b.Turbulence, b.HumidityPct)
	}
}

// TestDecodeBDS44_MultiField anchors the pressure/turbulence/humidity
// branches to the pyModeS reference MB field 18CA00002FD760: wind 50 kt at
// 180 deg, temp 0 C, pressure 1013 hPa, turbulence 2 (Moderate),
// humidity 50%.
func TestDecodeBDS44_MultiField(t *testing.T) {
	b := DecodeBDS44(mustHex(t, "18CA00002FD760"))
	if !b.IsBDS44 {
		t.Error("multi-field vector should pass is44")
	}
	if b.WindSpeedKt == nil || *b.WindSpeedKt != 50 {
		t.Errorf("wind speed = %v, want 50", b.WindSpeedKt)
	}
	if b.WindDirectionDeg == nil || math.Abs(*b.WindDirectionDeg-180.0) > 1e-9 {
		t.Errorf("wind direction = %v, want 180", b.WindDirectionDeg)
	}
	if b.StaticPressureHpa == nil || *b.StaticPressureHpa != 1013 {
		t.Errorf("pressure = %v, want 1013", b.StaticPressureHpa)
	}
	if b.Turbulence == nil || *b.Turbulence != 2 || b.TurbulenceName != "Moderate" {
		t.Errorf("turbulence = %v (%q), want 2 (Moderate)", b.Turbulence, b.TurbulenceName)
	}
	if b.HumidityPct == nil || math.Abs(*b.HumidityPct-50.0) > 1e-9 {
		t.Errorf("humidity = %v, want 50.0", b.HumidityPct)
	}
}

// TestIs44_Rejections mirrors pyModeS's is44 negative cases: all-zero,
// figure-of-merit above 4, and a status-bit/field contradiction must all
// report IsBDS44 false so a look-alike frame is flagged, not asserted.
func TestIs44_Rejections(t *testing.T) {
	// All zeros.
	if DecodeBDS44(mustHex(t, "00000000000000")).IsBDS44 {
		t.Error("all-zero MB must not pass is44")
	}
	// Golden vector with FOM forced to 5 (bits 1-4 = 0101) must fail.
	// 0x18 -> first byte; FOM is the top nibble. Set it to 0x5X.
	fomBad := mustHex(t, "585BD5CF400000")
	if DecodeBDS44(fomBad).IsBDS44 {
		t.Error("figure of merit > 4 must not pass is44")
	}
	// Pressure status clear (bit 35 = 0) but pressure bits non-zero is a
	// contradiction: take the golden vector (pressure status 0) and set a
	// pressure bit. Byte 5 bit... set the last bytes so bits 36-46 nonzero.
	contradiction := mustHex(t, "185BD5CF410000")
	if DecodeBDS44(contradiction).IsBDS44 {
		t.Error("clear pressure status with non-zero pressure field must not pass is44")
	}
}
