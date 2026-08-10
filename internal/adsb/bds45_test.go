// SPDX-License-Identifier: AGPL-3.0-or-later

package adsb

import (
	"math"
	"testing"
)

// TestDecodeBDS45_GoldenVector anchors the decode to the pyModeS reference
// MB field 0001FB80000000: static air temperature -4.5 C, every hazard and
// the pressure/radio-height fields absent.
func TestDecodeBDS45_GoldenVector(t *testing.T) {
	b := DecodeBDS45(mustHex(t, "0001FB80000000"))
	if !b.IsBDS45 {
		t.Error("golden vector should pass is45")
	}
	if b.StaticAirTemperatureC == nil || math.Abs(*b.StaticAirTemperatureC-(-4.5)) > 1e-9 {
		t.Errorf("SAT = %v, want -4.5", b.StaticAirTemperatureC)
	}
	if b.Turbulence != nil || b.WindShear != nil || b.Microburst != nil ||
		b.Icing != nil || b.WakeVortex != nil || b.StaticPressureHpa != nil || b.RadioHeightFt != nil {
		t.Errorf("expected only temperature; got %+v", b)
	}
}

// TestDecodeBDS45_MultiHazard anchors the five hazard branches + pressure +
// radio height to the pyModeS reference MB field D7EA002FD63E80. Crucially,
// temperature must be ABSENT here (its status bit is clear) — the v3 fix
// over v2, which reported it unconditionally.
func TestDecodeBDS45_MultiHazard(t *testing.T) {
	b := DecodeBDS45(mustHex(t, "D7EA002FD63E80"))
	if !b.IsBDS45 {
		t.Error("multi-hazard vector should pass is45")
	}
	want := []struct {
		name string
		got  *int
		val  int
		lbl  string
	}{
		{"turbulence", b.Turbulence, 2, "Moderate"},
		{"wind_shear", b.WindShear, 1, "Light"},
		{"microburst", b.Microburst, 3, "Severe"},
		{"icing", b.Icing, 2, "Moderate"},
		{"wake_vortex", b.WakeVortex, 1, "Light"},
	}
	labels := map[string]string{
		"turbulence": b.TurbulenceName, "wind_shear": b.WindShearName,
		"microburst": b.MicroburstName, "icing": b.IcingName, "wake_vortex": b.WakeVortexName,
	}
	for _, w := range want {
		if w.got == nil || *w.got != w.val || labels[w.name] != w.lbl {
			t.Errorf("%s = %v (%q), want %d (%q)", w.name, w.got, labels[w.name], w.val, w.lbl)
		}
	}
	if b.StaticPressureHpa == nil || *b.StaticPressureHpa != 1013 {
		t.Errorf("pressure = %v, want 1013", b.StaticPressureHpa)
	}
	if b.RadioHeightFt == nil || *b.RadioHeightFt != 8000 {
		t.Errorf("radio height = %v, want 8000", b.RadioHeightFt)
	}
	if b.StaticAirTemperatureC != nil {
		t.Errorf("temperature must be absent (status bit clear); got %v", *b.StaticAirTemperatureC)
	}
}

// TestIs45_RejectsBDS17LookAlike verifies the v3 disambiguation: a BDS 1,7
// (GICB capability) look-alike must report IsBDS45 false so it is not
// mistaken for a hazard report.
func TestIs45_RejectsBDS17LookAlike(t *testing.T) {
	b := DecodeBDS45(mustHex(t, "FF81C300000000"))
	if b.IsBDS45 {
		t.Error("a BDS 1,7 look-alike must not pass is45")
	}
	// All-zero is rejected too.
	if DecodeBDS45(mustHex(t, "00000000000000")).IsBDS45 {
		t.Error("all-zero MB must not pass is45")
	}
	// A non-zero reserved tail (lowest 5 bits) must fail.
	if DecodeBDS45(mustHex(t, "0001FB80000001")).IsBDS45 {
		t.Error("non-zero reserved tail must not pass is45")
	}
}
