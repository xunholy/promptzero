// SPDX-License-Identifier: AGPL-3.0-or-later

package adsb

import "testing"

// The altitude/squawk vectors are anchored to the pyModeS reference
// (py_common.altcode / idcode). The DF4/DF5 frames carry the 13-bit
// AC/ID field at bits 20-32 with the remaining bits zero (those bits are
// not part of the altitude/identity decode); the DF20 frames are the
// real Comm-B replies reused from commb_test.go, cross-checked with
// pyModeS altcode.

func TestSurveillanceSquawk(t *testing.T) {
	cases := []struct {
		frame, squawk, emergency string
	}{
		{"28000808000000", "1200", ""},
		{"28000AAA000000", "7700", "7700 — general emergency"},
		{"28000A8A000000", "7600", "7600 — radio failure (lost communications)"},
		{"28000AA2000000", "7500", "7500 — unlawful interference (hijack)"},
		{"280004BA000000", "4721", ""},
	}
	for _, c := range cases {
		f, err := Decode(c.frame)
		if err != nil {
			t.Fatalf("Decode(%s): %v", c.frame, err)
		}
		if f.DF != 5 {
			t.Fatalf("%s: df = %d, want 5", c.frame, f.DF)
		}
		if f.Surveillance == nil || f.Surveillance.Squawk != c.squawk {
			t.Errorf("%s: squawk = %v, want %s", c.frame, f.Surveillance, c.squawk)
		}
		if f.Surveillance.SquawkEmergency != c.emergency {
			t.Errorf("%s: emergency = %q, want %q", c.frame, f.Surveillance.SquawkEmergency, c.emergency)
		}
	}
}

func TestSurveillanceAltitude(t *testing.T) {
	cases := []struct {
		frame    string
		altFt    int
		encoding string
	}{
		{"200003B0000000", 5000, "25ft"},           // Q=1, 25-ft
		{"20000010000000", -1000, "25ft"},          // Q=1, low
		{"20000C83000000", 38000, "Gillham 100ft"}, // Q=0 Gillham
		{"20000CA8000000", 25000, "Gillham 100ft"}, // Q=0 Gillham
		{"20000100000000", -1200, "Gillham 100ft"}, // Q=0 Gillham
	}
	for _, c := range cases {
		f, err := Decode(c.frame)
		if err != nil {
			t.Fatalf("Decode(%s): %v", c.frame, err)
		}
		if f.Surveillance == nil || f.Surveillance.AltitudeFt == nil {
			t.Fatalf("%s: no altitude", c.frame)
		}
		if *f.Surveillance.AltitudeFt != c.altFt {
			t.Errorf("%s: altitude = %d, want %d", c.frame, *f.Surveillance.AltitudeFt, c.altFt)
		}
		if f.Surveillance.AltitudeEncoding != c.encoding {
			t.Errorf("%s: encoding = %q, want %q", c.frame, f.Surveillance.AltitudeEncoding, c.encoding)
		}
	}
}

// TestSurveillanceRealDF20 confirms the AC13 altitude on the real Comm-B
// (DF20) frames, cross-checked against pyModeS altcode.
func TestSurveillanceRealDF20(t *testing.T) {
	cases := []struct {
		frame string
		altFt int
	}{
		{"A000029C85E42F313000007047D3", 3300},
		{"A000139381951536E024D4CCF6B5", 30275},
		{"A00004128F39F91A7E27C46ADC21", 5450},
	}
	for _, c := range cases {
		f, err := Decode(c.frame)
		if err != nil {
			t.Fatalf("Decode(%s): %v", c.frame, err)
		}
		if f.DF != 20 {
			t.Fatalf("%s: df = %d, want 20", c.frame, f.DF)
		}
		if f.Surveillance == nil || f.Surveillance.AltitudeFt == nil {
			t.Fatalf("%s: no altitude", c.frame)
		}
		if *f.Surveillance.AltitudeFt != c.altFt {
			t.Errorf("%s: altitude = %d, want %d", c.frame, *f.Surveillance.AltitudeFt, c.altFt)
		}
		// DF20 also carries Comm-B — both layers must be present.
		if f.CommB == nil {
			t.Errorf("%s: DF20 should also have Comm-B", c.frame)
		}
	}
}

// TestSurveillanceAllZeroAltitude handles the unknown-altitude code.
func TestSurveillanceAllZeroAltitude(t *testing.T) {
	f, err := Decode("20000000000000") // DF4 short frame, all-zero AC
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if f.Surveillance == nil || f.Surveillance.AltitudeFt != nil {
		t.Errorf("all-zero AC: altitude = %v, want nil", f.Surveillance)
	}
}

// TestSurveillanceOnlyForSurveillanceDFs confirms DF17 gets no AltID.
func TestSurveillanceOnlyForSurveillanceDFs(t *testing.T) {
	f, err := Decode("8D406B902015A678D4D220AA4BDA")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if f.Surveillance != nil {
		t.Errorf("DF17 should have no surveillance AltID, got %+v", f.Surveillance)
	}
}
