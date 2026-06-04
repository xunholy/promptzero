// SPDX-License-Identifier: AGPL-3.0-or-later

package maidenhead

import (
	"math"
	"testing"
)

func feq(t *testing.T, name string, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 1e-6 {
		t.Errorf("%s = %.8f, want %.8f", name, got, want)
	}
}

// Expected outputs are the `maidenhead` Python reference library's.
func TestEncode(t *testing.T) {
	cases := []struct {
		lat, lon float64
		pairs    int
		want     string
	}{
		{41.714, -72.728, 2, "FN31"},
		{41.714, -72.728, 3, "FN31pr"},
		{41.714, -72.728, 4, "FN31pr21"},
		{48.146, 11.608, 3, "JN58td"},
		{-35.28, 149.13, 3, "QF44nr"},
		{0.0, 0.0, 3, "JJ00aa"},
		{51.5, -0.12, 4, "IO91wm50"},
	}
	for _, c := range cases {
		got, err := Encode(c.lat, c.lon, c.pairs)
		if err != nil {
			t.Errorf("Encode(%v,%v,%d): %v", c.lat, c.lon, c.pairs, err)
			continue
		}
		if got != c.want {
			t.Errorf("Encode(%v,%v,%d) = %q, want %q", c.lat, c.lon, c.pairs, got, c.want)
		}
	}
}

func TestEncodeDefaultPrecision(t *testing.T) {
	got, err := Encode(48.146, 11.608, 0) // 0 -> default 3 pairs
	if err != nil || got != "JN58td" {
		t.Errorf("Encode default = %q (%v), want JN58td", got, err)
	}
}

func TestDecode(t *testing.T) {
	cases := []struct {
		grid                       string
		cLat, cLon, ctrLat, ctrLon float64
	}{
		{"FN31", 41.0, -74.0, 41.5, -73.0},
		{"FN31pr", 41.708333333, -72.75, 41.729166666, -72.708333333},
		{"JN58td", 48.125, 11.583333333, 48.145833333, 11.625},
		{"QF44", -36.0, 148.0, -35.5, 149.0},
		{"JJ00aa", 0.0, 0.0, 0.020833333, 0.041666666},
		{"IO91wm", 51.5, -0.166666666, 51.520833333, -0.125},
	}
	for _, c := range cases {
		loc, err := Decode(c.grid)
		if err != nil {
			t.Errorf("Decode(%q): %v", c.grid, err)
			continue
		}
		feq(t, c.grid+".corner_lat", loc.CornerLat, c.cLat)
		feq(t, c.grid+".corner_lon", loc.CornerLon, c.cLon)
		feq(t, c.grid+".center_lat", loc.CenterLat, c.ctrLat)
		feq(t, c.grid+".center_lon", loc.CenterLon, c.ctrLon)
	}
}

// Decode is case-insensitive and round-trips with Encode (the encoded
// locator's center lands inside the original cell).
func TestRoundTripAndCaseInsensitive(t *testing.T) {
	loc, err := Decode("jn58TD") // mixed case
	if err != nil {
		t.Fatalf("Decode mixed case: %v", err)
	}
	if loc.Grid != "JN58td" {
		t.Errorf("canonical grid = %q, want JN58td", loc.Grid)
	}
	g, err := Encode(loc.CenterLat, loc.CenterLon, 3)
	if err != nil || g != "JN58td" {
		t.Errorf("round-trip center -> %q (%v), want JN58td", g, err)
	}
}

func TestDecodeRejects(t *testing.T) {
	for _, in := range []string{"", "F", "FN3", "FNXY", "9N31", "FN31zz", "FN31pr2"} {
		// "FNXY": square pair must be digits; "9N31": field must be letters;
		// "FN31zz": subsquare letters max 'x'; odd lengths rejected.
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) = nil error, want rejection", in)
		}
	}
}

func TestEncodeRejects(t *testing.T) {
	if _, err := Encode(91, 0, 3); err == nil {
		t.Error("Encode lat 91 should be rejected")
	}
	if _, err := Encode(0, 181, 3); err == nil {
		t.Error("Encode lon 181 should be rejected")
	}
	if _, err := Encode(0, 0, 99); err == nil {
		t.Error("Encode 99 pairs should be rejected")
	}
}
