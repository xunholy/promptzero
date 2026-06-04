// SPDX-License-Identifier: AGPL-3.0-or-later

package geohash

import (
	"math"
	"testing"
)

func feq(t *testing.T, name string, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 1e-9 {
		t.Errorf("%s = %.12f, want %.12f", name, got, want)
	}
}

// Expected values are the pygeohash reference library's decode_exactly.
func TestDecode(t *testing.T) {
	cases := []struct {
		gh                       string
		lat, lon, laterr, lonerr float64
	}{
		{"ezs42", 42.60498046875, -5.60302734375, 0.02197265625, 0.02197265625},
		{"u4pruydqqvj", 57.64911063015461, 10.407439693808556, 6.705522537231445e-07, 6.705522537231445e-07},
		{"9q8yy", 37.77099609375, -122.40966796875, 0.02197265625, 0.02197265625},
		{"0", -67.5, -157.5, 22.5, 22.5},
		{"z", 67.5, 157.5, 22.5, 22.5},
	}
	for _, c := range cases {
		loc, err := Decode(c.gh)
		if err != nil {
			t.Errorf("Decode(%q): %v", c.gh, err)
			continue
		}
		feq(t, c.gh+".lat", loc.Lat, c.lat)
		feq(t, c.gh+".lon", loc.Lon, c.lon)
		feq(t, c.gh+".laterr", loc.LatErr, c.laterr)
		feq(t, c.gh+".lonerr", loc.LonErr, c.lonerr)
		// center must sit inside the reported bounding box.
		if loc.Lat < loc.MinLat || loc.Lat > loc.MaxLat || loc.Lon < loc.MinLon || loc.Lon > loc.MaxLon {
			t.Errorf("%s: center outside bbox", c.gh)
		}
	}
}

func TestEncode(t *testing.T) {
	cases := []struct {
		lat, lon float64
		prec     int
		want     string
	}{
		{42.6, -5.6, 5, "ezs42"},
		{57.64911, 10.40744, 11, "u4pruydqqvj"},
		{37.77, -122.41, 5, "9q8yy"},
	}
	for _, c := range cases {
		got, err := Encode(c.lat, c.lon, c.prec)
		if err != nil {
			t.Errorf("Encode(%v,%v,%d): %v", c.lat, c.lon, c.prec, err)
			continue
		}
		if got != c.want {
			t.Errorf("Encode(%v,%v,%d) = %q, want %q", c.lat, c.lon, c.prec, got, c.want)
		}
	}
}

// Encoding a geohash's own center back must reproduce it (round-trip).
func TestRoundTrip(t *testing.T) {
	loc, _ := Decode("u4pruydqqvj")
	g, err := Encode(loc.Lat, loc.Lon, loc.Precision)
	if err != nil || g != "u4pruydqqvj" {
		t.Errorf("round-trip = %q (%v), want u4pruydqqvj", g, err)
	}
}

func TestDecodeRejects(t *testing.T) {
	for _, in := range []string{"", "abc", "ezs4i", "ezs4l", "EZS42O", "geohash!", "0123456789bcd"} {
		// a/i/l/o are not in the geohash alphabet; >12 chars rejected.
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) = nil error, want rejection", in)
		}
	}
}

func TestEncodeRejects(t *testing.T) {
	if _, err := Encode(91, 0, 5); err == nil {
		t.Error("Encode lat 91 should be rejected")
	}
	if _, err := Encode(0, 181, 5); err == nil {
		t.Error("Encode lon 181 should be rejected")
	}
	if _, err := Encode(0, 0, 99); err == nil {
		t.Error("Encode precision 99 should be rejected")
	}
}
