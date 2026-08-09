// SPDX-License-Identifier: AGPL-3.0-or-later

package adsb

import (
	"math"
	"testing"
)

// TestGlobalAirbornePosition_Canonical anchors the CPR global decode to the
// standard worked example (Junzi Sun, "The 1090 MHz Riddle"): even
// (93000, 51372) + odd (74158, 50194) resolve to 52.2572, 3.91937 for the
// even frame's instant.
func TestGlobalAirbornePosition_Canonical(t *testing.T) {
	lat, lon, ok := GlobalAirbornePosition(93000, 51372, 74158, 50194, true)
	if !ok {
		t.Fatal("canonical pair did not resolve")
	}
	if math.Abs(lat-52.25720) > 1e-4 {
		t.Errorf("lat = %.5f, want 52.25720", lat)
	}
	if math.Abs(lon-3.91937) > 1e-4 {
		t.Errorf("lon = %.5f, want 3.91937", lon)
	}
}

// TestGlobalPositionFromFrames_Canonical drives the full frame-pairing path
// with the canonical hex frames.
func TestGlobalPositionFromFrames_Canonical(t *testing.T) {
	const (
		even = "8D40621D58C382D690C8AC2863A7"
		odd  = "8D40621D58C386435CC412692AD6"
	)
	gp, err := GlobalPositionFromFrames(even, odd, true)
	if err != nil {
		t.Fatalf("GlobalPositionFromFrames: %v", err)
	}
	if math.Abs(gp.Latitude-52.25720) > 1e-4 || math.Abs(gp.Longitude-3.91937) > 1e-4 {
		t.Errorf("got (%.5f, %.5f), want (52.25720, 3.91937)", gp.Latitude, gp.Longitude)
	}
	if gp.ICAOAddress != "40621D" {
		t.Errorf("ICAO = %q, want 40621D", gp.ICAOAddress)
	}
	if gp.Reference != "even" {
		t.Errorf("Reference = %q, want even", gp.Reference)
	}
}

// TestGlobalPositionFromFrames_Refusals verifies the no-confidently-wrong
// guards: swapped even/odd, and two even frames, must error rather than
// return a bogus coordinate.
func TestGlobalPositionFromFrames_Refusals(t *testing.T) {
	const (
		even = "8D40621D58C382D690C8AC2863A7"
		odd  = "8D40621D58C386435CC412692AD6"
	)
	// even/odd swapped into the wrong parameters.
	if _, err := GlobalPositionFromFrames(odd, even, true); err == nil {
		t.Error("swapped even/odd frames should be rejected (format mismatch)")
	}
	// Two even frames — no odd frame to pair with.
	if _, err := GlobalPositionFromFrames(even, even, true); err == nil {
		t.Error("two even frames should be rejected")
	}
	// A non-position frame (identification, TC 4) must be refused.
	if _, err := GlobalPositionFromFrames("8D4840D6202CC371C32CE0576098", odd, true); err == nil {
		t.Error("a non-airborne-position even frame should be rejected")
	}
}

// TestLocalAirbornePosition_Canonical anchors the single-frame local decode:
// the even frame's CPR (93000, 51372) against reference (52.258, 3.918)
// resolves to the same canonical 52.2572, 3.91937.
func TestLocalAirbornePosition_Canonical(t *testing.T) {
	lat, lon, ok := LocalAirbornePosition(93000, 51372, false, 52.258, 3.918)
	if !ok {
		t.Fatal("local decode returned not-ok for an in-range reference")
	}
	if math.Abs(lat-52.25720) > 1e-4 || math.Abs(lon-3.91937) > 1e-4 {
		t.Errorf("got (%.5f, %.5f), want (52.25720, 3.91937)", lat, lon)
	}
}

// TestLocalPositionFromFrame drives the frame path and the out-of-range /
// wrong-frame guards.
func TestLocalPositionFromFrame(t *testing.T) {
	gp, err := LocalPositionFromFrame("8D40621D58C382D690C8AC2863A7", 52.258, 3.918)
	if err != nil {
		t.Fatalf("LocalPositionFromFrame: %v", err)
	}
	if math.Abs(gp.Latitude-52.25720) > 1e-4 || math.Abs(gp.Longitude-3.91937) > 1e-4 {
		t.Errorf("got (%.5f, %.5f), want (52.25720, 3.91937)", gp.Latitude, gp.Longitude)
	}
	if gp.Reference != "local" {
		t.Errorf("Reference = %q, want local", gp.Reference)
	}
	// Out-of-range reference.
	if _, _, ok := LocalAirbornePosition(93000, 51372, false, 200, 3.918); ok {
		t.Error("out-of-range reference latitude should return not-ok")
	}
	// A non-position frame (identification, TC 4) must be refused.
	if _, err := LocalPositionFromFrame("8D4840D6202CC371C32CE0576098", 52.258, 3.918); err == nil {
		t.Error("a non-airborne-position frame should be rejected")
	}
}

// TestCPRNL spot-checks the NL longitude-zone function at its documented
// break latitudes.
func TestCPRNL(t *testing.T) {
	cases := []struct {
		lat  float64
		want int
	}{
		{0, 59},
		{87, 2},
		{88, 1},
		{-88, 1},
		{52.0, 36}, // mid-latitude sanity (matches the canonical example's zone)
	}
	for _, c := range cases {
		if got := cprNL(c.lat); got != c.want {
			t.Errorf("cprNL(%.1f) = %d, want %d", c.lat, got, c.want)
		}
	}
}
