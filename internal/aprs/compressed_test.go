// SPDX-License-Identifier: AGPL-3.0-or-later

package aprs

import "testing"

// APRS101 §9 compressed-position vectors. Each packet was built from a
// known lat/lon + cs and cross-decoded with the aprslib Python library
// (the independent oracle); the expected values below are aprslib's,
// converted to APRS-native units (speed knots = aprslib km/h ÷ 1.852;
// altitude ft = aprslib m ÷ 0.3048; range mi = aprslib km ÷ 1.609344).

func TestCompressedCourseSpeed(t *testing.T) {
	f, err := Decode("N0CALL>APRS,WIDE1-1:!/5L!!<*e8>yE[")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	p := f.Position
	if p == nil || !p.Compressed {
		t.Fatalf("position=%v, want compressed", p)
	}
	near(t, "lat", p.LatitudeDeg, 49.5, 1e-6)
	near(t, "lon", p.LongitudeDeg, -72.7499986874091, 1e-6)
	if p.SymbolTable != "/" || p.SymbolCode != ">" {
		t.Errorf("symbol table/code = %q/%q, want / />", p.SymbolTable, p.SymbolCode)
	}
	if p.CourseDeg != 352 {
		t.Errorf("course = %d, want 352", p.CourseDeg)
	}
	near(t, "speed_knots", p.SpeedKnots, 14.9681718379, 1e-6) // 27.7210542437 km/h ÷ 1.852
	if p.AltitudeFt != 0 || p.RadioRangeMi != 0 {
		t.Errorf("alt/range set unexpectedly: %v / %v", p.AltitudeFt, p.RadioRangeMi)
	}
}

func TestCompressedNoCS(t *testing.T) {
	f, err := Decode("N0CALL>APRS:!\\`6WXqPijk  !")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	p := f.Position
	if p == nil || !p.Compressed {
		t.Fatalf("position=%v, want compressed", p)
	}
	near(t, "lat", p.LatitudeDeg, -35.10000105007272, 1e-6)
	near(t, "lon", p.LongitudeDeg, 138.6000010500727, 1e-6)
	if p.SymbolTable != "\\" || p.SymbolCode != "k" {
		t.Errorf("symbol table/code = %q/%q, want \\ /k", p.SymbolTable, p.SymbolCode)
	}
	// Spaces in cs => no course/speed/altitude/range.
	if p.CourseDeg != 0 || p.SpeedKnots != 0 || p.AltitudeFt != 0 || p.RadioRangeMi != 0 {
		t.Errorf("cs extension set on a no-cs packet: c=%d s=%v alt=%v rng=%v",
			p.CourseDeg, p.SpeedKnots, p.AltitudeFt, p.RadioRangeMi)
	}
}

func TestCompressedWithTimestampAndComment(t *testing.T) {
	// '=' data type, course/speed, plus a trailing comment.
	f, err := Decode("N0CALL>APRS:=/9u<\";gyon:+Chello")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	p := f.Position
	if p == nil || !p.Compressed {
		t.Fatalf("position=%v, want compressed", p)
	}
	near(t, "lat", p.LatitudeDeg, 40.68919947706379, 1e-6)
	near(t, "lon", p.LongitudeDeg, -74.04450208176917, 1e-6)
	if p.CourseDeg != 100 {
		t.Errorf("course = %d, want 100", p.CourseDeg)
	}
	near(t, "speed_knots", p.SpeedKnots, 1.1589249973, 1e-6) // 2.1463290949 km/h ÷ 1.852
	if f.Comment != "hello" {
		t.Errorf("comment = %q, want hello", f.Comment)
	}
}

func TestCompressedAltitude(t *testing.T) {
	f, err := Decode("N0CALL>APRS:!/5L!!<*e8O5SQ")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	p := f.Position
	if p == nil || !p.Compressed {
		t.Fatalf("position=%v, want compressed", p)
	}
	near(t, "altitude_ft", p.AltitudeFt, 41.941043307, 1e-3) // aprslib 12.7836 m ÷ 0.3048
	if p.CourseDeg != 0 || p.SpeedKnots != 0 {
		t.Errorf("course/speed set on an altitude packet: %d / %v", p.CourseDeg, p.SpeedKnots)
	}
}

func TestCompressedRadioRange(t *testing.T) {
	f, err := Decode("N0CALL>APRS:!/5L!!<*e8>{I#")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	p := f.Position
	if p == nil || !p.Compressed {
		t.Fatalf("position=%v, want compressed", p)
	}
	near(t, "radio_range_mi", p.RadioRangeMi, 43.449043, 1e-3) // aprslib 69.9245 km ÷ 1.609344
	if p.CourseDeg != 0 || p.AltitudeFt != 0 {
		t.Errorf("course/altitude set on a range packet: %d / %v", p.CourseDeg, p.AltitudeFt)
	}
}

// An uncompressed position must still take the §8 path (leading digit),
// not be misrouted to the compressed decoder.
func TestUncompressedStillWorks(t *testing.T) {
	f, err := Decode("N0CALL>APRS:!4903.50N/07201.75W-")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if f.Position == nil || f.Position.Compressed {
		t.Fatalf("position=%v, want uncompressed", f.Position)
	}
	near(t, "lat", f.Position.LatitudeDeg, 49.0583333, 1e-5)
}
