// SPDX-License-Identifier: AGPL-3.0-or-later

package nmea

import (
	"math"
	"testing"
)

// All expected values are pynmea2's decode of the same canonical sentences.

func one(t *testing.T, line string) *Sentence {
	t.Helper()
	s, err := Decode(line)
	if err != nil {
		t.Fatalf("Decode(%q): %v", line, err)
	}
	return s[0]
}

func feq(t *testing.T, name string, got *float64, want float64) {
	t.Helper()
	if got == nil {
		t.Errorf("%s = nil, want %v", name, want)
		return
	}
	if math.Abs(*got-want) > 1e-9 {
		t.Errorf("%s = %v, want %v", name, *got, want)
	}
}

func TestGGA(t *testing.T) {
	s := one(t, "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47")
	if !s.ChecksumOK {
		t.Error("checksum_ok = false, want true")
	}
	if s.Type != "GGA" || s.Talker != "GP" {
		t.Errorf("talker/type = %q/%q", s.Talker, s.Type)
	}
	if s.TimeUTC != "12:35:19" {
		t.Errorf("time = %q, want 12:35:19", s.TimeUTC)
	}
	feq(t, "lat", s.LatitudeDeg, 48.1173)
	feq(t, "lon", s.LongitudeDeg, 11.516666666666667)
	if s.FixQuality == nil || *s.FixQuality != 1 {
		t.Errorf("fix_quality = %v, want 1", s.FixQuality)
	}
	if s.NumSatellites == nil || *s.NumSatellites != 8 {
		t.Errorf("num_satellites = %v, want 8", s.NumSatellites)
	}
	feq(t, "hdop", s.HDOP, 0.9)
	feq(t, "alt", s.AltitudeM, 545.4)
}

func TestRMC(t *testing.T) {
	s := one(t, "$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A")
	if !s.ChecksumOK {
		t.Error("checksum_ok = false, want true")
	}
	if s.Status != "A (valid)" {
		t.Errorf("status = %q, want A (valid)", s.Status)
	}
	feq(t, "lat", s.LatitudeDeg, 48.1173)
	feq(t, "lon", s.LongitudeDeg, 11.516666666666667)
	feq(t, "speed_knots", s.SpeedKnots, 22.4)
	feq(t, "course", s.CourseDeg, 84.4)
	if s.Date != "1994-03-23" {
		t.Errorf("date = %q, want 1994-03-23", s.Date)
	}
	feq(t, "mag_var", s.MagVariationDeg, -3.1) // 003.1,W -> west is negative
}

func TestGLL(t *testing.T) {
	s := one(t, "$GPGLL,4916.45,N,12311.12,W,225444,A,*1D")
	if !s.ChecksumOK {
		t.Error("checksum_ok = false")
	}
	feq(t, "lat", s.LatitudeDeg, 49.274166666666666)
	feq(t, "lon", s.LongitudeDeg, -123.18533333333333)
	if s.TimeUTC != "22:54:44" || s.Status != "A (valid)" {
		t.Errorf("time/status = %q/%q", s.TimeUTC, s.Status)
	}
}

func TestVTG(t *testing.T) {
	s := one(t, "$GPVTG,054.7,T,034.4,M,005.5,N,010.2,K*48")
	if !s.ChecksumOK {
		t.Error("checksum_ok = false")
	}
	feq(t, "course_true", s.CourseDeg, 54.7)
	feq(t, "course_mag", s.CourseMagDeg, 34.4)
	feq(t, "speed_knots", s.SpeedKnots, 5.5)
	feq(t, "speed_kmh", s.SpeedKmh, 10.2)
}

func TestGSA(t *testing.T) {
	s := one(t, "$GPGSA,A,3,04,05,,09,12,,,24,,,,,2.5,1.3,2.1*39")
	if !s.ChecksumOK {
		t.Error("checksum_ok = false")
	}
	if s.FixType == nil || *s.FixType != 3 || s.FixTypeName != "3D fix" {
		t.Errorf("fix_type = %v / %q, want 3 / 3D fix", s.FixType, s.FixTypeName)
	}
	feq(t, "pdop", s.PDOP, 2.5)
	feq(t, "hdop", s.HDOP, 1.3)
	feq(t, "vdop", s.VDOP, 2.1)
}

func TestGSV(t *testing.T) {
	s := one(t, "$GPGSV,2,1,08,01,40,083,46,02,17,308,41,12,07,344,39,14,22,228,45*75")
	if !s.ChecksumOK {
		t.Error("checksum_ok = false")
	}
	if s.SatellitesInVie == nil || *s.SatellitesInVie != 8 {
		t.Errorf("satellites_in_view = %v, want 8", s.SatellitesInVie)
	}
}

func TestGSVSatelliteDetail(t *testing.T) {
	s := one(t, "$GPGSV,2,1,08,01,40,083,46,02,17,308,41,12,07,344,39,14,22,228,45*75")
	if s.SatellitesInVie == nil || *s.SatellitesInVie != 8 {
		t.Fatalf("satellites_in_view = %v, want 8", s.SatellitesInVie)
	}
	if len(s.Satellites) != 4 {
		t.Fatalf("got %d satellites, want 4", len(s.Satellites))
	}
	// First satellite: PRN 1, elev 40, azim 83, snr 46 (pynmea2).
	g := s.Satellites[0]
	if g.PRN != 1 || g.ElevationDeg == nil || *g.ElevationDeg != 40 ||
		g.AzimuthDeg == nil || *g.AzimuthDeg != 83 || g.SNR == nil || *g.SNR != 46 {
		t.Errorf("sat[0] = %+v, want PRN1/40/83/46", g)
	}
	// Last: PRN 14, elev 22, azim 228, snr 45.
	g = s.Satellites[3]
	if g.PRN != 14 || *g.SNR != 45 {
		t.Errorf("sat[3] = %+v, want PRN14 snr45", g)
	}
}

func TestGST(t *testing.T) {
	s := one(t, "$GPGST,172814.0,0.006,0.023,0.020,273.6,0.023,0.020,0.031*6A")
	if !s.ChecksumOK {
		t.Error("checksum_ok = false")
	}
	if s.TimeUTC != "17:28:14" {
		t.Errorf("time = %q, want 17:28:14", s.TimeUTC)
	}
	feq(t, "rms", s.RMS, 0.006)
	feq(t, "std_dev_major", s.StdDevMajorM, 0.023)
	feq(t, "std_dev_minor", s.StdDevMinorM, 0.020)
	feq(t, "orientation", s.OrientationDeg, 273.6)
	feq(t, "std_dev_lat", s.StdDevLatM, 0.023)
	feq(t, "std_dev_lon", s.StdDevLonM, 0.020)
	feq(t, "std_dev_alt", s.StdDevAltM, 0.031)
}

func TestZDA(t *testing.T) {
	s := one(t, "$GPZDA,160012.71,11,03,2004,-1,00*7D")
	if !s.ChecksumOK {
		t.Error("checksum_ok = false")
	}
	if s.TimeUTC != "16:00:12" {
		t.Errorf("time = %q, want 16:00:12", s.TimeUTC)
	}
	if s.Date != "2004-03-11" {
		t.Errorf("date = %q, want 2004-03-11", s.Date)
	}
}

// --- Marine instrument sentences (oracle values from pynmea2 1.19.0) ---

func TestHDT(t *testing.T) {
	s := one(t, "$GPHDT,274.07,T*03")
	if !s.ChecksumOK || s.Type != "HDT" {
		t.Fatalf("ck/type = %v/%s", s.ChecksumOK, s.Type)
	}
	feq(t, "heading_true", s.HeadingTrueDeg, 274.07)
}

func TestHDG(t *testing.T) {
	s := one(t, "$HCHDG,98.3,0.0,E,12.6,W*57")
	if !s.ChecksumOK || s.Type != "HDG" {
		t.Fatalf("ck/type = %v/%s", s.ChecksumOK, s.Type)
	}
	feq(t, "heading_mag", s.HeadingMagDeg, 98.3)
	feq(t, "deviation", s.MagDeviationDeg, 0.0)
	feq(t, "variation", s.MagVariationDeg, -12.6) // W = negative
}

func TestVHW(t *testing.T) {
	s := one(t, "$VWVHW,274.0,T,261.4,M,5.2,N,9.6,K*5C")
	if !s.ChecksumOK || s.Type != "VHW" {
		t.Fatalf("ck/type = %v/%s", s.ChecksumOK, s.Type)
	}
	feq(t, "heading_true", s.HeadingTrueDeg, 274.0)
	feq(t, "heading_mag", s.HeadingMagDeg, 261.4)
	feq(t, "water_speed_knots", s.WaterSpeedKnots, 5.2)
	feq(t, "water_speed_kmh", s.WaterSpeedKmh, 9.6)
}

func TestDBT(t *testing.T) {
	s := one(t, "$SDDBT,17.5,f,5.3,M,2.9,F*38")
	if !s.ChecksumOK || s.Type != "DBT" {
		t.Fatalf("ck/type = %v/%s", s.ChecksumOK, s.Type)
	}
	feq(t, "depth_feet", s.DepthFeet, 17.5)
	feq(t, "depth_meters", s.DepthMeters, 5.3)
	feq(t, "depth_fathoms", s.DepthFathoms, 2.9)
}

func TestDPT(t *testing.T) {
	s := one(t, "$SDDPT,5.3,0.5,0.0*56")
	if !s.ChecksumOK || s.Type != "DPT" {
		t.Fatalf("ck/type = %v/%s", s.ChecksumOK, s.Type)
	}
	feq(t, "depth_meters", s.DepthMeters, 5.3)
	feq(t, "depth_offset", s.DepthOffsetM, 0.5)
}

func TestMTW(t *testing.T) {
	s := one(t, "$YXMTW,17.9,C*1D")
	if !s.ChecksumOK || s.Type != "MTW" {
		t.Fatalf("ck/type = %v/%s", s.ChecksumOK, s.Type)
	}
	feq(t, "water_temp_c", s.WaterTempC, 17.9)
}

func TestMWV(t *testing.T) {
	s := one(t, "$WIMWV,214.8,R,0.1,K,A*28")
	if !s.ChecksumOK || s.Type != "MWV" {
		t.Fatalf("ck/type = %v/%s", s.ChecksumOK, s.Type)
	}
	feq(t, "wind_angle", s.WindAngleDeg, 214.8)
	if s.WindReference != "R" || s.WindSpeedUnits != "K" || s.Status != "A" {
		t.Errorf("ref/units/status = %q/%q/%q; want R/K/A", s.WindReference, s.WindSpeedUnits, s.Status)
	}
	feq(t, "wind_speed", s.WindSpeed, 0.1)
}

func TestMWD(t *testing.T) {
	s := one(t, "$WIMWD,271.0,T,261.0,M,7.0,N,3.6,M*59")
	if !s.ChecksumOK || s.Type != "MWD" {
		t.Fatalf("ck/type = %v/%s", s.ChecksumOK, s.Type)
	}
	feq(t, "dir_true", s.WindDirTrueDeg, 271.0)
	feq(t, "dir_mag", s.WindDirMagDeg, 261.0)
	feq(t, "speed_knots", s.WindSpeedKnots, 7.0)
	feq(t, "speed_ms", s.WindSpeedMS, 3.6)
}

func TestROT(t *testing.T) {
	s := one(t, "$TIROT,-2.3,A*17")
	if !s.ChecksumOK || s.Type != "ROT" {
		t.Fatalf("ck/type = %v/%s", s.ChecksumOK, s.Type)
	}
	feq(t, "rate_of_turn", s.RateOfTurnDegMin, -2.3)
	if s.Status != "A" {
		t.Errorf("status = %q; want A", s.Status)
	}
}

func TestChecksumBadFlagged(t *testing.T) {
	// Same GGA with a wrong checksum: still parses, but flagged.
	s := one(t, "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*00")
	if s.ChecksumOK {
		t.Error("checksum_ok = true, want false for a tampered sentence")
	}
	feq(t, "lat", s.LatitudeDeg, 48.1173) // still decoded
}

func TestEmptyFieldsNoFix(t *testing.T) {
	// A GGA with no fix: empty lat/lon must be nil, not zero.
	s := one(t, "$GPGGA,123519,,,,,0,00,,,M,,M,,*66")
	if s.LatitudeDeg != nil || s.LongitudeDeg != nil {
		t.Errorf("lat/lon = %v/%v, want nil/nil (no fix)", s.LatitudeDeg, s.LongitudeDeg)
	}
	if s.FixQuality == nil || *s.FixQuality != 0 {
		t.Errorf("fix_quality = %v, want 0", s.FixQuality)
	}
}

func TestMultiSentence(t *testing.T) {
	in := "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47\n" +
		"$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A"
	s, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(s) != 2 || s[0].Type != "GGA" || s[1].Type != "RMC" {
		t.Fatalf("got %d sentences: %v", len(s), s)
	}
}

func TestRejectsNonNMEA(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Error("Decode(empty) = nil error, want rejection")
	}
	s := one(t, "just some text")
	if s.Note == "" {
		t.Error("non-NMEA line should carry a Note")
	}
}
