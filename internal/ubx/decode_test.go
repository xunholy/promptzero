// SPDX-License-Identifier: AGPL-3.0-or-later

package ubx

import (
	"math"
	"testing"
)

// navPVTSample is a UBX-NAV-PVT frame minted by pyubx2 1.3.1 from
// known field values (Munich, 3D fix, 9 SV, validDate/validTime/
// fullyResolved set). The decoded fields below are cross-checked
// against pyubx2's own UBXReader.parse of the same bytes. Checksum
// bytes are CF DE.
const navPVTSample = "b56201075c0018610400e807030f0c1e2d0719000000000000000300000950" +
	"c8ea06207fb21ce850080050990700300c000068100000b0040000d4feffff" +
	"32000000d50400006f88fc00fa000000b0c4120008070000000000000000000000000000cfde"

func TestDecodeNavPVT(t *testing.T) {
	msgs, err := Decode(navPVTSample)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}
	m := msgs[0]
	if m.Name != "NAV-PVT" || m.ClassID != 0x01 || m.MessageID != 0x07 {
		t.Errorf("name/class/id = %s/%d/%d; want NAV-PVT/1/7", m.Name, m.ClassID, m.MessageID)
	}
	if !m.ChecksumOK {
		t.Errorf("ChecksumOK = false; want true (Fletcher CF DE)")
	}
	if m.Length != 92 {
		t.Errorf("Length = %d; want 92", m.Length)
	}
	p := m.NavPVT
	if p == nil {
		t.Fatal("NavPVT nil")
	}
	if p.ITOWms != 287000 {
		t.Errorf("ITOWms = %d; want 287000", p.ITOWms)
	}
	if p.Year != 2024 || p.Month != 3 || p.Day != 15 || p.Hour != 12 || p.Minute != 30 || p.Second != 45 {
		t.Errorf("UTC parts = %04d-%02d-%02d %02d:%02d:%02d; want 2024-03-15 12:30:45",
			p.Year, p.Month, p.Day, p.Hour, p.Minute, p.Second)
	}
	if p.FixType != 3 || p.FixTypeName != "3D fix" {
		t.Errorf("FixType = %d (%q); want 3 3D fix", p.FixType, p.FixTypeName)
	}
	if p.NumSV != 9 {
		t.Errorf("NumSV = %d; want 9", p.NumSV)
	}
	if math.Abs(p.LongitudeDeg-11.605) > 1e-6 {
		t.Errorf("LongitudeDeg = %v; want 11.605", p.LongitudeDeg)
	}
	if math.Abs(p.LatitudeDeg-48.146) > 1e-6 {
		t.Errorf("LatitudeDeg = %v; want 48.146", p.LatitudeDeg)
	}
	if math.Abs(p.HeightM-545.0) > 1e-6 {
		t.Errorf("HeightM = %v; want 545.0", p.HeightM)
	}
	if math.Abs(p.HeightMSLM-498.0) > 1e-6 {
		t.Errorf("HeightMSLM = %v; want 498.0", p.HeightMSLM)
	}
	if math.Abs(p.HorizAccuracyM-3.12) > 1e-6 {
		t.Errorf("HorizAccuracyM = %v; want 3.12", p.HorizAccuracyM)
	}
	if math.Abs(p.VertAccuracyM-4.2) > 1e-6 {
		t.Errorf("VertAccuracyM = %v; want 4.2", p.VertAccuracyM)
	}
	if math.Abs(p.VelNorthMS-1.2) > 1e-6 || math.Abs(p.VelEastMS-(-0.3)) > 1e-6 || math.Abs(p.VelDownMS-0.05) > 1e-6 {
		t.Errorf("velNED = %v/%v/%v; want 1.2/-0.3/0.05", p.VelNorthMS, p.VelEastMS, p.VelDownMS)
	}
	if math.Abs(p.GroundSpeedMS-1.237) > 1e-6 {
		t.Errorf("GroundSpeedMS = %v; want 1.237", p.GroundSpeedMS)
	}
	if math.Abs(p.HeadingDeg-165.5) > 1e-4 {
		t.Errorf("HeadingDeg = %v; want 165.5", p.HeadingDeg)
	}
	if math.Abs(p.PositionDOP-18.0) > 1e-6 {
		t.Errorf("PositionDOP = %v; want 18.0", p.PositionDOP)
	}
	if p.UTC != "2024-03-15T12:30:45Z" {
		t.Errorf("UTC = %q; want 2024-03-15T12:30:45Z", p.UTC)
	}
	if !p.ValidDate || !p.ValidTime || !p.FullyResolved {
		t.Errorf("valid flags = date %v time %v resolved %v; want all true",
			p.ValidDate, p.ValidTime, p.FullyResolved)
	}
}

// navSATSample is a UBX-NAV-SAT frame minted by pyubx2 1.3.1 with
// two satellites (a used/healthy GPS SV and an unused/unhealthy
// GLONASS SV). Cross-checked against pyubx2's decode. Checksum 63 C5.
const navSATSample = "b56201352000186104000102000000052c4678000b001f080000060b000a2c0100002400000063c5"

func TestDecodeNavSAT(t *testing.T) {
	msgs, err := Decode(navSATSample)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	m := msgs[0]
	if m.Name != "NAV-SAT" || !m.ChecksumOK {
		t.Fatalf("name/ck = %s/%v; want NAV-SAT/true", m.Name, m.ChecksumOK)
	}
	s := m.NavSAT
	if s == nil {
		t.Fatal("NavSAT nil")
	}
	if s.ITOWms != 287000 || s.Version != 1 || s.NumSVs != 2 {
		t.Errorf("itow/version/numSvs = %d/%d/%d; want 287000/1/2", s.ITOWms, s.Version, s.NumSVs)
	}
	if len(s.Satellites) != 2 {
		t.Fatalf("got %d satellites; want 2", len(s.Satellites))
	}
	sv1 := s.Satellites[0]
	if sv1.GNSSID != 0 || sv1.GNSSName != "GPS" || sv1.SVID != 5 {
		t.Errorf("sv1 gnss/svid = %d(%q)/%d; want 0 GPS / 5", sv1.GNSSID, sv1.GNSSName, sv1.SVID)
	}
	if sv1.CNoDBHz != 44 || sv1.ElevationDeg != 70 || sv1.AzimuthDeg != 120 {
		t.Errorf("sv1 cno/elev/azim = %d/%d/%d; want 44/70/120", sv1.CNoDBHz, sv1.ElevationDeg, sv1.AzimuthDeg)
	}
	if math.Abs(sv1.PseudoRangeRes-1.1) > 1e-6 {
		t.Errorf("sv1 prRes = %v; want 1.1", sv1.PseudoRangeRes)
	}
	if sv1.QualityInd != 7 || !sv1.Used || sv1.Health != 1 || sv1.HealthName != "healthy" || !sv1.EphemerisAvail {
		t.Errorf("sv1 qual/used/health/eph = %d/%v/%d(%q)/%v; want 7/true/1 healthy/true",
			sv1.QualityInd, sv1.Used, sv1.Health, sv1.HealthName, sv1.EphemerisAvail)
	}
	sv2 := s.Satellites[1]
	if sv2.GNSSID != 6 || sv2.GNSSName != "GLONASS" || sv2.SVID != 11 {
		t.Errorf("sv2 gnss/svid = %d(%q)/%d; want 6 GLONASS / 11", sv2.GNSSID, sv2.GNSSName, sv2.SVID)
	}
	if sv2.AzimuthDeg != 300 {
		t.Errorf("sv2 azim = %d; want 300", sv2.AzimuthDeg)
	}
	if sv2.QualityInd != 4 || sv2.Used || sv2.Health != 2 || sv2.HealthName != "unhealthy" {
		t.Errorf("sv2 qual/used/health = %d/%v/%d(%q); want 4/false/2 unhealthy",
			sv2.QualityInd, sv2.Used, sv2.Health, sv2.HealthName)
	}
}

// navStatusSample is a UBX-NAV-STATUS frame minted by pyubx2 1.3.1
// (3D fix, fixOK, week+TOW set, TTFF 3500 ms, uptime 128000 ms).
const navStatusSample = "b5620103100018610400030d0000ac0d000000f401004f20"

func TestDecodeNavStatus(t *testing.T) {
	msgs, err := Decode(navStatusSample)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	m := msgs[0]
	if m.Name != "NAV-STATUS" || !m.ChecksumOK {
		t.Fatalf("name/ck = %s/%v; want NAV-STATUS/true", m.Name, m.ChecksumOK)
	}
	st := m.NavStatus
	if st == nil {
		t.Fatal("NavStatus nil")
	}
	if st.GPSFix != 3 || st.GPSFixName != "3D fix" {
		t.Errorf("gpsFix = %d (%q); want 3 3D fix", st.GPSFix, st.GPSFixName)
	}
	if !st.GPSFixOK || st.DiffSoln || !st.WeekNumSet || !st.TimeOfWeekOK {
		t.Errorf("flags fixOK/diff/wkn/tow = %v/%v/%v/%v; want true/false/true/true",
			st.GPSFixOK, st.DiffSoln, st.WeekNumSet, st.TimeOfWeekOK)
	}
	if st.TTFFms != 3500 || st.UptimeMs != 128000 {
		t.Errorf("ttff/uptime = %d/%d; want 3500/128000", st.TTFFms, st.UptimeMs)
	}
}

func TestDecodeSkipsLeadingGarbage(t *testing.T) {
	// A real capture often starts mid-stream; prepend junk bytes.
	msgs, err := Decode("ffeedd" + navPVTSample)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(msgs) != 1 || msgs[0].Name != "NAV-PVT" {
		t.Fatalf("got %d msgs; want 1 NAV-PVT", len(msgs))
	}
}

func TestDecodeBackToBack(t *testing.T) {
	msgs, err := Decode(navPVTSample + navPVTSample)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("got %d msgs; want 2", len(msgs))
	}
}

func TestDecodeBadChecksum(t *testing.T) {
	// Flip the last checksum byte: frame still parses but is flagged.
	bad := navPVTSample[:len(navPVTSample)-2] + "00"
	msgs, err := Decode(bad)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if msgs[0].ChecksumOK {
		t.Error("ChecksumOK = true for corrupted frame; want false")
	}
}

func TestDecodeUnknownMessageFrameOnly(t *testing.T) {
	// NAV-POSLLH (0x01 0x02) is named but not bodied out: with a
	// 28-byte zero payload, recompute the checksum.
	body := []byte{0x01, 0x02, 0x1C, 0x00}
	for i := 0; i < 28; i++ {
		body = append(body, 0x00)
	}
	a, b := fletcher(body)
	frame := append([]byte{0xB5, 0x62}, body...)
	frame = append(frame, a, b)
	msgs, err := Decode(hexOf(frame))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if msgs[0].Name != "NAV-POSLLH" {
		t.Errorf("Name = %q; want NAV-POSLLH", msgs[0].Name)
	}
	if !msgs[0].ChecksumOK {
		t.Error("ChecksumOK = false; want true")
	}
	if msgs[0].NavPVT != nil || msgs[0].NavSAT != nil || msgs[0].NavStatus != nil {
		t.Error("typed bodies should be nil for an undecoded message")
	}
	if msgs[0].PayloadHex == "" {
		t.Error("PayloadHex should be surfaced for an undecoded body")
	}
}

func TestDecodeRejectsNonUBX(t *testing.T) {
	for _, c := range []string{"", "zz", "0011223344556677", "b5"} {
		if _, err := Decode(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func hexOf(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, h[c>>4], h[c&0xf])
	}
	return string(out)
}

func FuzzDecode(f *testing.F) {
	f.Add(navPVTSample)
	f.Add(navSATSample)
	f.Add(navStatusSample)
	f.Add("ffeedd" + navPVTSample)
	f.Add("b562010700000000")
	f.Add("")
	f.Add("b5")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
