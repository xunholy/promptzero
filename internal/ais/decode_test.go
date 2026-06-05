package ais

import (
	"math"
	"strings"
	"testing"
)

// TestDecode_Type1_PositionReport pins a real Type 1 Class A
// position report from a US-flagged vessel (MMSI 366053209) in
// the San Francisco area.
func TestDecode_Type1_PositionReport(t *testing.T) {
	got, err := Decode("!AIVDM,1,1,,A,15M67FC000G?ufbE`FepT@3n00Sa,0*5F")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MessageType != 1 {
		t.Errorf("MessageType = %d; want 1", got.MessageType)
	}
	if got.TypeName != "Position Report Class A (scheduled)" {
		t.Errorf("TypeName = %q", got.TypeName)
	}
	if got.MMSI != 366053209 {
		t.Errorf("MMSI = %d; want 366053209", got.MMSI)
	}
	if got.Channel != "A" {
		t.Errorf("Channel = %q; want 'A'", got.Channel)
	}
	if got.PositionClassA == nil {
		t.Fatal("PositionClassA nil")
	}
	pa := got.PositionClassA
	if pa.NavStatus != 3 {
		t.Errorf("NavStatus = %d; want 3 (Restricted manoeuvrability)", pa.NavStatus)
	}
	if pa.NavStatusName != "Restricted manoeuvrability" {
		t.Errorf("NavStatusName = %q", pa.NavStatusName)
	}
	if pa.LongitudeDeg == nil || math.Abs(*pa.LongitudeDeg-(-122.34161833)) > 0.0001 {
		t.Errorf("LongitudeDeg = %v; want ~-122.3416", pa.LongitudeDeg)
	}
	if pa.LatitudeDeg == nil || math.Abs(*pa.LatitudeDeg-37.80211833) > 0.0001 {
		t.Errorf("LatitudeDeg = %v; want ~37.8021", pa.LatitudeDeg)
	}
	if pa.CourseOverGroundDeg == nil || math.Abs(*pa.CourseOverGroundDeg-219.3) > 0.01 {
		t.Errorf("CourseOverGroundDeg = %v; want ~219.3", pa.CourseOverGroundDeg)
	}
}

// TestDecode_Type1_Moored pins a moored-vessel position report
// (different nav status, no movement).
func TestDecode_Type1_Moored(t *testing.T) {
	got, err := Decode("!AIVDM,1,1,,A,177KQJ5000G?tO`K>RA1wUbN0TKH,0*5F")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MMSI != 477553000 {
		t.Errorf("MMSI = %d; want 477553000", got.MMSI)
	}
	pa := got.PositionClassA
	if pa == nil {
		t.Fatal("PositionClassA nil")
	}
	if pa.NavStatus != 5 {
		t.Errorf("NavStatus = %d; want 5 (Moored)", pa.NavStatus)
	}
	if pa.NavStatusName != "Moored" {
		t.Errorf("NavStatusName = %q", pa.NavStatusName)
	}
	if pa.LongitudeDeg == nil || math.Abs(*pa.LongitudeDeg-(-122.34583333)) > 0.0001 {
		t.Errorf("LongitudeDeg = %v; want ~-122.3458", pa.LongitudeDeg)
	}
	if pa.LatitudeDeg == nil || math.Abs(*pa.LatitudeDeg-47.58283333) > 0.0001 {
		t.Errorf("LatitudeDeg = %v; want ~47.5828", pa.LatitudeDeg)
	}
}

// TestDecode_Type5_MultiFragment exercises the 2-fragment
// reassembly path that Type 5 always uses.
func TestDecode_Type5_MultiFragment(t *testing.T) {
	input := "!AIVDM,2,1,3,A,539p4OT00000@7WSKL0LE@TltL5@F22222222220O1@F2240Ht50000000000,0*3D\n" +
		"!AIVDM,2,2,3,A,000000000000000,2*27"
	got, err := Decode(input)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MessageType != 5 {
		t.Errorf("MessageType = %d; want 5", got.MessageType)
	}
	if got.MMSI != 211682430 {
		t.Errorf("MMSI = %d; want 211682430", got.MMSI)
	}
	if len(got.Sentences) != 2 {
		t.Errorf("Sentences count = %d; want 2", len(got.Sentences))
	}
	sv := got.StaticAndVoyage
	if sv == nil {
		t.Fatal("StaticAndVoyage nil")
	}
	if sv.CallSign != "DA9867" {
		t.Errorf("CallSign = %q; want 'DA9867'", sv.CallSign)
	}
	if sv.VesselName != "GETIMOGATE" {
		t.Errorf("VesselName = %q; want 'GETIMOGATE'", sv.VesselName)
	}
	if sv.AISVersion != 1 {
		t.Errorf("AISVersion = %d; want 1", sv.AISVersion)
	}
}

// TestDecode_Type18_PositionClassB pins a real Class B position
// report from a Chinese-flagged vessel.
func TestDecode_Type18_PositionClassB(t *testing.T) {
	got, err := Decode("!AIVDM,1,1,,B,B69>7m@0?j<:>05B0`0e;wq2PHI8,0*35")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MessageType != 18 {
		t.Errorf("MessageType = %d; want 18", got.MessageType)
	}
	if got.MMSI != 412321749 {
		t.Errorf("MMSI = %d; want 412321749", got.MMSI)
	}
	pb := got.PositionClassB
	if pb == nil {
		t.Fatal("PositionClassB nil")
	}
	if pb.SpeedOverGroundKts == nil || *pb.SpeedOverGroundKts != 6.3 {
		t.Errorf("SpeedOverGroundKts = %v; want 6.3", pb.SpeedOverGroundKts)
	}
	if pb.LongitudeDeg == nil || math.Abs(*pb.LongitudeDeg-122.47338666) > 0.001 {
		t.Errorf("LongitudeDeg = %v; want ~122.47", pb.LongitudeDeg)
	}
	if pb.LatitudeDeg == nil || math.Abs(*pb.LatitudeDeg-36.91968) > 0.001 {
		t.Errorf("LatitudeDeg = %v; want ~36.92", pb.LatitudeDeg)
	}
}

// TestDecode_Type24_PartB pins a Class B static-data report
// PartB carrying ship type + callsign + vendor ID.
func TestDecode_Type24_PartB(t *testing.T) {
	got, err := Decode("!AIVDM,1,1,,B,H1c2;qDTijklmno31<<C970`43<1,0*2A")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MessageType != 24 {
		t.Errorf("MessageType = %d; want 24", got.MessageType)
	}
	sb := got.StaticClassB
	if sb == nil {
		t.Fatal("StaticClassB nil")
	}
	if sb.PartNumber != 1 {
		t.Errorf("PartNumber = %d; want 1", sb.PartNumber)
	}
	if !strings.Contains(sb.ShipTypeName, "Sailing") {
		t.Errorf("ShipTypeName = %q; want 'Sailing' label", sb.ShipTypeName)
	}
	if sb.CallSign != "CALLSIG" {
		t.Errorf("CallSign = %q", sb.CallSign)
	}
	if sb.DimensionBow == 0 && sb.DimensionStern == 0 {
		t.Errorf("Dimensions should be non-zero (non-auxiliary craft): bow=%d stern=%d", sb.DimensionBow, sb.DimensionStern)
	}
}

// TestDecode_Type9_SARAircraft pins a Search-And-Rescue aircraft
// position report. The sentence was minted by pyais 3.0.1's
// encoder from known field values and the decoded fields are
// cross-checked against pyais's own decode() of it.
func TestDecode_Type9_SARAircraft(t *testing.T) {
	got, err := Decode("!AIVDO,1,1,,A,91b74r1GQOPC?t8MfhuW:rP00000,0*7E")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MessageType != 9 {
		t.Errorf("MessageType = %d; want 9", got.MessageType)
	}
	if got.MMSI != 111265000 {
		t.Errorf("MMSI = %d; want 111265000", got.MMSI)
	}
	a := got.SARAircraft
	if a == nil {
		t.Fatal("SARAircraft nil")
	}
	if a.AltitudeM == nil || *a.AltitudeM != 350 {
		t.Errorf("AltitudeM = %v; want 350", a.AltitudeM)
	}
	if a.SpeedOverGroundKts == nil || *a.SpeedOverGroundKts != 95 {
		t.Errorf("SpeedOverGroundKts = %v; want 95 (whole knots)", a.SpeedOverGroundKts)
	}
	if !a.PositionAccuracy {
		t.Errorf("PositionAccuracy = false; want true")
	}
	if a.LongitudeDeg == nil || math.Abs(*a.LongitudeDeg-4.20502) > 0.001 {
		t.Errorf("LongitudeDeg = %v; want ~4.20502", a.LongitudeDeg)
	}
	if a.LatitudeDeg == nil || math.Abs(*a.LatitudeDeg-51.95817) > 0.001 {
		t.Errorf("LatitudeDeg = %v; want ~51.95817", a.LatitudeDeg)
	}
	if a.CourseOverGroundDeg == nil || math.Abs(*a.CourseOverGroundDeg-183.5) > 0.001 {
		t.Errorf("CourseOverGroundDeg = %v; want 183.5", a.CourseOverGroundDeg)
	}
	if a.Timestamp != 42 {
		t.Errorf("Timestamp = %d; want 42", a.Timestamp)
	}
	if a.DTE != 0 || a.Assigned || a.RAIM {
		t.Errorf("dte/assigned/raim = %d/%v/%v; want 0/false/false", a.DTE, a.Assigned, a.RAIM)
	}
}

// TestDecode_Type27_LongRange pins a long-range (satellite)
// position report. Oracle values cross-checked against pyais
// 3.0.1.
func TestDecode_Type27_LongRange(t *testing.T) {
	got, err := Decode("!AIVDM,1,1,,B,KC5E2b@U19PFdLbMuc5=ROv62<7m,0*16")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MessageType != 27 {
		t.Errorf("MessageType = %d; want 27", got.MessageType)
	}
	if got.MMSI != 206914217 {
		t.Errorf("MMSI = %d; want 206914217", got.MMSI)
	}
	l := got.LongRange
	if l == nil {
		t.Fatal("LongRange nil")
	}
	if l.NavStatus != 2 || !strings.Contains(l.NavStatusName, "Not under command") {
		t.Errorf("NavStatus = %d (%q); want 2 Not under command", l.NavStatus, l.NavStatusName)
	}
	if l.LongitudeDeg == nil || math.Abs(*l.LongitudeDeg-137.023333) > 0.001 {
		t.Errorf("LongitudeDeg = %v; want ~137.023333", l.LongitudeDeg)
	}
	if l.LatitudeDeg == nil || math.Abs(*l.LatitudeDeg-4.84) > 0.001 {
		t.Errorf("LatitudeDeg = %v; want ~4.84", l.LatitudeDeg)
	}
	if l.SpeedOverGroundKts == nil || *l.SpeedOverGroundKts != 57 {
		t.Errorf("SpeedOverGroundKts = %v; want 57 (whole knots)", l.SpeedOverGroundKts)
	}
	if l.CourseOverGroundDeg == nil || *l.CourseOverGroundDeg != 167 {
		t.Errorf("CourseOverGroundDeg = %v; want 167 (whole degrees)", l.CourseOverGroundDeg)
	}
	if l.PositionAccuracy || l.RAIM || l.GNSSPositionLatency {
		t.Errorf("accuracy/raim/gnss = %v/%v/%v; want false/false/false",
			l.PositionAccuracy, l.RAIM, l.GNSSPositionLatency)
	}
}

// TestDecode_Type9_Sentinels locks in the not-available sentinels: a
// Type 9 with altitude 4095 (N/A) and speed 1023 (N/A) but a valid
// position must decode those two to nil, not a zero. Oracle: pyais.
func TestDecode_Type9_Sentinels(t *testing.T) {
	got, err := Decode("!AIVDO,1,1,,A,91auciwwwwPC>N0Md``>3jP00000,0*4F")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	a := got.SARAircraft
	if a == nil {
		t.Fatal("SARAircraft nil")
	}
	if a.AltitudeM != nil {
		t.Errorf("AltitudeM = %v; want nil (4095 sentinel)", a.AltitudeM)
	}
	if a.SpeedOverGroundKts != nil {
		t.Errorf("SpeedOverGroundKts = %v; want nil (1023 sentinel)", a.SpeedOverGroundKts)
	}
	if a.LongitudeDeg == nil || math.Abs(*a.LongitudeDeg-4.2) > 0.001 {
		t.Errorf("LongitudeDeg = %v; want ~4.2 (position still valid)", a.LongitudeDeg)
	}
}

// TestDecode_Type27_Sentinels locks in the Type 27 not-available
// sentinels: speed 63 and course 511 must decode to nil. Oracle: pyais.
func TestDecode_Type27_Sentinels(t *testing.T) {
	got, err := Decode("!AIVDO,1,1,,A,K3CsGSShGL3bHOwt,0*1D")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	l := got.LongRange
	if l == nil {
		t.Fatal("LongRange nil")
	}
	if l.SpeedOverGroundKts != nil {
		t.Errorf("SpeedOverGroundKts = %v; want nil (63 sentinel)", l.SpeedOverGroundKts)
	}
	if l.CourseOverGroundDeg != nil {
		t.Errorf("CourseOverGroundDeg = %v; want nil (511 sentinel)", l.CourseOverGroundDeg)
	}
	if l.LongitudeDeg == nil || math.Abs(*l.LongitudeDeg-10.0) > 0.01 {
		t.Errorf("LongitudeDeg = %v; want ~10.0 (position still valid)", l.LongitudeDeg)
	}
}

// TestDecode_Type19_ExtendedClassB pins an Extended Class B
// position report. Oracle values cross-checked against pyais
// 3.0.1 decode() of the same sentence.
func TestDecode_Type19_ExtendedClassB(t *testing.T) {
	got, err := Decode("!AIVDM,1,1,,B,C5N3SRgPEnJGEBT>NhWAwwo862PaLELTBJ:V00000000S0D:R220,0*0B")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MessageType != 19 {
		t.Errorf("MessageType = %d; want 19", got.MessageType)
	}
	if got.MMSI != 367059850 {
		t.Errorf("MMSI = %d; want 367059850", got.MMSI)
	}
	e := got.ExtendedClassB
	if e == nil {
		t.Fatal("ExtendedClassB nil")
	}
	if e.SpeedOverGroundKts == nil || math.Abs(*e.SpeedOverGroundKts-8.7) > 0.001 {
		t.Errorf("SpeedOverGroundKts = %v; want 8.7", e.SpeedOverGroundKts)
	}
	if e.LongitudeDeg == nil || math.Abs(*e.LongitudeDeg-(-88.810392)) > 0.001 {
		t.Errorf("LongitudeDeg = %v; want ~-88.810392", e.LongitudeDeg)
	}
	if e.LatitudeDeg == nil || math.Abs(*e.LatitudeDeg-29.543695) > 0.001 {
		t.Errorf("LatitudeDeg = %v; want ~29.543695", e.LatitudeDeg)
	}
	if e.CourseOverGroundDeg == nil || math.Abs(*e.CourseOverGroundDeg-335.9) > 0.001 {
		t.Errorf("CourseOverGroundDeg = %v; want 335.9", e.CourseOverGroundDeg)
	}
	if e.TrueHeadingDeg != nil { // 511 sentinel = not available
		t.Errorf("TrueHeadingDeg = %v; want nil (511 sentinel)", e.TrueHeadingDeg)
	}
	if e.Timestamp != 46 {
		t.Errorf("Timestamp = %d; want 46", e.Timestamp)
	}
	if e.VesselName != "CAPT.J.RIMES" {
		t.Errorf("VesselName = %q; want CAPT.J.RIMES", e.VesselName)
	}
	if e.ShipType != 70 || !strings.Contains(e.ShipTypeName, "Cargo") {
		t.Errorf("ShipType = %d (%q); want 70 Cargo", e.ShipType, e.ShipTypeName)
	}
	if e.DimensionBow != 5 || e.DimensionStern != 21 || e.DimensionPort != 4 || e.DimensionStbd != 4 {
		t.Errorf("dims = %d/%d/%d/%d; want 5/21/4/4", e.DimensionBow, e.DimensionStern, e.DimensionPort, e.DimensionStbd)
	}
	if e.EPFDType != 1 || e.RAIM || e.DTE != 0 || e.Assigned {
		t.Errorf("epfd/raim/dte/assigned = %d/%v/%d/%v; want 1/false/0/false", e.EPFDType, e.RAIM, e.DTE, e.Assigned)
	}
}

// TestDecode_Type21_AidToNavigation pins a multi-fragment
// Aid-to-Navigation report, including the variable name-
// extension field. Oracle values cross-checked against pyais
// 3.0.1.
func TestDecode_Type21_AidToNavigation(t *testing.T) {
	// NB: the widely-circulated copy of this AtoN vector carries
	// bad NMEA checksums (*7B / *60); the XOR-correct values are
	// *79 / *62. pyais does not verify checksums, but our decoder
	// does, so the corrected suffixes are used here.
	got, err := Decode("!AIVDM,2,1,5,B,E1c2;q@b44ah4ah0h:2ab@70VRpU<Bgpm4:gP50HH`Th`QF5,0*79\n" +
		"!AIVDM,2,2,5,B,1CQ1A83PCAH0,0*62")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MessageType != 21 {
		t.Errorf("MessageType = %d; want 21", got.MessageType)
	}
	if got.MMSI != 112233445 {
		t.Errorf("MMSI = %d; want 112233445", got.MMSI)
	}
	a := got.AidToNavigation
	if a == nil {
		t.Fatal("AidToNavigation nil")
	}
	if a.AidType != 1 || !strings.Contains(a.AidTypeName, "Reference point") {
		t.Errorf("AidType = %d (%q); want 1 Reference point", a.AidType, a.AidTypeName)
	}
	if a.Name != "THIS IS A TEST NAME1" {
		t.Errorf("Name = %q; want 'THIS IS A TEST NAME1'", a.Name)
	}
	if a.NameExtension != "EXTENDED NAME" {
		t.Errorf("NameExtension = %q; want 'EXTENDED NAME'", a.NameExtension)
	}
	if a.LongitudeDeg == nil || math.Abs(*a.LongitudeDeg-145.181) > 0.001 {
		t.Errorf("LongitudeDeg = %v; want ~145.181", a.LongitudeDeg)
	}
	if a.LatitudeDeg == nil || math.Abs(*a.LatitudeDeg-(-38.220167)) > 0.001 {
		t.Errorf("LatitudeDeg = %v; want ~-38.220167", a.LatitudeDeg)
	}
	if a.DimensionBow != 5 || a.DimensionStern != 3 || a.DimensionPort != 3 || a.DimensionStbd != 5 {
		t.Errorf("dims = %d/%d/%d/%d; want 5/3/3/5", a.DimensionBow, a.DimensionStern, a.DimensionPort, a.DimensionStbd)
	}
	if a.EPFDType != 1 || a.Timestamp != 9 {
		t.Errorf("epfd/second = %d/%d; want 1/9", a.EPFDType, a.Timestamp)
	}
	if !a.OffPosition || a.RAIM || a.VirtualAid || !a.Assigned {
		t.Errorf("off/raim/virtual/assigned = %v/%v/%v/%v; want true/false/false/true",
			a.OffPosition, a.RAIM, a.VirtualAid, a.Assigned)
	}
}

// TestDecode_BadChecksum surfaces a clear error.
func TestDecode_BadChecksum(t *testing.T) {
	if _, err := Decode("!AIVDM,1,1,,A,15M67FC000G?ufbE`FepT@3n00Sa,0*FF"); err == nil {
		t.Error("bad checksum: want error")
	}
}

// TestDecode_BadPrefix rejects sentences that aren't AIVDM/AIVDO.
func TestDecode_BadPrefix(t *testing.T) {
	if _, err := Decode("$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47"); err == nil {
		t.Error("non-AIS sentence: want error")
	}
}

// TestDecode_FragmentCountMismatch rejects a 2-fragment header
// when only 1 sentence is provided.
func TestDecode_FragmentCountMismatch(t *testing.T) {
	if _, err := Decode("!AIVDM,2,1,3,A,539p4OT00000@7WSKL0LE@TltL5@F22222222220O1@F2240Ht50000000000,0*3D"); err == nil {
		t.Error("incomplete multi-fragment: want error")
	}
}

// TestDecode_FragmentIndexOutOfOrder rejects sentences arriving
// in the wrong order.
func TestDecode_FragmentIndexOutOfOrder(t *testing.T) {
	input := "!AIVDM,2,2,3,A,000000000000000,2*27\n" +
		"!AIVDM,2,1,3,A,539p4OT00000@7WSKL0LE@TltL5@F22222222220O1@F2240Ht50000000000,0*3D"
	if _, err := Decode(input); err == nil {
		t.Error("out-of-order fragments: want error")
	}
}

// TestDecode_EmptyInput rejects empty input.
func TestDecode_EmptyInput(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Error("empty input: want error")
	}
	if _, err := Decode("\n\n"); err == nil {
		t.Error("only newlines: want error")
	}
}

// TestUnpack6BitASCII_PaddingBits exercises padding-bit
// trimming.
func TestUnpack6BitASCII_PaddingBits(t *testing.T) {
	// Two chars, padding 4 → expect (12 - 4) = 8 bits.
	bits, err := unpack6BitASCII("0?", 4)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if len(bits) != 8 {
		t.Errorf("bit count = %d; want 8 (12 - 4 padding)", len(bits))
	}
}

// TestUnpack6BitASCII_InvalidChar surfaces an error on
// out-of-range chars.
func TestUnpack6BitASCII_InvalidChar(t *testing.T) {
	// 'z' (0x7A) is outside the 0x30..0x77 valid AIS range.
	if _, err := unpack6BitASCII("z", 0); err == nil {
		t.Error("char 'z': want error")
	}
}

// TestNMEAChecksum pins the XOR algorithm against the famous
// vector.
func TestNMEAChecksum(t *testing.T) {
	body := "AIVDM,1,1,,A,15M67FC000G?ufbE`FepT@3n00Sa,0"
	if got := nmeaChecksum(body); got != 0x5F {
		t.Errorf("nmeaChecksum = 0x%02X; want 0x5F", got)
	}
}

// TestMessageTypeNameTable spot-checks the documented type
// names.
func TestMessageTypeNameTable(t *testing.T) {
	cases := map[int]string{
		1:  "Position Report Class A (scheduled)",
		4:  "Base Station Report",
		5:  "Static and Voyage Related Data",
		18: "Standard Class B CS Position Report",
		21: "Aid-to-Navigation Report",
		24: "Static Data Report (Class B)",
		27: "Position Report For Long-Range Applications",
	}
	for typ, want := range cases {
		if got := messageTypeName(typ); got != want {
			t.Errorf("messageTypeName(%d) = %q; want %q", typ, got, want)
		}
	}
}

// TestNavStatusNameTable spot-checks the nav-status table.
func TestNavStatusNameTable(t *testing.T) {
	cases := map[int]string{
		0:  "Under way using engine",
		1:  "At anchor",
		5:  "Moored",
		7:  "Engaged in fishing",
		8:  "Under way sailing",
		15: "Undefined (default)",
	}
	for s, want := range cases {
		if got := navStatusName(s); got != want {
			t.Errorf("navStatusName(%d) = %q; want %q", s, got, want)
		}
	}
}

// TestShipTypeNameTable spot-checks the ship-type lookup.
func TestShipTypeNameTable(t *testing.T) {
	cases := map[int]string{
		0:  "Not available",
		30: "Fishing",
		36: "Sailing",
		51: "Search and Rescue vessel",
		60: "Passenger",
		70: "Cargo",
		80: "Tanker",
	}
	for s, want := range cases {
		if got := shipTypeName(s); got != want {
			t.Errorf("shipTypeName(%d) = %q; want %q", s, got, want)
		}
	}
}

// TestEPFDNameTable spot-checks the EPFD lookup.
func TestEPFDNameTable(t *testing.T) {
	cases := map[int]string{
		1:  "GPS",
		2:  "GLONASS",
		3:  "Combined GPS/GLONASS",
		8:  "Galileo",
		15: "Internal GNSS",
	}
	for e, want := range cases {
		if got := epfdName(e); got != want {
			t.Errorf("epfdName(%d) = %q; want %q", e, got, want)
		}
	}
}
