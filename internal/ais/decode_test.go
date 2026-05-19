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
