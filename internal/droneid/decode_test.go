package droneid

import (
	"strings"
	"testing"
)

// TestDecode_BasicID pins a Basic ID message (type 0x0) with
// ID type = Serial Number (1) and UA type = Helicopter (2).
func TestDecode_BasicID(t *testing.T) {
	// header=0x02 (type=0, pv=2), tag=(idType=1<<4 | uaType=2)=0x12,
	// UAS ID = "1581F4DKE000000000" (18 chars + 2 null pad)
	got, err := Decode("0212313538314634444B453030303030303030300000000000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Type != 0 {
		t.Errorf("Type = %d; want 0", got.Type)
	}
	if got.TypeName != "Basic ID" {
		t.Errorf("TypeName = %q", got.TypeName)
	}
	if got.ProtocolVersion != 2 {
		t.Errorf("ProtocolVersion = %d", got.ProtocolVersion)
	}
	if got.BasicID == nil {
		t.Fatal("BasicID nil")
	}
	if got.BasicID.IDType != 1 {
		t.Errorf("IDType = %d; want 1", got.BasicID.IDType)
	}
	if !strings.Contains(got.BasicID.IDName, "Serial Number") {
		t.Errorf("IDName = %q", got.BasicID.IDName)
	}
	if got.BasicID.UAType != 2 {
		t.Errorf("UAType = %d; want 2", got.BasicID.UAType)
	}
	if !strings.Contains(got.BasicID.UAName, "Helicopter") {
		t.Errorf("UAName = %q", got.BasicID.UAName)
	}
	if got.BasicID.UASID != "1581F4DKE000000000" {
		t.Errorf("UASID = %q", got.BasicID.UASID)
	}
}

// TestDecode_Location pins a Location/Vector message (type 0x1)
// with hand-crafted lat 47.77728°, lon 7.671024°, altitude 100 m,
// AGL 50 m, ground speed 20 m/s on track 042°.
func TestDecode_Location(t *testing.T) {
	got, err := Decode("12202A500A003C7A1C60819204980898083408235439300700")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Type != 1 {
		t.Errorf("Type = %d; want 1", got.Type)
	}
	if got.Location == nil {
		t.Fatal("Location nil")
	}
	loc := got.Location
	if loc.Status != 2 {
		t.Errorf("Status = %d; want 2 (Airborne)", loc.Status)
	}
	if loc.StatusName != "Airborne" {
		t.Errorf("StatusName = %q", loc.StatusName)
	}
	if loc.HeightType != "AGL / takeoff" {
		t.Errorf("HeightType = %q", loc.HeightType)
	}
	if loc.TrackDirectionDeg != 42 {
		t.Errorf("TrackDirectionDeg = %d; want 42", loc.TrackDirectionDeg)
	}
	if loc.SpeedMS != 20.0 {
		t.Errorf("SpeedMS = %f; want 20.0", loc.SpeedMS)
	}
	if loc.VerticalSpeedMS != 5.0 {
		t.Errorf("VerticalSpeedMS = %f; want 5.0", loc.VerticalSpeedMS)
	}
	if loc.LatitudeDeg != 47.77728 {
		t.Errorf("LatitudeDeg = %f; want 47.77728", loc.LatitudeDeg)
	}
	if loc.LongitudeDeg != 7.671024 {
		t.Errorf("LongitudeDeg = %f; want 7.671024", loc.LongitudeDeg)
	}
	if loc.PressureAltitudeM != 100.0 {
		t.Errorf("PressureAltitudeM = %f; want 100.0", loc.PressureAltitudeM)
	}
	if loc.GeodeticAltitudeM != 100.0 {
		t.Errorf("GeodeticAltitudeM = %f; want 100.0", loc.GeodeticAltitudeM)
	}
	if loc.HeightAGLM != 50.0 {
		t.Errorf("HeightAGLM = %f; want 50.0", loc.HeightAGLM)
	}
	if loc.HorizontalAccuracy != 3 {
		t.Errorf("HorizontalAccuracy = %d; want 3", loc.HorizontalAccuracy)
	}
	if loc.VerticalAccuracy != 2 {
		t.Errorf("VerticalAccuracy = %d; want 2", loc.VerticalAccuracy)
	}
	if loc.BaroAltitudeAccuracy != 5 {
		t.Errorf("BaroAltitudeAccuracy = %d; want 5", loc.BaroAltitudeAccuracy)
	}
	if loc.SpeedAccuracy != 4 {
		t.Errorf("SpeedAccuracy = %d; want 4", loc.SpeedAccuracy)
	}
	if loc.Timestamp1_10Sec != 12345 {
		t.Errorf("Timestamp1_10Sec = %d; want 12345", loc.Timestamp1_10Sec)
	}
	if loc.TimestampAccuracyTenths != 7 {
		t.Errorf("TimestampAccuracyTenths = %d; want 7", loc.TimestampAccuracyTenths)
	}
}

// TestDecode_Location_EWBitFlipsTrack verifies that the East/
// West direction segment bit adds 180° to the track field.
func TestDecode_Location_EWBitFlipsTrack(t *testing.T) {
	// Same as Location test but with EW bit set (byte1 |= 0x02).
	// byte1 was 0x20, becomes 0x22. Track byte still 42 → 42+180=222.
	got, err := Decode("12222A500A003C7A1C60819204980898083408235439300700")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Location.TrackDirectionDeg != 222 {
		t.Errorf("TrackDirectionDeg = %d; want 222 (42 + 180)", got.Location.TrackDirectionDeg)
	}
}

// TestDecode_Location_HighSpeedMultiplier verifies the
// speed-multiplier-1 encoding (raw × 0.75 + 63.75).
func TestDecode_Location_HighSpeedMultiplier(t *testing.T) {
	// Set byte1's bit 0 (speedMult=1). 0x20 → 0x21.
	// raw byte 3 = 80; expected speed = 80×0.75 + 63.75 = 60 + 63.75 = 123.75 m/s
	got, err := Decode("12212A500A003C7A1C60819204980898083408235439300700")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Location.SpeedMS != 123.75 {
		t.Errorf("SpeedMS = %f; want 123.75 (high-speed encoding)", got.Location.SpeedMS)
	}
}

// TestDecode_SelfID pins a Self-ID message (type 0x3) with a
// short free-text description.
func TestDecode_SelfID(t *testing.T) {
	got, err := Decode("32005465737420666C69676874206F766572206669656C6400")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Type != 3 {
		t.Errorf("Type = %d; want 3", got.Type)
	}
	if got.SelfID == nil {
		t.Fatal("SelfID nil")
	}
	if got.SelfID.DescriptionType != 0 {
		t.Errorf("DescriptionType = %d", got.SelfID.DescriptionType)
	}
	if got.SelfID.Description != "Test flight over field" {
		t.Errorf("Description = %q", got.SelfID.Description)
	}
}

// TestDecode_OperatorID pins an Operator ID message (type 0x5).
func TestDecode_OperatorID(t *testing.T) {
	got, err := Decode("5200464133484B333941345100000000000000000000000000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Type != 5 {
		t.Errorf("Type = %d; want 5", got.Type)
	}
	if got.OperatorID == nil {
		t.Fatal("OperatorID nil")
	}
	if got.OperatorID.IDType != 0 {
		t.Errorf("IDType = %d", got.OperatorID.IDType)
	}
	if got.OperatorID.ID != "FA3HK39A4Q" {
		t.Errorf("ID = %q", got.OperatorID.ID)
	}
}

// TestDecode_System pins a System message (type 0x4) with EU
// classification + Dynamic operator location source + Class 1
// drone + swarm area dimensions + system timestamp.
func TestDecode_System(t *testing.T) {
	got, err := Decode("420540427A1CA87F92040100326009D00712FC0840E2010000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Type != 4 {
		t.Errorf("Type = %d; want 4", got.Type)
	}
	if got.System == nil {
		t.Fatal("System nil")
	}
	s := got.System
	if s.OperatorLocationSource != 1 {
		t.Errorf("OperatorLocationSource = %d; want 1 (Dynamic)", s.OperatorLocationSource)
	}
	if !strings.Contains(s.OperatorLocationName, "Dynamic") {
		t.Errorf("OperatorLocationName = %q", s.OperatorLocationName)
	}
	if s.ClassificationRegion != 1 {
		t.Errorf("ClassificationRegion = %d; want 1 (EU)", s.ClassificationRegion)
	}
	if s.OperatorLatDeg != 47.77744 {
		t.Errorf("OperatorLatDeg = %f; want 47.77744", s.OperatorLatDeg)
	}
	if s.OperatorLonDeg != 7.67098 {
		t.Errorf("OperatorLonDeg = %f; want 7.67098", s.OperatorLonDeg)
	}
	if s.AreaCount != 1 {
		t.Errorf("AreaCount = %d", s.AreaCount)
	}
	if s.AreaRadiusM != 500 {
		t.Errorf("AreaRadiusM = %d; want 500", s.AreaRadiusM)
	}
	if s.AreaCeilingM != 200.0 {
		t.Errorf("AreaCeilingM = %f; want 200.0", s.AreaCeilingM)
	}
	if s.AreaFloorM != 0.0 {
		t.Errorf("AreaFloorM = %f; want 0.0", s.AreaFloorM)
	}
	if s.UACategory != 1 {
		t.Errorf("UACategory = %d; want 1 (EU)", s.UACategory)
	}
	if s.UAClass != 2 {
		t.Errorf("UAClass = %d; want 2 (EU Class 1)", s.UAClass)
	}
	if !strings.Contains(s.UAClassName, "EU Class 1") {
		t.Errorf("UAClassName = %q", s.UAClassName)
	}
	if s.OperatorAltitudeM != 150.0 {
		t.Errorf("OperatorAltitudeM = %f; want 150.0", s.OperatorAltitudeM)
	}
	// SystemTimestamp raw = 123456; +1546300800 epoch = 1546424256
	if s.SystemTimestampUnix != 1546424256 {
		t.Errorf("SystemTimestampUnix = %d; want 1546424256", s.SystemTimestampUnix)
	}
}

// TestDecode_MessagePack pins a Message Pack (type 0xF) bundle
// containing 2 messages: a Basic ID + a Location.
func TestDecode_MessagePack(t *testing.T) {
	// Header (0xF2) + msgSize (0x19=25) + count (0x02) + Basic ID + Location
	hex := "F2" + "1902" +
		"0212313538314634444B453030303030303030300000000000" +
		"12202A500A003C7A1C60819204980898083408235439300700"
	got, err := Decode(hex)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Type != 0xF {
		t.Errorf("Type = %d; want 0xF", got.Type)
	}
	if got.Pack == nil {
		t.Fatal("Pack nil")
	}
	if got.Pack.MessageSize != 25 {
		t.Errorf("MessageSize = %d; want 25", got.Pack.MessageSize)
	}
	if got.Pack.MessageCount != 2 {
		t.Errorf("MessageCount = %d; want 2", got.Pack.MessageCount)
	}
	if len(got.Pack.Messages) != 2 {
		t.Fatalf("Messages count = %d; want 2", len(got.Pack.Messages))
	}
	if got.Pack.Messages[0].BasicID == nil {
		t.Error("Messages[0] should be a Basic ID")
	}
	if got.Pack.Messages[1].Location == nil {
		t.Error("Messages[1] should be a Location")
	}
}

// TestDecode_MessagePack_BadCount rejects message counts outside
// the 1..9 spec range.
func TestDecode_MessagePack_BadCount(t *testing.T) {
	// count=0 (invalid)
	if _, err := Decode("F2" + "1900"); err == nil {
		t.Error("count=0: want error")
	}
}

// TestDecode_MessagePack_LengthMismatch surfaces a clear error
// when the buffer length doesn't match the declared count.
func TestDecode_MessagePack_LengthMismatch(t *testing.T) {
	// count=2 declared, but only 1 message of payload follows
	hex := "F21902" + "0212313538314634444B453030303030303030300000000000"
	if _, err := Decode(hex); err == nil {
		t.Error("count vs length mismatch: want error")
	}
}

// TestDecode_BadLength rejects non-25-byte single messages.
func TestDecode_BadLength(t *testing.T) {
	if _, err := Decode("0212"); err == nil {
		t.Error("3-byte input: want error")
	}
}

// TestDecode_BadHex rejects garbage hex input.
func TestDecode_BadHex(t *testing.T) {
	if _, err := Decode("ZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
	if _, err := Decode(""); err == nil {
		t.Error("empty: want error")
	}
}

// TestDecode_Authentication labels the type but does not decode
// the variable-length body (deliberately out of scope).
func TestDecode_Authentication(t *testing.T) {
	// 25-byte frame, type=2
	got, err := Decode("22" + strings.Repeat("00", 24))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Type != 2 {
		t.Errorf("Type = %d", got.Type)
	}
	if got.TypeName != "Authentication" {
		t.Errorf("TypeName = %q", got.TypeName)
	}
	// All sub-pointers should be nil (no body decoder for
	// Authentication in this iteration).
	if got.BasicID != nil || got.Location != nil || got.SelfID != nil ||
		got.System != nil || got.OperatorID != nil || got.Pack != nil {
		t.Error("Authentication should leave all sub-pointers nil")
	}
}

// TestDecode_Separators tolerates :, -, _, and whitespace.
func TestDecode_Separators(t *testing.T) {
	got, err := Decode("02:12:31:35:38:31 46-34 44_4B 45 30 30 30 30 30 30 30 30 30 00 00 00 00 00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.BasicID == nil {
		t.Fatal("BasicID nil after separator strip")
	}
}

// TestUAClassName_NonEU returns a non-EU label rather than
// claiming a Cn class for an undeclared region.
func TestUAClassName_NonEU(t *testing.T) {
	if got := uaClassName(0, 2); got != "Class 2 (non-EU; reserved)" {
		t.Errorf("uaClassName(0, 2) = %q", got)
	}
	if got := uaClassName(0, 0); got != "Undeclared" {
		t.Errorf("uaClassName(0, 0) = %q", got)
	}
}

// TestMessageTypeNameTable spot-checks the message-type table.
func TestMessageTypeNameTable(t *testing.T) {
	cases := map[int]string{
		0x0: "Basic ID",
		0x1: "Location / Vector",
		0x2: "Authentication",
		0x3: "Self ID",
		0x4: "System",
		0x5: "Operator ID",
		0xF: "Message Pack",
	}
	for typ, want := range cases {
		if got := messageTypeName(typ); got != want {
			t.Errorf("messageTypeName(0x%X) = %q; want %q", typ, got, want)
		}
	}
}
