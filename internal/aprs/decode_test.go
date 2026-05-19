package aprs

import (
	"math"
	"strings"
	"testing"
)

// TestDecode_TNC2_PositionNoTimestamp pins the canonical
// APRS101 example: a position-without-timestamp report.
//
//	K1ABC-9>APRS,WIDE2-1:!4903.50N/07201.75W>South of Ottawa
func TestDecode_TNC2_PositionNoTimestamp(t *testing.T) {
	got, err := Decode("K1ABC-9>APRS,WIDE2-1:!4903.50N/07201.75W>South of Ottawa")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Source.Callsign != "K1ABC" {
		t.Errorf("Source.Callsign = %q", got.Source.Callsign)
	}
	if got.Source.SSID != 9 {
		t.Errorf("Source.SSID = %d; want 9", got.Source.SSID)
	}
	if got.Destination.Callsign != "APRS" {
		t.Errorf("Destination.Callsign = %q", got.Destination.Callsign)
	}
	if len(got.Path) != 1 {
		t.Fatalf("Path count = %d; want 1", len(got.Path))
	}
	if got.Path[0].Callsign != "WIDE2" || got.Path[0].SSID != 1 {
		t.Errorf("Path[0] = %+v", got.Path[0])
	}
	if got.InfoType != "!" {
		t.Errorf("InfoType = %q", got.InfoType)
	}
	if got.Position == nil {
		t.Fatal("Position nil")
	}
	if math.Abs(got.Position.LatitudeDeg-49.05833) > 0.0001 {
		t.Errorf("LatitudeDeg = %f; want ~49.05833 (49°03.50'N)", got.Position.LatitudeDeg)
	}
	// 72°01.75'W → -(72 + 1.75/60) = -72.02917
	if math.Abs(got.Position.LongitudeDeg-(-72.02917)) > 0.0001 {
		t.Errorf("LongitudeDeg = %f; want ~-72.02917 (72°01.75'W)", got.Position.LongitudeDeg)
	}
	if got.Position.SymbolTable != "/" {
		t.Errorf("SymbolTable = %q; want '/'", got.Position.SymbolTable)
	}
	if got.Position.SymbolCode != ">" {
		t.Errorf("SymbolCode = %q; want '>' (car)", got.Position.SymbolCode)
	}
	if got.Position.SymbolName != "Car" {
		t.Errorf("SymbolName = %q; want 'Car'", got.Position.SymbolName)
	}
	if got.Comment != "South of Ottawa" {
		t.Errorf("Comment = %q", got.Comment)
	}
}

// TestDecode_TNC2_PositionWithTimestamp covers the '@' info
// prefix (position with timestamp).
func TestDecode_TNC2_PositionWithTimestamp(t *testing.T) {
	got, err := Decode("K1ABC>APRS,WIDE1-1:@092345z4903.50N/07201.75W>Test")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.InfoType != "@" {
		t.Errorf("InfoType = %q", got.InfoType)
	}
	if got.Position == nil {
		t.Fatal("Position nil")
	}
	if got.Position.Timestamp != "092345z" {
		t.Errorf("Timestamp = %q", got.Position.Timestamp)
	}
}

// TestDecode_TNC2_StatusReport pins a '>' status report.
func TestDecode_TNC2_StatusReport(t *testing.T) {
	got, err := Decode("K1ABC>APRS:>Net at 9pm")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.InfoType != ">" {
		t.Errorf("InfoType = %q", got.InfoType)
	}
	if got.Status != "Net at 9pm" {
		t.Errorf("Status = %q", got.Status)
	}
}

// TestDecode_TNC2_Message pins the ':' message format with
// addressee + body + message number.
func TestDecode_TNC2_Message(t *testing.T) {
	got, err := Decode("K1ABC>APRS::N0CALL   :Hello world{12345")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.InfoType != ":" {
		t.Errorf("InfoType = %q", got.InfoType)
	}
	if got.Message == nil {
		t.Fatal("Message nil")
	}
	if got.Message.Addressee != "N0CALL" {
		t.Errorf("Addressee = %q", got.Message.Addressee)
	}
	if got.Message.Body != "Hello world" {
		t.Errorf("Body = %q", got.Message.Body)
	}
	if got.Message.MessageNumber != "12345" {
		t.Errorf("MessageNumber = %q", got.Message.MessageNumber)
	}
}

// TestDecode_TNC2_PHGExtension pins the PHG antenna profile
// extension immediately after a position.
func TestDecode_TNC2_PHGExtension(t *testing.T) {
	// Power code 3 → 9 W; Height code 6 → 10×2^6 = 640 ft;
	// Gain 4 dBi; Directivity code 0 → Omnidirectional.
	got, err := Decode("K1ABC>APRS:=4903.50N/07201.75W#PHG3640Test station")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.PHG == nil {
		t.Fatal("PHG nil")
	}
	if got.PHG.PowerW != 9 {
		t.Errorf("PowerW = %d; want 9 (3²)", got.PHG.PowerW)
	}
	if got.PHG.HeightFt != 640 {
		t.Errorf("HeightFt = %d; want 640", got.PHG.HeightFt)
	}
	if got.PHG.GainDBi != 4 {
		t.Errorf("GainDBi = %d; want 4", got.PHG.GainDBi)
	}
	if got.PHG.Directivity != "Omnidirectional" {
		t.Errorf("Directivity = %q", got.PHG.Directivity)
	}
	if got.Comment != "Test station" {
		t.Errorf("Comment = %q (PHG should be stripped)", got.Comment)
	}
}

// TestDecode_TNC2_Telemetry pins a basic 'T#nnn,...' frame.
func TestDecode_TNC2_Telemetry(t *testing.T) {
	got, err := Decode("K1ABC>APRS:T#123,100,200,300,400,500,11001100")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Telemetry == nil {
		t.Fatal("Telemetry nil")
	}
	if got.Telemetry.SequenceNumber != 123 {
		t.Errorf("SequenceNumber = %d", got.Telemetry.SequenceNumber)
	}
	if len(got.Telemetry.Analog) != 5 {
		t.Fatalf("Analog count = %d; want 5", len(got.Telemetry.Analog))
	}
	want := []float64{100, 200, 300, 400, 500}
	for i, v := range want {
		if got.Telemetry.Analog[i] != v {
			t.Errorf("Analog[%d] = %f; want %f", i, got.Telemetry.Analog[i], v)
		}
	}
	if got.Telemetry.DigitalBits != "11001100" {
		t.Errorf("DigitalBits = %q", got.Telemetry.DigitalBits)
	}
}

// TestDecode_TNC2_DigipeatedFlag exercises the '*' suffix on
// path entries.
func TestDecode_TNC2_DigipeatedFlag(t *testing.T) {
	got, err := Decode("K1ABC>APRS,WIDE1-1*,WIDE2-1:>Test")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.Path[0].Digipeated {
		t.Error("Path[0].Digipeated = false; want true (asterisked)")
	}
	if got.Path[1].Digipeated {
		t.Error("Path[1].Digipeated = true; want false (no asterisk)")
	}
}

// TestDecode_AX25Hex pins a hand-crafted AX.25 UI frame with
// addresses, control byte 0x03, PID 0xF0, and an info field.
func TestDecode_AX25Hex(t *testing.T) {
	// Build manually:
	//   dest = "APRS  " SSID 0 (not last)
	//   src  = "K1ABC " SSID 9 (last)
	//   control = 0x03
	//   PID = 0xF0
	//   info = ">Test status"
	frame := buildAX25Frame(t, "APRS", 0, "K1ABC", 9, ">Test status")
	got, err := DecodeAX25Bytes(frame)
	if err != nil {
		t.Fatalf("DecodeAX25Bytes: %v", err)
	}
	if got.Destination.Callsign != "APRS" {
		t.Errorf("Destination.Callsign = %q", got.Destination.Callsign)
	}
	if got.Source.Callsign != "K1ABC" {
		t.Errorf("Source.Callsign = %q", got.Source.Callsign)
	}
	if got.Source.SSID != 9 {
		t.Errorf("Source.SSID = %d; want 9", got.Source.SSID)
	}
	if got.InfoType != ">" {
		t.Errorf("InfoType = %q", got.InfoType)
	}
	if got.Status != "Test status" {
		t.Errorf("Status = %q", got.Status)
	}
}

// TestDecode_AX25Hex_NotUIFrame rejects frames with a control
// byte != 0x03.
func TestDecode_AX25Hex_NotUIFrame(t *testing.T) {
	frame := buildAX25Frame(t, "APRS", 0, "K1ABC", 0, ">x")
	frame[14] = 0x73 // arbitrary non-UI control
	if _, err := DecodeAX25Bytes(frame); err == nil {
		t.Error("non-UI frame: want error")
	}
}

// TestDecode_BadTNC2 rejects malformed envelopes.
func TestDecode_BadTNC2(t *testing.T) {
	cases := []string{
		"",
		"NOENVELOPE",
		":no source>nor path",
	}
	for _, c := range cases {
		if _, err := Decode(c); err == nil {
			t.Errorf("input %q: want error", c)
		}
	}
}

// TestDecode_TNC2_LatLonAmbiguity exercises the spec's space
// padding in the minute field (used to indicate position
// ambiguity to the nearest 10/100/1000 m).
func TestDecode_TNC2_LatLonAmbiguity(t *testing.T) {
	// "4903.5 N" with the trailing space indicates ±100m
	// ambiguity per APRS101 §8.1.1.
	got, err := Decode("K1ABC>APRS:!4903.5 N/07201.75W>Ambiguous")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Position == nil {
		t.Fatal("Position nil")
	}
	// Spaces become 0s for our decode; lat should still parse.
	if got.Position.LatitudeDeg == 0 {
		t.Error("LatitudeDeg should be non-zero even with space padding")
	}
}

// TestInfoTypeNameTable spot-checks the info-type-name table.
func TestInfoTypeNameTable(t *testing.T) {
	cases := map[string]string{
		"!": "Position without timestamp (no APRS messaging)",
		"=": "Position without timestamp (with APRS messaging)",
		"@": "Position with timestamp (with APRS messaging)",
		":": "Message",
		">": "Status report",
		"T": "Telemetry",
		";": "Object",
		")": "Item",
	}
	for prefix, want := range cases {
		if got := infoTypeName(prefix); got != want {
			t.Errorf("infoTypeName(%q) = %q; want %q", prefix, got, want)
		}
	}
}

// TestSymbolName covers a few well-known primary + alternate
// symbol mappings.
func TestSymbolName(t *testing.T) {
	cases := []struct {
		table, code, want string
	}{
		{"/", ">", "Car"},
		{"/", "-", "House (QTH)"},
		{"/", "Y", "Yacht (sailboat)"},
		{"\\", "_", "Weather station"},
		{"\\", "h", "Hospital"},
		{"\\", "f", "Fire engine"},
	}
	for _, c := range cases {
		if got := symbolName(c.table, c.code); got != c.want {
			t.Errorf("symbolName(%q, %q) = %q; want %q", c.table, c.code, got, c.want)
		}
	}
}

// TestPHG_DirectivityTable spot-checks the directivity codes.
func TestPHG_DirectivityTable(t *testing.T) {
	if phgDirectivity(0) != "Omnidirectional" {
		t.Errorf("0 = %q", phgDirectivity(0))
	}
	if phgDirectivity(1) != "45°" {
		t.Errorf("1 = %q", phgDirectivity(1))
	}
	if phgDirectivity(8) != "360°" {
		t.Errorf("8 = %q", phgDirectivity(8))
	}
}

// buildAX25Frame is a test helper that constructs a UI-frame
// byte slice with the given destination, source, and info.
// All addresses are emitted with the H-bit clear (not yet
// digipeated). Source is marked as the last address.
func buildAX25Frame(t *testing.T, dest string, destSSID int, src string, srcSSID int, info string) []byte {
	t.Helper()
	encode := func(callsign string, ssid int, last bool) []byte {
		buf := make([]byte, 7)
		padded := callsign + strings.Repeat(" ", 6)
		for i := 0; i < 6; i++ {
			buf[i] = padded[i] << 1
		}
		ssidByte := byte(ssid&0x0F) << 1
		ssidByte |= 0x60 // R-bits set per AX.25 §3.12.3
		if last {
			ssidByte |= 0x01
		}
		buf[6] = ssidByte
		return buf
	}
	out := make([]byte, 0, 7+7+2+len(info))
	out = append(out, encode(dest, destSSID, false)...)
	out = append(out, encode(src, srcSSID, true)...)
	out = append(out, 0x03, 0xF0)
	out = append(out, []byte(info)...)
	return out
}
