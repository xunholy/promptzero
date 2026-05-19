package adsb

import (
	"strings"
	"testing"
)

// TestDecode_KLM1023_AircraftIdentification pins the canonical
// MIT-textbook DF17 example: an Aircraft Identification message
// from KLM1023 (callsign decode + emitter category + ICAO).
//
//	8D 4840D6 20 2CC371 C32CE0 576098
//	└┬┘ └─┬──┘ └─┬─────────────────┘ └─┬──┘
//	 DF/CA ICAO  ME (TC=4, ID)         PI
func TestDecode_KLM1023_AircraftIdentification(t *testing.T) {
	got, err := Decode("8D4840D6202CC371C32CE0576098")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.DF != 17 {
		t.Errorf("DF = %d; want 17", got.DF)
	}
	if got.DFName != "Extended Squitter (ADS-B)" {
		t.Errorf("DFName = %q", got.DFName)
	}
	if got.ICAOAddress != "4840D6" {
		t.Errorf("ICAOAddress = %q; want '4840D6'", got.ICAOAddress)
	}
	if got.CRC != "576098" {
		t.Errorf("CRC = %q; want '576098'", got.CRC)
	}
	if got.CRCExpected != "576098" {
		t.Errorf("CRCExpected = %q; want '576098'", got.CRCExpected)
	}
	if !got.CRCValid {
		t.Error("CRCValid = false; want true (known-good textbook frame)")
	}
	if got.ADSB == nil {
		t.Fatal("ADSB nil")
	}
	if got.ADSB.TC != 4 {
		t.Errorf("TC = %d; want 4", got.ADSB.TC)
	}
	if got.ADSB.Identification == nil {
		t.Fatal("Identification nil")
	}
	if got.ADSB.Identification.Callsign != "KLM1023" {
		t.Errorf("Callsign = %q; want 'KLM1023'", got.ADSB.Identification.Callsign)
	}
}

// TestDecode_AirbornePosition pins a known DF17 TC=11 (airborne
// position, barometric altitude) frame from MIT material.
//
//	8D 40621D 58 C382D6 90C8AC 2863A7
//	      └─┬┘  └ ME ── ──────┘ └─PI─┘
//	      ICAO   TC=11
func TestDecode_AirbornePosition(t *testing.T) {
	got, err := Decode("8D40621D58C382D690C8AC2863A7")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.DF != 17 {
		t.Errorf("DF = %d", got.DF)
	}
	if got.ICAOAddress != "40621D" {
		t.Errorf("ICAOAddress = %q", got.ICAOAddress)
	}
	if !got.CRCValid {
		t.Errorf("CRCValid = false; expected %s, got %s", got.CRCExpected, got.CRC)
	}
	if got.ADSB == nil || got.ADSB.AirbornePosition == nil {
		t.Fatal("AirbornePosition nil")
	}
	ap := got.ADSB.AirbornePosition
	if got.ADSB.TC != 11 {
		t.Errorf("TC = %d; want 11", got.ADSB.TC)
	}
	if ap.AltitudeSource != "barometric" {
		t.Errorf("AltitudeSource = %q", ap.AltitudeSource)
	}
	if !ap.AltitudeValid {
		t.Error("AltitudeValid = false; want true (Q=1 frame)")
	}
	// MIT material decodes this frame's altitude as 38000 ft.
	if ap.AltitudeFt != 38000 {
		t.Errorf("AltitudeFt = %d; want 38000", ap.AltitudeFt)
	}
	// CPR Format: this frame is documented as even-encoded.
	if ap.CPRFormat != 0 {
		t.Errorf("CPRFormat = %d; want 0 (even frame)", ap.CPRFormat)
	}
}

// TestDecode_AirborneVelocity pins the MIT textbook TC=19
// Airborne Velocity frame (ground-speed subtype).
//
//	8D 485020 99 4409 9408 3817 5B284F
//	      ICAO  TC=19+subtype=1
func TestDecode_AirborneVelocity(t *testing.T) {
	got, err := Decode("8D485020994409940838175B284F")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.CRCValid {
		t.Errorf("CRCValid = false; expected %s, got %s", got.CRCExpected, got.CRC)
	}
	if got.ADSB == nil || got.ADSB.AirborneVelocity == nil {
		t.Fatal("AirborneVelocity nil")
	}
	av := got.ADSB.AirborneVelocity
	if av.Subtype != 1 {
		t.Errorf("Subtype = %d; want 1", av.Subtype)
	}
	if av.SubtypeName != "Ground speed, normal" {
		t.Errorf("SubtypeName = %q", av.SubtypeName)
	}
	if av.GroundSpeedKts == nil {
		t.Fatal("GroundSpeedKts nil")
	}
	// MIT material decodes ground speed as 159 kts.
	if *av.GroundSpeedKts != 159 {
		t.Errorf("GroundSpeedKts = %d; want 159", *av.GroundSpeedKts)
	}
	if av.GroundTrackDeg == nil {
		t.Fatal("GroundTrackDeg nil")
	}
	// Ground track ~182.88° per MIT material.
	if *av.GroundTrackDeg < 182.5 || *av.GroundTrackDeg > 183.5 {
		t.Errorf("GroundTrackDeg = %f; want ~182.88", *av.GroundTrackDeg)
	}
	if av.VerticalRateSource != "barometric" {
		t.Errorf("VerticalRateSource = %q; want 'barometric'", av.VerticalRateSource)
	}
	// MIT material: vertical rate = -832 fpm (descending).
	if av.VerticalRateFPM != -832 {
		t.Errorf("VerticalRateFPM = %d; want -832", av.VerticalRateFPM)
	}
}

// TestDecode_CRCInvalid surfaces CRCValid=false when the last 3
// bytes don't match the computed parity.
func TestDecode_CRCInvalid(t *testing.T) {
	// Same as KLM frame but with parity bytes mangled.
	got, err := Decode("8D4840D6202CC371C32CE0AAAAAA")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.CRCValid {
		t.Error("CRCValid = true; want false for bogus PI")
	}
	if got.CRC != "AAAAAA" {
		t.Errorf("CRC = %q", got.CRC)
	}
	if got.CRCExpected != "576098" {
		t.Errorf("CRCExpected = %q; want '576098'", got.CRCExpected)
	}
}

// TestDecode_DFNameTable exercises all of the operationally
// relevant DF codes and their canonical names.
func TestDecode_DFNameTable(t *testing.T) {
	cases := map[int]string{
		0:  "Short Air-Air Surveillance",
		4:  "Surveillance, Altitude Reply",
		5:  "Surveillance, Identity Reply",
		11: "All-Call Reply",
		16: "Long Air-Air Surveillance",
		17: "Extended Squitter (ADS-B)",
		18: "Extended Squitter / Non-Transponder (TIS-B / ADS-R)",
		19: "Military Extended Squitter",
		20: "Comm-B, Altitude Reply",
		21: "Comm-B, Identity Reply",
		24: "Comm-D Extended Length Message",
	}
	for df, want := range cases {
		if got := dfName(df); got != want {
			t.Errorf("dfName(%d) = %q; want %q", df, got, want)
		}
	}
}

// TestDecode_ShortFrameDF11 exercises the 56-bit short-frame
// path. The CRC byte is computed by this implementation; we
// pin the round trip end-to-end.
func TestDecode_ShortFrameDF11(t *testing.T) {
	// DF=11 (0x58 >> 3 = 11), CA=0, ICAO = AA BB CC, then 3-byte
	// computed CRC. Build the bytes, compute the expected CRC,
	// append it, and round-trip.
	data := []byte{0x58, 0xAA, 0xBB, 0xCC}
	// 56-bit frame = 7 bytes; need 3-byte parity to compute the
	// expected CRC over.
	full := make([]byte, 7)
	copy(full, data)
	// Compute parity assuming current parity = 0
	expected := computeCRC(full)
	full[4] = byte(expected >> 16)
	full[5] = byte(expected >> 8)
	full[6] = byte(expected)
	got, err := DecodeBytes(full)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	if got.DF != 11 {
		t.Errorf("DF = %d; want 11", got.DF)
	}
	if got.BitCount != 56 {
		t.Errorf("BitCount = %d; want 56", got.BitCount)
	}
	if got.ICAOAddress != "AABBCC" {
		t.Errorf("ICAOAddress = %q", got.ICAOAddress)
	}
	if !got.CRCValid {
		t.Errorf("CRCValid = false; expected %s, got %s", got.CRCExpected, got.CRC)
	}
	if got.ADSB != nil {
		t.Error("ADSB should be nil on a DF11 frame")
	}
}

// TestDecode_HexPrefix tolerates a leading '0x'.
func TestDecode_HexPrefix(t *testing.T) {
	got, err := Decode("0x8D4840D6202CC371C32CE0576098")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.DF != 17 {
		t.Errorf("DF = %d", got.DF)
	}
}

// TestDecode_Separators tolerates :, -, _, and whitespace.
func TestDecode_Separators(t *testing.T) {
	got, err := Decode("8D:48:40:D6 20-2C_C3 71 C3 2C E0 57 60 98")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.CRCValid {
		t.Error("CRCValid = false")
	}
}

// TestDecode_BadLength rejects frames that are neither 7 nor
// 14 bytes long.
func TestDecode_BadLength(t *testing.T) {
	if _, err := Decode("8D4840D6"); err == nil {
		t.Error("4-byte input: want error")
	}
	if _, err := Decode("8D4840D6202CC371C32CE0576098FF"); err == nil {
		t.Error("15-byte input: want error")
	}
}

// TestDecode_BadDFLengthMismatch — a short-DF (11) frame given
// at long-frame length should be rejected.
func TestDecode_BadDFLengthMismatch(t *testing.T) {
	// 14-byte frame whose DF computes to 11 (short)
	if _, err := Decode("58AABBCC0000000000000000FFFF"); err == nil {
		t.Error("DF11 frame at 14 bytes: want error")
	}
}

// TestDecode_BadHex rejects garbage input.
func TestDecode_BadHex(t *testing.T) {
	if _, err := Decode("ZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
	if _, err := Decode(""); err == nil {
		t.Error("empty: want error")
	}
}

// TestCallsignDecode_SpaceTrimmed exercises the AIS-alphabet
// decoder for a callsign with trailing space padding.
func TestCallsignDecode_SpaceTrimmed(t *testing.T) {
	// Build a TC=1 (ID) message: TC=1 → first byte = 0x08 | cat
	// We craft "TEST  " (4 chars + 4 spaces).
	// 6-bit values: T=20, E=5, S=19, T=20, space=32, space=32, space=32, space=32
	// Pack into 8 bytes of ME (the 7-byte ME contains 48 bits
	// of callsign packed into the trailing 6 bytes; bit 1-5 = TC,
	// bit 6-8 = category, bits 9-56 = callsign).
	me := make([]byte, 7)
	// TC=4, category=1 -> me[0] = (4<<3) | 1 = 0x21
	me[0] = 0x21
	chars := []byte{20, 5, 19, 20, 32, 32, 32, 32} // T E S T (4 spaces)
	bitPos := 8
	for _, c := range chars {
		for j := 5; j >= 0; j-- {
			bit := (c >> j) & 0x01
			byteIdx := bitPos >> 3
			bitIdx := 7 - (bitPos & 7)
			me[byteIdx] |= bit << bitIdx
			bitPos++
		}
	}
	id := decodeIdentification(me)
	if id.Callsign != "TEST" {
		t.Errorf("Callsign = %q; want 'TEST' (trailing spaces trimmed)", id.Callsign)
	}
	if !strings.Contains(id.CategoryName, "Light") {
		t.Errorf("CategoryName = %q; want a Light-aircraft label (TC=4 cat=1)", id.CategoryName)
	}
}

// TestAltitudeDecode_Q1 pins the Q=1 altitude formula.
func TestAltitudeDecode_Q1(t *testing.T) {
	// 38000 ft → N = (38000 + 1000) / 25 = 1560 → 11-bit binary
	// 1560 = 0b110_0001_1000 = high 7 bits "1100001" + low 4 bits
	// "1000". 12-bit field with Q-bit (bit 4) = 1.
	// Build: top7 = 0110_0001, Q=1, bottom4 = 1000 → 12-bit
	// field = 0110_0001 1 1000 = 0x618 + bit ordering. Easier
	// to compute via the inverse: place N as ((top << 1) | Q) | bottom
	q := 1
	n := 1560
	raw := ((n >> 4) << 5) | (q << 4) | (n & 0x0F)
	if alt, ok := decodeAltitude12(raw); !ok || alt != 38000 {
		t.Errorf("decodeAltitude12 = %d ok=%v; want 38000 ok=true", alt, ok)
	}
}

// TestAltitudeDecode_Q0_Gillham_NotSupported verifies that
// Q=0 frames are reported as invalid (Gillham decoding is
// deliberately out of scope).
func TestAltitudeDecode_Q0_Gillham_NotSupported(t *testing.T) {
	// 12-bit field with Q=0: top7=0010101, Q=0, bottom4=0101
	raw := (0b0010101 << 5) | (0 << 4) | 0b0101
	if _, ok := decodeAltitude12(raw); ok {
		t.Error("Q=0 (Gillham) should report invalid; got ok=true")
	}
}

// TestComputeCRC pins the polynomial against three published
// reference frames.
func TestComputeCRC(t *testing.T) {
	cases := []struct {
		hex  string
		want uint32
	}{
		{"8D4840D6202CC371C32CE0576098", 0x576098},
		{"8D40621D58C382D690C8AC2863A7", 0x2863A7},
		{"8D485020994409940838175B284F", 0x5B284F},
	}
	for _, c := range cases {
		b, _ := parseHex(c.hex)
		got := computeCRC(b)
		if got != c.want {
			t.Errorf("computeCRC(%s) = %06X; want %06X", c.hex, got, c.want)
		}
	}
}
