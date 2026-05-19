package ntp

import (
	"encoding/binary"
	"strings"
	"testing"
)

// TestDecode_ClientRequest_v4 pins a typical NTPv4 client
// request: LI=0, VN=4, Mode=3 (client), Stratum=0, Poll=10
// (1024s), Precision=-6 (~16ms), zeroed timestamps.
func TestDecode_ClientRequest_v4(t *testing.T) {
	pkt := make([]byte, 48)
	pkt[0] = (0 << 6) | (4 << 3) | 3 // LI=0 | VN=4 | Mode=3
	pkt[1] = 0                       // Stratum
	pkt[2] = 10                      // Poll = 1024s
	precision := int8(-6)
	pkt[3] = byte(precision) // Precision
	// Transmit time = arbitrary non-zero
	binary.BigEndian.PutUint32(pkt[40:44], 2208988800+1700000000) // 2023-11-14ish
	binary.BigEndian.PutUint32(pkt[44:48], 0x80000000)            // 0.5s fraction
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.LeapIndicator != 0 {
		t.Errorf("LeapIndicator = %d", got.LeapIndicator)
	}
	if got.VersionNumber != 4 {
		t.Errorf("VersionNumber = %d; want 4", got.VersionNumber)
	}
	if got.Mode != 3 {
		t.Errorf("Mode = %d; want 3", got.Mode)
	}
	if got.ModeName != "Client" {
		t.Errorf("ModeName = %q", got.ModeName)
	}
	if got.Stratum != 0 {
		t.Errorf("Stratum = %d", got.Stratum)
	}
	if got.PollIntervalLog2 != 10 {
		t.Errorf("PollIntervalLog2 = %d", got.PollIntervalLog2)
	}
	if got.PollIntervalSec != 1024 {
		t.Errorf("PollIntervalSec = %f; want 1024", got.PollIntervalSec)
	}
	if got.PrecisionLog2 != -6 {
		t.Errorf("PrecisionLog2 = %d", got.PrecisionLog2)
	}
	if got.TransmitTime == nil {
		t.Fatal("TransmitTime nil")
	}
	if got.TransmitTime.FractionSec != 0.5 {
		t.Errorf("TransmitTime.FractionSec = %f; want 0.5", got.TransmitTime.FractionSec)
	}
	if got.TransmitTime.UnixSeconds != 1700000000 {
		t.Errorf("TransmitTime.UnixSeconds = %d; want 1700000000", got.TransmitTime.UnixSeconds)
	}
	if !strings.HasPrefix(got.TransmitTime.RFC3339, "2023-11") {
		t.Errorf("TransmitTime.RFC3339 = %q; want '2023-11...' prefix", got.TransmitTime.RFC3339)
	}
}

// TestDecode_ServerReply_Stratum1_GPS pins a stratum-1 server
// response with the GPS primary-source identifier.
func TestDecode_ServerReply_Stratum1_GPS(t *testing.T) {
	pkt := make([]byte, 48)
	pkt[0] = (0 << 6) | (4 << 3) | 4 // LI=0 | VN=4 | Mode=4 (server)
	pkt[1] = 1                       // Stratum = primary
	pkt[2] = 6                       // Poll = 64s
	precision := int8(-20)
	pkt[3] = byte(precision) // Precision ~1us
	// Root delay = 0.000s
	binary.BigEndian.PutUint16(pkt[4:6], 0)
	binary.BigEndian.PutUint16(pkt[6:8], 0)
	// Root dispersion = 0.5s
	binary.BigEndian.PutUint16(pkt[8:10], 0)
	binary.BigEndian.PutUint16(pkt[10:12], 0x8000)
	// Reference ID = "GPS\0"
	copy(pkt[12:16], []byte{'G', 'P', 'S', 0})
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Stratum != 1 {
		t.Errorf("Stratum = %d", got.Stratum)
	}
	if got.ReferenceID.ASCIICode != "GPS" {
		t.Errorf("ASCIICode = %q", got.ReferenceID.ASCIICode)
	}
	if !strings.Contains(got.ReferenceID.ASCIIName, "Global Positioning System") {
		t.Errorf("ASCIIName = %q", got.ReferenceID.ASCIIName)
	}
	if got.RootDispersionSec != 0.5 {
		t.Errorf("RootDispersionSec = %f; want 0.5", got.RootDispersionSec)
	}
}

// TestDecode_KoD_RATE pins a Kiss-o'-Death "RATE" stratum-0
// response telling the client to back off.
func TestDecode_KoD_RATE(t *testing.T) {
	pkt := make([]byte, 48)
	pkt[0] = (0 << 6) | (4 << 3) | 4
	pkt[1] = 0 // Stratum = 0 (KoD)
	pkt[2] = 6
	precision := int8(-20)
	pkt[3] = byte(precision)
	copy(pkt[12:16], []byte("RATE"))
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Stratum != 0 {
		t.Errorf("Stratum = %d", got.Stratum)
	}
	if !strings.Contains(got.ReferenceID.Interpretation, "Kiss-o'-Death") {
		t.Errorf("Interpretation = %q", got.ReferenceID.Interpretation)
	}
	if got.ReferenceID.KoDCode != "RATE" {
		t.Errorf("KoDCode = %q", got.ReferenceID.KoDCode)
	}
	if !strings.Contains(got.ReferenceID.KoDName, "Rate exceeded") {
		t.Errorf("KoDName = %q", got.ReferenceID.KoDName)
	}
}

// TestDecode_Stratum2_IPv4 pins a stratum-2 secondary server
// with an IPv4 reference identifier.
func TestDecode_Stratum2_IPv4(t *testing.T) {
	pkt := make([]byte, 48)
	pkt[0] = (0 << 6) | (4 << 3) | 4
	pkt[1] = 2                               // Stratum 2
	copy(pkt[12:16], []byte{129, 6, 15, 28}) // 129.6.15.28 (time-a.nist.gov)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.ReferenceID.IPv4 != "129.6.15.28" {
		t.Errorf("IPv4 = %q", got.ReferenceID.IPv4)
	}
	if !strings.Contains(got.ReferenceID.Interpretation, "Upstream IPv4") {
		t.Errorf("Interpretation = %q", got.ReferenceID.Interpretation)
	}
}

// TestDecode_ZeroTimestamp surfaces is_zero on an all-zero
// timestamp (typical of an originate field on the first
// client request).
func TestDecode_ZeroTimestamp(t *testing.T) {
	pkt := make([]byte, 48)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.OriginTime.IsZero {
		t.Error("OriginTime.IsZero = false; want true")
	}
	if got.OriginTime.UnixSeconds != 0 {
		t.Errorf("UnixSeconds = %d; want 0", got.OriginTime.UnixSeconds)
	}
	if got.OriginTime.RFC3339 != "" {
		t.Errorf("RFC3339 = %q; want empty for zero timestamp", got.OriginTime.RFC3339)
	}
}

// TestDecode_Authenticator_MD5 pins an authenticated packet
// with a 4-byte key ID + 16-byte MD5 MAC (total tail = 20).
func TestDecode_Authenticator_MD5(t *testing.T) {
	pkt := make([]byte, 48)
	pkt[0] = (0 << 6) | (3 << 3) | 3 // LI=0 | VN=3 | Mode=3
	auth := make([]byte, 20)
	binary.BigEndian.PutUint32(auth[0:4], 0x12345678)
	for i := 0; i < 16; i++ {
		auth[4+i] = byte(i)
	}
	pkt = append(pkt, auth...)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Authenticator == nil {
		t.Fatal("Authenticator nil")
	}
	if got.Authenticator.KeyID != 0x12345678 {
		t.Errorf("KeyID = 0x%08X", got.Authenticator.KeyID)
	}
	if got.Authenticator.MACAlg != "MD5 (16-byte MAC)" {
		t.Errorf("MACAlg = %q", got.Authenticator.MACAlg)
	}
}

// TestDecode_Authenticator_SHA1 pins a 4-byte key ID + 20-byte
// SHA-1 MAC (total tail = 24).
func TestDecode_Authenticator_SHA1(t *testing.T) {
	pkt := make([]byte, 48)
	pkt[0] = (0 << 6) | (4 << 3) | 3
	auth := make([]byte, 24)
	binary.BigEndian.PutUint32(auth[0:4], 42)
	pkt = append(pkt, auth...)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Authenticator == nil {
		t.Fatal("Authenticator nil")
	}
	if got.Authenticator.MACAlg != "SHA-1 (20-byte MAC)" {
		t.Errorf("MACAlg = %q", got.Authenticator.MACAlg)
	}
}

// TestDecode_TooShort rejects buffers < 48 bytes.
func TestDecode_TooShort(t *testing.T) {
	if _, err := Decode("00 01 02 03"); err == nil {
		t.Error("4-byte input: want error")
	}
}

// TestDecode_BadHex rejects garbage.
func TestDecode_BadHex(t *testing.T) {
	if _, err := Decode("ZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
	if _, err := Decode(""); err == nil {
		t.Error("empty: want error")
	}
}

// TestModeNameTable spot-checks.
func TestModeNameTable(t *testing.T) {
	cases := map[int]string{
		0: "Reserved",
		1: "Symmetric active",
		2: "Symmetric passive",
		3: "Client",
		4: "Server",
		5: "Broadcast",
		6: "NTP control message",
		7: "Private use (reserved)",
	}
	for v, want := range cases {
		if got := modeName(v); got != want {
			t.Errorf("modeName(%d) = %q; want %q", v, got, want)
		}
	}
}

// TestLeapIndicatorTable spot-checks.
func TestLeapIndicatorTable(t *testing.T) {
	cases := map[int]string{
		0: "No warning",
		1: "Last minute has 61 seconds",
		2: "Last minute has 59 seconds",
		3: "Alarm condition (clock not synchronised)",
	}
	for v, want := range cases {
		if got := leapIndicatorName(v); got != want {
			t.Errorf("leapIndicatorName(%d) = %q; want %q", v, got, want)
		}
	}
}

// TestKoDCodeTable spot-checks.
func TestKoDCodeTable(t *testing.T) {
	cases := map[string]string{
		"DENY": "Access denied by remote server",
		"RATE": "Rate exceeded (back off, slow your polls)",
		"INIT": "The association has not yet synchronised for the first time",
		"STEP": "A step change in system time has occurred",
	}
	for v, want := range cases {
		if got := kodCodeName(v); got != want {
			t.Errorf("kodCodeName(%q) = %q; want %q", v, got, want)
		}
	}
}

// TestPrimarySourceTable spot-checks.
func TestPrimarySourceTable(t *testing.T) {
	cases := map[string]string{
		"GPS":  "Global Positioning System",
		"PPS":  "Generic pulse-per-second",
		"WWVB": "LF Radio WWVB Fort Collins, CO USA",
		"DCF":  "LF Radio DCF77 Mainflingen, DE",
		"NIST": "NIST telephone modem",
	}
	for v, want := range cases {
		if got := primarySourceName(v); got != want {
			t.Errorf("primarySourceName(%q) = %q; want %q", v, got, want)
		}
	}
}

// TestStratumName spot-checks.
func TestStratumName(t *testing.T) {
	cases := map[int]string{
		0:  "Unspecified / invalid (Kiss-o'-Death)",
		1:  "Primary reference (directly attached source)",
		2:  "Secondary reference (synced via stratum 1 server)",
		15: "Secondary reference (synced via stratum 14 server)",
		16: "Unsynchronised",
	}
	for v, want := range cases {
		if got := stratumName(v); got != want {
			t.Errorf("stratumName(%d) = %q; want %q", v, got, want)
		}
	}
}

// TestDecodeShortFixed spot-checks the NTPv3 short-format
// fixed-point decoder.
func TestDecodeShortFixed(t *testing.T) {
	cases := []struct {
		b    []byte
		want float64
	}{
		{[]byte{0x00, 0x01, 0x00, 0x00}, 1.0},
		{[]byte{0x00, 0x00, 0x80, 0x00}, 0.5},
		{[]byte{0x00, 0x02, 0x40, 0x00}, 2.25},
	}
	for _, c := range cases {
		if got := decodeShortFixed(c.b); got != c.want {
			t.Errorf("decodeShortFixed(% X) = %f; want %f", c.b, got, c.want)
		}
	}
}
