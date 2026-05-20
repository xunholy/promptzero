package openflow

import (
	"strings"
	"testing"
)

// TestDecodeHelloWithVersionBitmap pins a canonical OF 1.3
// HELLO carrying a Version Bitmap TLV (the typical
// controller-side bootstrap message).
func TestDecodeHelloWithVersionBitmap(t *testing.T) {
	// Version 0x04 (OF 1.3); Type 0 HELLO; Length 16; XID 1.
	// Body: HELLO element type 1 (OFPHET_VERSIONBITMAP),
	// length 8 (4-byte header + 4-byte bitmap), bitmap with
	// bits 1+4 set (OF 1.0 + OF 1.3 supported).
	in := "04 00 0010 00000001 " +
		"0001 0008 00000012"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.VersionName != "OF_1.3" {
		t.Errorf("version: got %q want OF_1.3", r.VersionName)
	}
	if r.TypeName != "HELLO" {
		t.Errorf("type: got %q want HELLO", r.TypeName)
	}
	if r.Length != 16 {
		t.Errorf("length: got %d want 16", r.Length)
	}
	if len(r.HelloVersionsSupported) != 2 {
		t.Fatalf("versions: got %d want 2", len(r.HelloVersionsSupported))
	}
	if r.HelloVersionsSupported[0] != 1 || r.HelloVersionsSupported[1] != 4 {
		t.Errorf("versions: got %v want [1 4]", r.HelloVersionsSupported)
	}
}

// TestDecodeError pins an ERROR with FLOW_MOD_FAILED type.
func TestDecodeError(t *testing.T) {
	// Type 1 ERROR; Length 12; XID 7. Body: errorType=5
	// FLOW_MOD_FAILED; errorCode=2 (OVERLAP per OF 1.3); 4
	// bytes of offending-message data.
	in := "04 01 000C 00000007 " +
		"0005 0002 DEADBEEF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.TypeName != "ERROR" {
		t.Errorf("type: got %q want ERROR", r.TypeName)
	}
	if r.ErrorType != 5 || r.ErrorTypeName != "FLOW_MOD_FAILED" {
		t.Errorf("error type: got %d/%q want 5/FLOW_MOD_FAILED",
			r.ErrorType, r.ErrorTypeName)
	}
	if r.ErrorCode != 2 {
		t.Errorf("error code: got %d want 2", r.ErrorCode)
	}
	if r.ErrorDataHex != "DEADBEEF" {
		t.Errorf("error data: got %q want DEADBEEF", r.ErrorDataHex)
	}
}

// TestDecodeEchoRequest pins an ECHO_REQUEST with opaque
// payload (the keep-alive primitive).
func TestDecodeEchoRequest(t *testing.T) {
	in := "04 02 000C 0000000A AABBCCDD"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.TypeName != "ECHO_REQUEST" {
		t.Errorf("type: got %q want ECHO_REQUEST", r.TypeName)
	}
	if r.PayloadHex != "AABBCCDD" {
		t.Errorf("payload: got %q want AABBCCDD", r.PayloadHex)
	}
}

// TestDecodeFeaturesReply pins the canonical switch handshake
// reply revealing datapath_id + table count + capabilities.
func TestDecodeFeaturesReply(t *testing.T) {
	// Type 6 FEATURES_REPLY; Length 32 (8 hdr + 24 body).
	// datapath_id = 00:00:00:00:00:00:00:01;
	// n_buffers = 256 = 0x100;
	// n_tables = 254 = 0xFE;
	// auxiliary_id = 0;
	// capabilities = 0x4F (FLOW_STATS + TABLE_STATS +
	// PORT_STATS + GROUP_STATS + QUEUE_STATS)
	in := "04 06 0020 00000001 " +
		"0000000000000001 " +
		"00000100 FE 00 0000 0000004F 00000000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.TypeName != "FEATURES_REPLY" {
		t.Errorf("type: got %q want FEATURES_REPLY", r.TypeName)
	}
	if r.DatapathIDHex != "0000000000000001" {
		t.Errorf("datapath: got %q", r.DatapathIDHex)
	}
	if r.NBuffers != 256 {
		t.Errorf("n_buffers: got %d want 256", r.NBuffers)
	}
	if r.NTables != 254 {
		t.Errorf("n_tables: got %d want 254", r.NTables)
	}
	wantCaps := []string{
		"FLOW_STATS", "TABLE_STATS", "PORT_STATS",
		"GROUP_STATS", "QUEUE_STATS",
	}
	for _, w := range wantCaps {
		found := false
		for _, c := range r.CapabilitiesActive {
			if c == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("capability %q missing from %v", w, r.CapabilitiesActive)
		}
	}
}

// TestDecodeFlowMod pins that FLOW_MOD (Type 14) bodies fall
// through to opaque hex (we don't decode OXM matches or
// instruction lists).
func TestDecodeFlowMod(t *testing.T) {
	in := "04 0E 0010 00000010 DEAD BEEF CAFE BABE"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.TypeName != "FLOW_MOD" {
		t.Errorf("type: got %q want FLOW_MOD", r.TypeName)
	}
	if r.BodyHex != "DEADBEEFCAFEBABE" {
		t.Errorf("body: got %q want DEADBEEFCAFEBABE", r.BodyHex)
	}
}

// TestDecodeOF10 pins an OF 1.0 HELLO (legacy version) — the
// version byte alone distinguishes it.
func TestDecodeOF10(t *testing.T) {
	in := "01 00 0008 00000001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.VersionName != "OF_1.0" {
		t.Errorf("version: got %q want OF_1.0", r.VersionName)
	}
}

// TestTypeNameTable spot-checks key catalogued types.
func TestTypeNameTable(t *testing.T) {
	cases := map[int]string{
		0: "HELLO", 1: "ERROR", 2: "ECHO_REQUEST", 3: "ECHO_REPLY",
		5: "FEATURES_REQUEST", 6: "FEATURES_REPLY",
		10: "PACKET_IN", 13: "PACKET_OUT", 14: "FLOW_MOD",
		18: "MULTIPART_REQUEST", 19: "MULTIPART_REPLY",
		20: "BARRIER_REQUEST", 24: "ROLE_REQUEST",
		29: "METER_MOD", 33: "BUNDLE_CONTROL",
	}
	for k, v := range cases {
		if got := typeName(k); got != v {
			t.Errorf("typeName(%d) = %q want %q", k, got, v)
		}
	}
	if !strings.HasPrefix(typeName(255), "uncatalogued") {
		t.Errorf("uncatalogued type should be flagged")
	}
}

// TestErrorTypeNameTable spot-checks the documented error
// types.
func TestErrorTypeNameTable(t *testing.T) {
	cases := map[int]string{
		0: "HELLO_FAILED", 1: "BAD_REQUEST",
		4: "BAD_MATCH", 5: "FLOW_MOD_FAILED",
		11:     "ROLE_REQUEST_FAILED",
		13:     "TABLE_FEATURES_FAILED",
		0xFFFF: "EXPERIMENTER",
	}
	for k, v := range cases {
		if got := errorTypeName(k); got != v {
			t.Errorf("errorTypeName(%d) = %q want %q", k, got, v)
		}
	}
}

// TestVersionNameTable spot-checks each catalogued OF version.
func TestVersionNameTable(t *testing.T) {
	cases := map[int]string{
		0x01: "OF_1.0", 0x02: "OF_1.1", 0x03: "OF_1.2",
		0x04: "OF_1.3", 0x05: "OF_1.4", 0x06: "OF_1.5",
	}
	for k, v := range cases {
		if got := versionName(k); got != v {
			t.Errorf("versionName(0x%02X) = %q want %q", k, got, v)
		}
	}
}

// TestDecodeCapabilitiesBitmap covers each documented
// capability flag.
func TestDecodeCapabilitiesBitmap(t *testing.T) {
	all := decodeCapabilities(0x16F)
	for _, want := range []string{
		"FLOW_STATS", "TABLE_STATS", "PORT_STATS",
		"GROUP_STATS", "IP_REASM", "QUEUE_STATS",
		"PORT_BLOCKED",
	} {
		found := false
		for _, c := range all {
			if c == want {
				found = true
			}
		}
		if !found {
			t.Errorf("capability %q missing from %v", want, all)
		}
	}
}

func TestDecodeRejectsEmpty(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Fatal("want error for empty input")
	}
}

func TestDecodeRejectsOddNibbles(t *testing.T) {
	if _, err := Decode("ABC"); err == nil {
		t.Fatal("want error for odd-length input")
	}
}

func TestDecodeRejectsShortHeader(t *testing.T) {
	if _, err := Decode("04 00 0008"); err == nil {
		t.Fatal("want error for short header")
	}
}

func TestDecodeRejectsBadHex(t *testing.T) {
	if _, err := Decode("ZZ" + strings.Repeat("00", 7)); err == nil {
		t.Fatal("want error for non-hex chars")
	}
}
