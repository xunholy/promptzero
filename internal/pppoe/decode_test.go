package pppoe

import (
	"strings"
	"testing"
)

func TestDecode_PADI(t *testing.T) {
	// V=1, T=1 (0x11). Code=PADI (0x09). Session ID=0.
	// Tags: empty Service-Name (0x0101 len 0) + Host-Uniq
	// (0x0103 len 4 value DEADBEEF). Length = 4 + 8 = 12.
	in := "11 09 0000 000C 0101 0000 0103 0004 DEADBEEF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 1 || r.Type != 1 {
		t.Errorf("V/T: %d / %d", r.Version, r.Type)
	}
	if r.CodeName != "PADI (PPPoE Active Discovery Initiation)" {
		t.Errorf("code: %q", r.CodeName)
	}
	if r.SessionID != 0 {
		t.Errorf("session id: 0x%X", r.SessionID)
	}
	if !r.IsDiscovery {
		t.Errorf("should be Discovery")
	}
	if len(r.Tags) != 2 {
		t.Fatalf("expected 2 tags, got %d", len(r.Tags))
	}
	if r.Tags[0].TypeName != "Service-Name" || r.Tags[0].Length != 0 {
		t.Errorf("tag 0: %+v", r.Tags[0])
	}
	if r.Tags[1].TypeName != "Host-Uniq (client-chosen request cookie)" {
		t.Errorf("tag 1: %+v", r.Tags[1])
	}
	if r.Tags[1].ValueHex != "DEADBEEF" {
		t.Errorf("tag 1 value: %q", r.Tags[1].ValueHex)
	}
}

func TestDecode_PADO_WithACName(t *testing.T) {
	// PADO with AC-Name "MyAC" + Service-Name "internet".
	in := "11 07 0000 0014 0102 0004 4D794143 0101 0008 696E7465726E6574"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CodeName != "PADO (PPPoE Active Discovery Offer)" {
		t.Errorf("code: %q", r.CodeName)
	}
	if len(r.Tags) != 2 {
		t.Fatalf("expected 2 tags, got %d", len(r.Tags))
	}
	if !strings.Contains(r.Tags[0].TypeName, "AC-Name") {
		t.Errorf("tag 0 name: %q", r.Tags[0].TypeName)
	}
	if r.Tags[0].ValueText != "MyAC" {
		t.Errorf("AC-Name text: %q", r.Tags[0].ValueText)
	}
	if r.Tags[1].ValueText != "internet" {
		t.Errorf("Service-Name text: %q", r.Tags[1].ValueText)
	}
}

func TestDecode_PADS_AssignsSessionID(t *testing.T) {
	in := "11 65 1234 0008 0101 0004 74657374"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CodeName != "PADS (PPPoE Active Discovery Session-confirmation)" {
		t.Errorf("code: %q", r.CodeName)
	}
	if r.SessionID != 0x1234 {
		t.Errorf("session id: 0x%X", r.SessionID)
	}
	if len(r.Notes) != 0 {
		t.Errorf("PADS with assigned session ID should be conformant, notes=%v",
			r.Notes)
	}
}

func TestDecode_Session_LCP(t *testing.T) {
	// Session with PPP Protocol 0xC021 (LCP) and 4-byte body.
	in := "11 00 1234 0006 C021 01010002"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.IsSession {
		t.Errorf("should be Session")
	}
	if r.PPPProtocol == nil || *r.PPPProtocol != 0xC021 {
		t.Errorf("PPP protocol: %+v", r.PPPProtocol)
	}
	if r.PPPProtocolName != "LCP (Link Control Protocol)" {
		t.Errorf("PPP name: %q", r.PPPProtocolName)
	}
	if r.PPPPayloadHex != "01010002" {
		t.Errorf("PPP payload: %q", r.PPPPayloadHex)
	}
}

func TestDecode_Session_IPv4(t *testing.T) {
	in := "11 00 5678 0016 0021" +
		"45000014 12340000 40110000 7F000001 7F000001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.PPPProtocolName != "IPv4" {
		t.Errorf("PPP name: %q", r.PPPProtocolName)
	}
	if r.PPPPayloadLen != 20 {
		t.Errorf("PPP payload len: %d", r.PPPPayloadLen)
	}
}

func TestDecode_PADT_TearDown(t *testing.T) {
	in := "11 A7 1234 0000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.Contains(r.CodeName, "PADT") {
		t.Errorf("code: %q", r.CodeName)
	}
	if r.SessionID != 0x1234 {
		t.Errorf("session id: 0x%X", r.SessionID)
	}
}

func TestDecode_PADI_NonZeroSessionID_Violation(t *testing.T) {
	// PADI must have Session ID = 0; non-zero surfaces a Note.
	in := "11 09 9999 0008 0101 0004 74657374"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "non-zero Session ID") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected non-zero-session-id note in: %v", r.Notes)
	}
}

func TestDecode_BadVersion(t *testing.T) {
	// V=2, T=1 (0x21) — should surface a Note.
	in := "21 09 0000 0000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 2 {
		t.Errorf("version: %d", r.Version)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "byte 0 must be 0x11") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected version note in: %v", r.Notes)
	}
}

func TestDecode_CodeNameTable(t *testing.T) {
	cases := map[int]string{
		0x00: "Session (carries PPP frame)",
		0x09: "PADI (PPPoE Active Discovery Initiation)",
		0x07: "PADO (PPPoE Active Discovery Offer)",
		0x19: "PADR (PPPoE Active Discovery Request)",
		0x65: "PADS (PPPoE Active Discovery Session-confirmation)",
		0xA7: "PADT (PPPoE Active Discovery Terminate)",
	}
	for k, v := range cases {
		if got := codeName(k); got != v {
			t.Errorf("codeName(0x%02X): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_PPPProtocolTable(t *testing.T) {
	cases := map[int]string{
		0x0021: "IPv4",
		0x0057: "IPv6",
		0x8021: "IPCP (IP Control Protocol)",
		0xC021: "LCP (Link Control Protocol)",
		0xC023: "PAP (Password Authentication Protocol)",
		0xC223: "CHAP (Challenge Handshake Auth Protocol)",
		0xC229: "EAP (Extensible Authentication Protocol)",
	}
	for k, v := range cases {
		if got := pppProtocolName(k); got != v {
			t.Errorf("pppProtocolName(0x%04X): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":     "",
		"odd hex":   "11090",
		"too short": "1109",
		"bad hex":   "ZZ09 0000 0000",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
