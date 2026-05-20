package l2tp

import (
	"strings"
	"testing"
)

func TestDecode_Control_HELLO_OnlyMessageType(t *testing.T) {
	// Control header bits: T=1 L=1 S=1 V=3 → 0xC803.
	// Length=20, ConnID=1, Ns=0, Nr=1.
	// AVP: Message Type (attr 0, value 6 HELLO).
	in := "C803 0014 00000001 0000 0001" +
		"8008 0000 0000 0006"
	r, err := Decode(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Type != 1 || r.TypeName != "Control Message" {
		t.Errorf("type: %d %q", r.Type, r.TypeName)
	}
	if !r.LengthPresent || !r.SequencePresent {
		t.Errorf("L/S flags: %+v", r)
	}
	if r.Version != 3 {
		t.Errorf("version: %d", r.Version)
	}
	c := r.Control
	if c == nil {
		t.Fatal("control body nil")
	}
	if c.Length != 20 || c.ControlConnectionID != 1 {
		t.Errorf("control header: %+v", c)
	}
	if c.Ns != 0 || c.Nr != 1 {
		t.Errorf("seq: Ns=%d Nr=%d", c.Ns, c.Nr)
	}
	if c.MessageType != 6 || c.MessageTypeName != "HELLO (Keepalive)" {
		t.Errorf("message type: %d %q", c.MessageType, c.MessageTypeName)
	}
	if len(c.AVPs) != 1 {
		t.Fatalf("AVPs: %d", len(c.AVPs))
	}
	a := c.AVPs[0]
	if !a.Mandatory || a.Hidden {
		t.Errorf("AVP flags: %+v", a)
	}
	if a.AttributeName != "Message Type" {
		t.Errorf("AVP attr: %q", a.AttributeName)
	}
}

func TestDecode_Control_SCCRQ_WithHostAndVendor(t *testing.T) {
	// SCCRQ with Message Type=1 + Host Name="router1"
	// + Vendor Name="Cisco".
	in := "C803 002C 00000001 0001 0000" +
		"8008 0000 0000 0001" +
		"800D 0000 0007 726F75746572 31" +
		"800B 0000 0008 4369 73 63 6F"
	r, err := Decode(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	c := r.Control
	if c.MessageTypeName != "SCCRQ (Start-Control-Connection-Request)" {
		t.Errorf("message type: %q", c.MessageTypeName)
	}
	if len(c.AVPs) != 3 {
		t.Fatalf("AVPs: %d", len(c.AVPs))
	}
	if c.AVPs[1].AttributeName != "Host Name" ||
		c.AVPs[1].ValueText != "router1" {
		t.Errorf("Host Name: %+v", c.AVPs[1])
	}
	if c.AVPs[2].AttributeName != "Vendor Name" ||
		c.AVPs[2].ValueText != "Cisco" {
		t.Errorf("Vendor Name: %+v", c.AVPs[2])
	}
}

func TestDecode_Data_SessionIDPlusPayload(t *testing.T) {
	// Data header: T=0 L=0 S=0 V=3 → 0x0003.
	// Session ID=100, payload DEADBEEF00112233.
	in := "0003 00000064 DEADBEEF00112233"
	r, err := Decode(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Type != 0 || r.TypeName != "Data Message" {
		t.Errorf("type: %d %q", r.Type, r.TypeName)
	}
	d := r.Data
	if d == nil {
		t.Fatal("data body nil")
	}
	if d.SessionID != 100 {
		t.Errorf("session ID: %d", d.SessionID)
	}
	if d.PayloadBytes != 8 {
		t.Errorf("payload bytes: %d", d.PayloadBytes)
	}
	if d.PayloadHex != "DEADBEEF00112233" {
		t.Errorf("payload: %q", d.PayloadHex)
	}
}

func TestDecode_Data_PayloadCap(t *testing.T) {
	// Data message with 100-byte payload, capped to 32.
	in := "0003 00000001 " + strings.Repeat("AA", 100)
	r, err := Decode(in, DecodeOpts{MaxPayloadBytes: 32})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Data.PayloadBytes != 100 {
		t.Errorf("payload bytes: %d", r.Data.PayloadBytes)
	}
	if r.Data.PayloadBytesShown != 32 {
		t.Errorf("payload shown: %d", r.Data.PayloadBytesShown)
	}
}

func TestDecode_HiddenAVP(t *testing.T) {
	// AVP with H flag set: should not surface ValueText.
	in := "C803 0014 00000001 0000 0001" +
		"C008 0000 0009 1234"
	r, err := Decode(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	a := r.Control.AVPs[0]
	if !a.Hidden {
		t.Errorf("expected hidden flag set")
	}
	if a.ValueText != "" {
		t.Errorf("hidden AVP should not have text: %q", a.ValueText)
	}
}

func TestDecode_VendorSpecificAVP(t *testing.T) {
	// AVP with Vendor ID != 0 (e.g. Cisco PEN 9):
	// should not be named via the IETF table.
	in := "C803 0014 00000001 0000 0001" +
		"8008 0009 0001 1234"
	r, err := Decode(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	a := r.Control.AVPs[0]
	if a.VendorID != 9 {
		t.Errorf("vendor ID: %d", a.VendorID)
	}
	if a.AttributeName != "" {
		t.Errorf("non-IETF AVP should not have name: %q", a.AttributeName)
	}
}

func TestDecode_MessageTypeTable(t *testing.T) {
	cases := map[int]string{
		1:  "SCCRQ (Start-Control-Connection-Request)",
		2:  "SCCRP (Start-Control-Connection-Reply)",
		3:  "SCCCN (Start-Control-Connection-Connected)",
		4:  "StopCCN (Stop-Control-Connection-Notification)",
		6:  "HELLO (Keepalive)",
		7:  "OCRQ (Outgoing-Call-Request)",
		8:  "OCRP (Outgoing-Call-Reply)",
		9:  "OCCN (Outgoing-Call-Connected)",
		10: "ICRQ (Incoming-Call-Request)",
		11: "ICRP (Incoming-Call-Reply)",
		12: "ICCN (Incoming-Call-Connected)",
		14: "CDN (Call-Disconnect-Notify)",
		15: "WEN (WAN-Error-Notify)",
		16: "SLI (Set-Link-Info)",
		20: "ACK (Acknowledgement)",
	}
	for k, v := range cases {
		if got := messageTypeName(k); got != v {
			t.Errorf("messageTypeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_AVPNameSpotCheck(t *testing.T) {
	cases := map[int]string{
		0:  "Message Type",
		1:  "Result Code",
		7:  "Host Name",
		8:  "Vendor Name",
		63: "Local Session ID",
		64: "Remote Session ID",
		65: "Assigned Cookie",
	}
	for k, v := range cases {
		if got := avpName(k); got != v {
			t.Errorf("avpName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_VersionNot3_Note(t *testing.T) {
	// V=2 (L2TPv2 — not handled by this Spec).
	in := "C802 0014 00000001 0000 0001 8008 0000 0000 0006"
	r, err := Decode(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 2 {
		t.Errorf("version: %d", r.Version)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "L2TPv3") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected L2TPv3 note in: %v", r.Notes)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":   "",
		"odd hex": "C803 001",
		"short":   "C8",
		"bad hex": "ZZ03 0014 00000001 0000 0001",
	}
	for name, in := range cases {
		_, err := Decode(in, DefaultDecodeOpts())
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
