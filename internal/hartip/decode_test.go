package hartip

import (
	"strings"
	"testing"
)

// TestDecodeSessionInitiate pins a canonical HART-IP Session
// Initiate request — the first message every host sends to
// establish a HART-IP session.
func TestDecodeSessionInitiate(t *testing.T) {
	// Version 1, MsgType 0 Request, MsgID 0 Session_Initiate,
	// Status 0, SeqNum 0x0001, ByteCount 5 (5-byte session
	// init payload: 1 byte primary master + 4 bytes timeout).
	in := "01 00 00 00 0001 0005 01 00000005"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Version != 1 {
		t.Errorf("version: got %d want 1", r.Version)
	}
	if r.MessageTypeName != "Request" {
		t.Errorf("messageType: got %q want Request", r.MessageTypeName)
	}
	if r.MessageIDName != "Session_Initiate" {
		t.Errorf("messageID: got %q want Session_Initiate", r.MessageIDName)
	}
	if r.SequenceNumber != 1 {
		t.Errorf("sequence: got %d want 1", r.SequenceNumber)
	}
	if r.ByteCount != 5 {
		t.Errorf("byte count: got %d want 5", r.ByteCount)
	}
	if r.HartPayloadHex != "0100000005" {
		t.Errorf("payload: got %q want 0100000005", r.HartPayloadHex)
	}
}

// TestDecodeHARTPDURequest pins the most common shape — a
// HART_PDU carrying a HART command (Cmd 0 Read Unique
// Identifier in this example).
func TestDecodeHARTPDURequest(t *testing.T) {
	// Version 1, MsgType 0 Request, MsgID 3 HART_PDU,
	// Status 0, SeqNum 0x0010, ByteCount 5.
	// HART payload: Delimiter 0x02 (STX with short address) +
	// short address 0x80 + Command 0x00 (Read Unique Identifier)
	// + Byte Count 0x00 + Checksum 0x82 (XOR).
	in := "01 00 03 00 0010 0005 02 80 00 00 82"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MessageIDName != "HART_PDU" {
		t.Errorf("messageID: got %q want HART_PDU", r.MessageIDName)
	}
	if r.HartPayloadHex != "0280000082" {
		t.Errorf("payload: got %q want 0280000082", r.HartPayloadHex)
	}
}

// TestDecodeHARTPDUResponse pins a HART_PDU Response.
func TestDecodeHARTPDUResponse(t *testing.T) {
	// MsgType 1 Response, MsgID 3 HART_PDU.
	in := "01 01 03 00 0010 0008 06 80 00 02 00 00 11 95"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MessageTypeName != "Response" {
		t.Errorf("messageType: got %q want Response", r.MessageTypeName)
	}
	if r.ByteCount != 8 {
		t.Errorf("byte count: got %d want 8", r.ByteCount)
	}
}

// TestDecodePublishBurstNotify pins the unsolicited burst-mode
// notification (Publish + Publish_Burst_Notify combo).
func TestDecodePublishBurstNotify(t *testing.T) {
	// MsgType 2 Publish, MsgID 128 Publish_Burst_Notify.
	in := "01 02 80 00 0001 0004 DEADBEEF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MessageTypeName != "Publish" {
		t.Errorf("messageType: got %q want Publish", r.MessageTypeName)
	}
	if r.MessageIDName != "Publish_Burst_Notify" {
		t.Errorf("messageID: got %q want Publish_Burst_Notify", r.MessageIDName)
	}
}

// TestDecodeNAK pins a NAK with non-zero status.
func TestDecodeNAK(t *testing.T) {
	// MsgType 3 NAK, Status 0x02, no payload.
	in := "01 03 03 02 0010 0000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MessageTypeName != "NAK" {
		t.Errorf("messageType: got %q want NAK", r.MessageTypeName)
	}
	if r.StatusCode != 2 {
		t.Errorf("status: got %d want 2", r.StatusCode)
	}
}

// TestDecodeKeepAlive pins a minimal Keep_Alive.
func TestDecodeKeepAlive(t *testing.T) {
	in := "01 00 02 00 0042 0000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MessageIDName != "Keep_Alive" {
		t.Errorf("messageID: got %q want Keep_Alive", r.MessageIDName)
	}
	if r.HartPayloadHex != "" {
		t.Errorf("payload: should be empty for Keep_Alive, got %q",
			r.HartPayloadHex)
	}
}

// TestMessageTypeNameTable covers every catalogued message type.
func TestMessageTypeNameTable(t *testing.T) {
	cases := map[int]string{
		0: "Request", 1: "Response",
		2: "Publish", 3: "NAK",
	}
	for k, v := range cases {
		if got := messageTypeName(k); got != v {
			t.Errorf("messageTypeName(%d) = %q want %q", k, got, v)
		}
	}
	if !strings.HasPrefix(messageTypeName(7), "uncatalogued") {
		t.Errorf("uncatalogued message type should be flagged")
	}
}

// TestMessageIDNameTable covers every catalogued message ID.
func TestMessageIDNameTable(t *testing.T) {
	cases := map[int]string{
		0: "Session_Initiate", 1: "Session_Close",
		2: "Keep_Alive", 3: "HART_PDU",
		4: "Direct_PDU", 128: "Publish_Burst_Notify",
	}
	for k, v := range cases {
		if got := messageIDName(k); got != v {
			t.Errorf("messageIDName(%d) = %q want %q", k, got, v)
		}
	}
	if !strings.HasPrefix(messageIDName(99), "uncatalogued") {
		t.Errorf("uncatalogued message ID should be flagged")
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
	if _, err := Decode("01 00 00 00"); err == nil {
		t.Fatal("want error for short header")
	}
}

func TestDecodeRejectsBadHex(t *testing.T) {
	if _, err := Decode("ZZ" + strings.Repeat("00", 7)); err == nil {
		t.Fatal("want error for non-hex chars")
	}
}
