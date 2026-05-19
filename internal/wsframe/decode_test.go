package wsframe

import (
	"strings"
	"testing"
)

func TestDecode_ServerText_Hello(t *testing.T) {
	// FIN=1 opcode=1 (Text), MASK=0, len=5, payload "Hello".
	in := "8105 48656C6C6F"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.FrameCount != 1 {
		t.Fatalf("expected 1 frame, got %d", r.FrameCount)
	}
	f := r.Frames[0]
	if !f.FIN || f.Opcode != 1 || f.OpcodeName != "Text" {
		t.Errorf("flags/opcode: FIN=%v op=%d name=%q", f.FIN, f.Opcode, f.OpcodeName)
	}
	if f.Masked {
		t.Errorf("masked should be false for server→client")
	}
	if f.PayloadText != "Hello" {
		t.Errorf("text: %q", f.PayloadText)
	}
	if f.PayloadLength != 5 {
		t.Errorf("len: %d", f.PayloadLength)
	}
}

func TestDecode_ClientText_HelloMasked(t *testing.T) {
	// Canonical example from RFC 6455 §5.7. Masked client→server
	// Text "Hello" with mask key 0x37 0xFA 0x21 0x3D.
	in := "8185 37FA213D 7F9F4D5158"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	f := r.Frames[0]
	if !f.Masked {
		t.Fatal("masked should be true")
	}
	if f.MaskKey != "37FA213D" {
		t.Errorf("mask key: %q", f.MaskKey)
	}
	if f.PayloadText != "Hello" {
		t.Errorf("demasked text: %q", f.PayloadText)
	}
}

func TestDecode_Binary(t *testing.T) {
	// FIN=1 opcode=2 (Binary), MASK=0, len=4, payload DEADBEEF.
	in := "8204 DEADBEEF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	f := r.Frames[0]
	if f.OpcodeName != "Binary" {
		t.Errorf("opcode name: %q", f.OpcodeName)
	}
	if f.PayloadHex != "DEADBEEF" {
		t.Errorf("payload hex: %q", f.PayloadHex)
	}
	if f.PayloadText != "" {
		t.Errorf("text should be empty for binary, got %q", f.PayloadText)
	}
}

func TestDecode_Extended16(t *testing.T) {
	// Payload length 200 → uses extended 16-bit form.
	// 200 × 0x41 = "A" repeated.
	body := strings.Repeat("41", 200)
	in := "817E 00C8 " + body
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	f := r.Frames[0]
	if f.PayloadLenRaw != 126 {
		t.Errorf("raw len marker: %d", f.PayloadLenRaw)
	}
	if f.PayloadLength != 200 {
		t.Errorf("actual len: %d", f.PayloadLength)
	}
	if !strings.HasPrefix(f.PayloadText, "AAAAAAAA") || len(f.PayloadText) != 200 {
		t.Errorf("text: prefix=%q len=%d", f.PayloadText[:8], len(f.PayloadText))
	}
}

func TestDecode_Extended64(t *testing.T) {
	// Payload length 10 expressed as extended 64-bit form
	// (artificial — real wire never does this for small
	// payloads, but it exercises the parser).
	in := "827F 000000000000000A 00112233445566778899"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	f := r.Frames[0]
	if f.PayloadLenRaw != 127 {
		t.Errorf("raw len marker: %d", f.PayloadLenRaw)
	}
	if f.PayloadLength != 10 {
		t.Errorf("actual len: %d", f.PayloadLength)
	}
	if f.PayloadHex != "00112233445566778899" {
		t.Errorf("payload: %q", f.PayloadHex)
	}
}

func TestDecode_Close_NormalWithReason(t *testing.T) {
	// FIN=1 opcode=8 (Close), len=5, status 1000 + reason "bye".
	in := "8805 03E8 627965"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	f := r.Frames[0]
	if f.OpcodeName != "Close" || f.Close == nil {
		t.Fatal("expected Close")
	}
	if f.Close.StatusCode != 1000 || f.Close.StatusName != "Normal Closure" {
		t.Errorf("status: %d %q", f.Close.StatusCode, f.Close.StatusName)
	}
	if f.Close.Reason != "bye" {
		t.Errorf("reason: %q", f.Close.Reason)
	}
}

func TestDecode_Close_EmptyBody(t *testing.T) {
	// Close with no body — valid per RFC 6455 §5.5.1.
	in := "8800"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Frames[0].Close == nil || r.Frames[0].Close.StatusCode != -1 {
		t.Errorf("expected status_code -1 for empty close, got %+v", r.Frames[0].Close)
	}
}

func TestDecode_CloseStatusTable(t *testing.T) {
	cases := []struct {
		code int
		want string
	}{
		{1000, "Normal Closure"},
		{1001, "Going Away"},
		{1002, "Protocol Error"},
		{1006, "Abnormal Closure (reserved — must not be sent on the wire)"},
		{1011, "Internal Error"},
		{1015, "TLS Handshake (reserved — must not be sent on the wire)"},
	}
	for _, c := range cases {
		got := closeStatusName(c.code)
		if got != c.want {
			t.Errorf("code %d: got %q want %q", c.code, got, c.want)
		}
	}
	if !strings.Contains(closeStatusName(3001), "Library") {
		t.Errorf("3001 should map to Library range")
	}
	if !strings.Contains(closeStatusName(4001), "Application") {
		t.Errorf("4001 should map to Application range")
	}
}

func TestDecode_Ping(t *testing.T) {
	// FIN=1 opcode=9 (Ping), MASK=0, len=4, payload "ping".
	in := "8904 70696E67"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	f := r.Frames[0]
	if f.OpcodeName != "Ping" || !f.IsControl {
		t.Errorf("opcode/control: %q %v", f.OpcodeName, f.IsControl)
	}
	if f.PayloadText != "ping" {
		t.Errorf("ping text: %q", f.PayloadText)
	}
}

func TestDecode_Fragmented(t *testing.T) {
	// Frame 1: FIN=0 opcode=1 (Text) len=3 "Hel".
	// Frame 2: FIN=1 opcode=0 (Continuation) len=2 "lo".
	in := "0103 48656C 8002 6C6F"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.FrameCount != 2 {
		t.Fatalf("expected 2 frames, got %d", r.FrameCount)
	}
	if r.Frames[0].FIN {
		t.Errorf("frame 0 FIN should be 0")
	}
	if r.Frames[0].Opcode != 1 || r.Frames[1].Opcode != 0 {
		t.Errorf("opcodes: %d %d", r.Frames[0].Opcode, r.Frames[1].Opcode)
	}
	if len(r.Frames[0].Notes) == 0 {
		t.Error("frame 0 should have a fragmentation note")
	}
}

func TestDecode_MultiFrame_TextPingClose(t *testing.T) {
	in := "8103 666F6F 8901 21 8802 03E8"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.FrameCount != 3 {
		t.Fatalf("expected 3 frames, got %d", r.FrameCount)
	}
	if r.Summary != "Text + Ping + Close" {
		t.Errorf("summary: %q", r.Summary)
	}
	if r.Frames[0].PayloadText != "foo" {
		t.Errorf("frame 0 text: %q", r.Frames[0].PayloadText)
	}
	if r.Frames[2].Close.StatusCode != 1000 {
		t.Errorf("close status: %d", r.Frames[2].Close.StatusCode)
	}
}

func TestDecode_RSV1_DeflateNote(t *testing.T) {
	// FIN=1 RSV1=1 opcode=1 (Text), len=4, payload (raw).
	// 0xC1 = 1100 0001
	in := "C104 DEADBEEF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	f := r.Frames[0]
	if !f.RSV1 {
		t.Error("RSV1 should be set")
	}
	found := false
	for _, n := range f.Notes {
		if strings.Contains(n, "permessage-deflate") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected deflate note in: %v", f.Notes)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":              "",
		"odd hex":            "8105 48656",
		"single byte":        "81",
		"truncated payload":  "8105 48",
		"control too big":    "887E 0080 " + strings.Repeat("00", 128),
		"fragmented control": "0805 03E8 627965",
		"ext64 MSB set":      "827F 8000000000000010 " + strings.Repeat("00", 16),
		"truncated mask key": "8185 37FA",
		"truncated ext16":    "817E 00",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
