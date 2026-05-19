package http2

import (
	"strings"
	"testing"
)

const prefaceHex = "505249202A20485454502F322E300D0A0D0A534D0D0A0D0A"

func TestDecode_Settings(t *testing.T) {
	// 12 bytes payload, 2 settings:
	// MAX_CONCURRENT_STREAMS=100, MAX_FRAME_SIZE=16384.
	in := "00000C 04 00 00000000 0003 00000064 0005 00004000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.FrameCount != 1 {
		t.Fatalf("expected 1 frame, got %d", r.FrameCount)
	}
	f := r.Frames[0]
	if f.TypeName != "SETTINGS" {
		t.Errorf("type: %q", f.TypeName)
	}
	if f.Settings == nil || len(f.Settings.Parameters) != 2 {
		t.Fatalf("settings: %+v", f.Settings)
	}
	if f.Settings.Parameters[0].IdentifierName != "MAX_CONCURRENT_STREAMS" ||
		f.Settings.Parameters[0].Value != 100 {
		t.Errorf("param 0: %+v", f.Settings.Parameters[0])
	}
	if f.Settings.Parameters[1].IdentifierName != "MAX_FRAME_SIZE" ||
		f.Settings.Parameters[1].Value != 16384 {
		t.Errorf("param 1: %+v", f.Settings.Parameters[1])
	}
}

func TestDecode_SettingsAck(t *testing.T) {
	in := "000000 04 01 00000000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.Frames[0].Settings.IsAck {
		t.Errorf("expected SETTINGS ACK")
	}
	if r.Frames[0].FlagsDecoded != "ACK" {
		t.Errorf("flags: %q", r.Frames[0].FlagsDecoded)
	}
}

func TestDecode_Headers_EndStreamEndHeaders(t *testing.T) {
	// Length 10, flags 0x05 (END_STREAM | END_HEADERS),
	// stream 1, HPACK block "82864184F1E3C2E5F23A6BA0AB90F4FF"
	// (16 bytes — arbitrary, we don't decode).
	in := "000010 01 05 00000001 82864184F1E3C2E5F23A6BA0AB90F4FF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	f := r.Frames[0]
	if f.TypeName != "HEADERS" {
		t.Errorf("type: %q", f.TypeName)
	}
	if !strings.Contains(f.FlagsDecoded, "END_STREAM") ||
		!strings.Contains(f.FlagsDecoded, "END_HEADERS") {
		t.Errorf("flags: %q", f.FlagsDecoded)
	}
	if f.Headers.HPACKBlockLen != 16 {
		t.Errorf("hpack len: %d", f.Headers.HPACKBlockLen)
	}
	if f.Headers.HPACKBlockHex != "82864184F1E3C2E5F23A6BA0AB90F4FF" {
		t.Errorf("hpack hex: %q", f.Headers.HPACKBlockHex)
	}
}

func TestDecode_Data_EndStream(t *testing.T) {
	// 5 byte payload "Hello", END_STREAM, stream 1.
	in := "000005 00 01 00000001 48656C6C6F"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	f := r.Frames[0]
	if f.Data == nil || f.Data.DataLen != 5 {
		t.Fatalf("data: %+v", f.Data)
	}
	if f.Data.DataHex != "48656C6C6F" {
		t.Errorf("data hex: %q", f.Data.DataHex)
	}
	if f.FlagsDecoded != "END_STREAM" {
		t.Errorf("flags: %q", f.FlagsDecoded)
	}
}

func TestDecode_Data_Padded(t *testing.T) {
	// 8 byte payload: pad-len=2, "Hello", 2 pad bytes 00 00.
	// Flags 0x09 (END_STREAM | PADDED).
	in := "000008 00 09 00000001 02 48656C6C6F 0000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	d := r.Frames[0].Data
	if d.PaddingLen != 2 {
		t.Errorf("padding_len: %d", d.PaddingLen)
	}
	if d.DataLen != 5 || d.DataHex != "48656C6C6F" {
		t.Errorf("data: %+v", d)
	}
}

func TestDecode_Ping(t *testing.T) {
	in := "000008 06 00 00000000 DEADBEEFCAFEBABE"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	p := r.Frames[0].Ping
	if p == nil || p.OpaqueHex != "DEADBEEFCAFEBABE" {
		t.Errorf("ping: %+v", p)
	}
	if p.IsAck {
		t.Errorf("ping should not be ACK")
	}
}

func TestDecode_PingAck(t *testing.T) {
	in := "000008 06 01 00000000 DEADBEEFCAFEBABE"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.Frames[0].Ping.IsAck {
		t.Errorf("ping should be ACK")
	}
}

func TestDecode_GoAway(t *testing.T) {
	// Last stream ID 5, error PROTOCOL_ERROR (0x01).
	in := "000008 07 00 00000000 00000005 00000001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	g := r.Frames[0].GoAway
	if g == nil || g.LastStreamID != 5 || g.ErrorCodeName != "PROTOCOL_ERROR" {
		t.Errorf("goaway: %+v", g)
	}
}

func TestDecode_GoAway_WithDebug(t *testing.T) {
	// Last stream ID 7, error CONNECT_ERROR, debug data "fail".
	in := "00000C 07 00 00000000 00000007 0000000A 6661696C"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	g := r.Frames[0].GoAway
	if g.ErrorCodeName != "CONNECT_ERROR" {
		t.Errorf("error name: %q", g.ErrorCodeName)
	}
	if g.DebugHex != "6661696C" {
		t.Errorf("debug: %q", g.DebugHex)
	}
}

func TestDecode_RstStream(t *testing.T) {
	in := "000004 03 00 00000001 00000008"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Frames[0].RstStream.ErrorCodeName != "CANCEL" {
		t.Errorf("error: %q", r.Frames[0].RstStream.ErrorCodeName)
	}
}

func TestDecode_WindowUpdate(t *testing.T) {
	in := "000004 08 00 00000000 0000FFFF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	w := r.Frames[0].WindowUpdate
	if w == nil || w.WindowSizeIncrement != 0xFFFF {
		t.Errorf("window_update: %+v", w)
	}
}

func TestDecode_Priority(t *testing.T) {
	// Exclusive=1, stream dep 0x12345678, weight=15 (encoded
	// as 14 + 1).
	in := "000005 02 00 00000001 92345678 0E"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	p := r.Frames[0].Priority
	if p == nil {
		t.Fatal("Priority nil")
	}
	if !p.Exclusive {
		t.Errorf("exclusive should be true")
	}
	if p.StreamDependency != 0x12345678 {
		t.Errorf("dependency: 0x%X", p.StreamDependency)
	}
	if p.Weight != 15 {
		t.Errorf("weight: %d", p.Weight)
	}
}

func TestDecode_Continuation(t *testing.T) {
	in := "000004 09 04 00000001 DEADBEEF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	c := r.Frames[0].Continuation
	if c == nil || c.HPACKBlockHex != "DEADBEEF" {
		t.Errorf("continuation: %+v", c)
	}
}

func TestDecode_PrefacePlusSettings(t *testing.T) {
	in := prefaceHex + "000000 04 00 00000000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.HasPreface {
		t.Errorf("expected preface detection")
	}
	if r.FrameCount != 2 {
		t.Fatalf("expected preface + 1 frame, got %d", r.FrameCount)
	}
	if !r.Frames[0].IsPreface {
		t.Errorf("first frame should be preface")
	}
	if r.Frames[1].TypeName != "SETTINGS" {
		t.Errorf("second frame: %q", r.Frames[1].TypeName)
	}
}

func TestDecode_MultiFrame_HeadersData(t *testing.T) {
	// HEADERS (end_headers) then DATA (end_stream).
	in := "000004 01 04 00000001 82864184 000005 00 01 00000001 48656C6C6F"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.FrameCount != 2 {
		t.Fatalf("expected 2 frames, got %d", r.FrameCount)
	}
	if r.Summary != "HEADERS + DATA" {
		t.Errorf("summary: %q", r.Summary)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":                  "",
		"odd hex":                "00000F0",
		"truncated header":       "0000",
		"truncated payload":      "000010 01 00 00000001 ABCD",
		"settings odd len":       "000005 04 00 00000000 0001000000",
		"settings ack non-empty": "000006 04 01 00000000 000300000064",
		"rst_stream wrong len":   "000003 03 00 00000001 000000",
		"ping wrong len":         "000004 06 00 00000000 DEADBEEF",
		"window_update zero":     "000004 08 00 00000000 00000000",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
