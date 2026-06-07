// SPDX-License-Identifier: AGPL-3.0-or-later

package isotp

import (
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestDecodeFrame_SingleFrame(t *testing.T) {
	f, err := DecodeFrame(mustHex(t, "021003"))
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	if f.Type != "SingleFrame" || f.Length != 2 || f.PayloadHex != "1003" {
		t.Errorf("SF = %+v", f)
	}
}

func TestDecodeFrame_FirstFrame(t *testing.T) {
	// 10 0A = First Frame, total length 10.
	f, err := DecodeFrame(mustHex(t, "100A22F190010203"))
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	if f.Type != "FirstFrame" || f.Length != 10 {
		t.Errorf("FF = %+v, want FirstFrame len 10", f)
	}
}

func TestDecodeFrame_ConsecutiveFrame(t *testing.T) {
	f, err := DecodeFrame(mustHex(t, "2104050607"))
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	if f.Type != "ConsecutiveFrame" || f.SequenceNumber == nil || *f.SequenceNumber != 1 {
		t.Errorf("CF = %+v", f)
	}
	if f.PayloadHex != "04050607" {
		t.Errorf("CF payload = %s", f.PayloadHex)
	}
}

func TestDecodeFrame_FlowControl(t *testing.T) {
	// 30 00 0A = Flow Control, CTS, BS 0, STmin 10.
	f, err := DecodeFrame(mustHex(t, "30000A"))
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	if f.Type != "FlowControl" || f.FlowStatusName != "ContinueToSend" {
		t.Errorf("FC = %+v", f)
	}
	if f.BlockSize == nil || *f.BlockSize != 0 || f.STmin == nil || *f.STmin != 10 {
		t.Errorf("FC bs/stmin = %v/%v", f.BlockSize, f.STmin)
	}
}

func TestDecodeFrame_SingleFrameFDEscape(t *testing.T) {
	// 00 09 <9 bytes> = CAN-FD single-frame escape, length 9.
	f, err := DecodeFrame(mustHex(t, "0009112233445566778899"))
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	if f.Length != 9 || f.PayloadHex != "112233445566778899" {
		t.Errorf("FD SF = %+v", f)
	}
}

// TestReassemble_SingleFrame: a lone SF reassembles to its payload.
func TestReassemble_SingleFrame(t *testing.T) {
	r, err := Reassemble([][]byte{mustHex(t, "0622F190123456")})
	if err != nil {
		t.Fatalf("Reassemble: %v", err)
	}
	if !r.Complete || r.PayloadHex != "22F190123456" {
		t.Errorf("SF reassembly = %+v", r)
	}
}

// TestReassemble_MultiFrame: FF + CF reassemble to the full UDS PDU
// 22 F1 90 01 02 03 04 05 06 07 (ReadDataByIdentifier VIN, 10 bytes).
func TestReassemble_MultiFrame(t *testing.T) {
	ff := mustHex(t, "100A22F190010203") // FF, len 10, 6 payload bytes
	cf := mustHex(t, "2104050607")       // CF SN1, 4 payload bytes
	r, err := Reassemble([][]byte{ff, cf})
	if err != nil {
		t.Fatalf("Reassemble: %v", err)
	}
	if !r.Complete {
		t.Fatalf("not complete: %+v", r)
	}
	if r.Length != 10 || r.PayloadHex != "22F19001020304050607" {
		t.Errorf("reassembled = %s len %d", r.PayloadHex, r.Length)
	}
}

// TestReassemble_SkipsFlowControl: an interleaved FC frame is decoded but
// not part of the payload.
func TestReassemble_SkipsFlowControl(t *testing.T) {
	ff := mustHex(t, "100A22F190010203")
	fc := mustHex(t, "300000")
	cf := mustHex(t, "2104050607")
	r, err := Reassemble([][]byte{ff, fc, cf})
	if err != nil {
		t.Fatalf("Reassemble: %v", err)
	}
	if !r.Complete || r.PayloadHex != "22F19001020304050607" {
		t.Errorf("reassembly w/ FC = %+v", r)
	}
	if len(r.Frames) != 3 {
		t.Errorf("frames decoded = %d, want 3", len(r.Frames))
	}
}

// TestReassemble_Incomplete: missing CF leaves it incomplete with a note.
func TestReassemble_Incomplete(t *testing.T) {
	ff := mustHex(t, "100A22F190010203") // needs 10, has 6
	r, err := Reassemble([][]byte{ff})
	if err != nil {
		t.Fatalf("Reassemble: %v", err)
	}
	if r.Complete {
		t.Error("expected incomplete")
	}
	if len(r.Notes) == 0 {
		t.Error("expected an incomplete note")
	}
}

// TestReassemble_SequenceGap: a wrong SN is noted.
func TestReassemble_SequenceGap(t *testing.T) {
	ff := mustHex(t, "100A22F190010203")
	cf := mustHex(t, "2204050607") // SN 2, expected 1
	r, err := Reassemble([][]byte{ff, cf})
	if err != nil {
		t.Fatalf("Reassemble: %v", err)
	}
	if len(r.Notes) == 0 {
		t.Error("expected a sequence-number note")
	}
}

func TestReassemble_Empty(t *testing.T) {
	if _, err := Reassemble(nil); err == nil {
		t.Error("expected error for empty input")
	}
}

// TestReassemble_ChainsUDS pins the UDS chaining: a Single Frame carrying a
// UDS ReadDataByIdentifier (0x22 F1 90) is interpreted inline as UDS.
func TestReassemble_ChainsUDS(t *testing.T) {
	r, err := Reassemble([][]byte{mustHex(t, "0322F190")})
	if err != nil {
		t.Fatalf("Reassemble: %v", err)
	}
	if !r.Complete {
		t.Fatal("expected complete reassembly")
	}
	if r.UDS == nil {
		t.Fatalf("expected chained UDS, got nil (err=%q)", r.UDSDecodeError)
	}
	if r.UDS.ServiceID != 0x22 || r.UDS.Service != "ReadDataByIdentifier" {
		t.Errorf("chained UDS = 0x%02X/%q, want 0x22/ReadDataByIdentifier", r.UDS.ServiceID, r.UDS.Service)
	}
	if r.UDS.DataIdentifier == nil || *r.UDS.DataIdentifier != 0xF190 {
		t.Errorf("DataIdentifier = %v, want 0xF190", r.UDS.DataIdentifier)
	}
}

// TestReassemble_MultiFrameChainsUDS pins chaining on a reassembled FF+CF
// message (UDS positive response to ReadDataByIdentifier).
func TestReassemble_MultiFrameChainsUDS(t *testing.T) {
	// FF: total length 0x00A, payload starts 62 F1 90 01 02 03; CF: 04 05 06 07.
	r, err := Reassemble([][]byte{
		mustHex(t, "100A62F190010203"),
		mustHex(t, "2104050607"),
	})
	if err != nil {
		t.Fatalf("Reassemble: %v", err)
	}
	if !r.Complete || r.UDS == nil {
		t.Fatalf("expected complete reassembly with chained UDS (complete=%v err=%q)", r.Complete, r.UDSDecodeError)
	}
	// 0x62 is the positive response to ReadDataByIdentifier (0x22 | 0x40); the
	// UDS decoder normalises it to the base service + a positive_response direction.
	if r.UDS.ServiceID != 0x22 {
		t.Errorf("chained UDS service = 0x%02X, want 0x22 (ReadDataByIdentifier)", r.UDS.ServiceID)
	}
	if r.UDS.Direction != "positive_response" {
		t.Errorf("Direction = %q, want positive_response", r.UDS.Direction)
	}
}
