// SPDX-License-Identifier: AGPL-3.0-or-later

package isotp

import (
	"encoding/hex"
	"strings"
	"testing"
)

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func up(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) }

// TestSegment_SingleFrame: a <=7-byte PDU becomes one SF, padded to 8.
func TestSegment_SingleFrame(t *testing.T) {
	frames, err := Segment(hx(t, "22F190"), 0x00)
	if err != nil {
		t.Fatalf("Segment: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("frames = %d, want 1", len(frames))
	}
	if up(frames[0]) != "0322F19000000000" {
		t.Errorf("SF = %s, want 0322F19000000000", up(frames[0]))
	}
}

// TestSegment_MultiFrame: a 10-byte PDU becomes FF + one CF, matching the
// exact vector the v0.398 reassembler test consumes.
func TestSegment_MultiFrame(t *testing.T) {
	frames, err := Segment(hx(t, "22F19001020304050607"), 0x00)
	if err != nil {
		t.Fatalf("Segment: %v", err)
	}
	if len(frames) != 2 {
		t.Fatalf("frames = %d, want 2", len(frames))
	}
	if up(frames[0]) != "100A22F190010203" {
		t.Errorf("FF = %s, want 100A22F190010203", up(frames[0]))
	}
	if up(frames[1]) != "2104050607000000" {
		t.Errorf("CF = %s, want 2104050607000000", up(frames[1]))
	}
}

// TestSegment_RoundTrip: Segment -> Reassemble recovers the original PDU,
// for sizes spanning SF, FF+1CF, and several CFs with SN wrap.
func TestSegment_RoundTrip(t *testing.T) {
	for _, n := range []int{1, 7, 8, 13, 20, 119, 200} {
		pdu := make([]byte, n)
		for i := range pdu {
			pdu[i] = byte(i * 7)
		}
		frames, err := Segment(pdu, 0xAA)
		if err != nil {
			t.Fatalf("Segment(%d): %v", n, err)
		}
		r, err := Reassemble(frames)
		if err != nil {
			t.Fatalf("Reassemble(%d): %v", n, err)
		}
		if !r.Complete {
			t.Fatalf("n=%d: not complete: %+v", n, r)
		}
		if r.PayloadHex != up(pdu) {
			t.Errorf("n=%d: round-trip = %s, want %s", n, r.PayloadHex, up(pdu))
		}
	}
}

// TestSegment_SequenceNumbersCycle: a long PDU produces CFs with SN
// 1,2,...,15,0,1 in order.
func TestSegment_SequenceNumbersCycle(t *testing.T) {
	// 6 (FF) + 7*16 = 118 bytes -> FF + 16 CFs, SN 1..15 then 0.
	pdu := make([]byte, 6+7*16)
	frames, err := Segment(pdu, 0x00)
	if err != nil {
		t.Fatalf("Segment: %v", err)
	}
	cfs := frames[1:]
	for i, cf := range cfs {
		wantSN := (i + 1) & 0x0F
		gotSN := int(cf[0] & 0x0F)
		if gotSN != wantSN {
			t.Errorf("CF %d SN = %d, want %d", i, gotSN, wantSN)
		}
		if cf[0]&0xF0 != 0x20 {
			t.Errorf("CF %d PCI high nibble = 0x%X, want 2", i, cf[0]>>4)
		}
	}
}

func TestSegment_AllFramesEightBytes(t *testing.T) {
	frames, _ := Segment(make([]byte, 30), 0x00)
	for i, f := range frames {
		if len(f) != 8 {
			t.Errorf("frame %d length = %d, want 8", i, len(f))
		}
	}
}

func TestSegment_Errors(t *testing.T) {
	if _, err := Segment(nil, 0x00); err == nil {
		t.Error("expected error for empty PDU")
	}
	if _, err := Segment(make([]byte, MaxClassicFFLen+1), 0x00); err == nil {
		t.Error("expected error for over-12-bit PDU")
	}
}
