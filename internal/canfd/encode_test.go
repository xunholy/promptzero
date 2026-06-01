// SPDX-License-Identifier: AGPL-3.0-or-later

package canfd

import (
	"encoding/hex"
	"testing"
)

func TestEncode_ClassicFixed(t *testing.T) {
	s, err := Encode(EncodeRequest{ID: 0x123, Data: mustB(t, "DEADBEEF")})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if s != "123#DEADBEEF" {
		t.Errorf("frame = %q, want 123#DEADBEEF", s)
	}
}

func TestEncode_ExtendedPadding(t *testing.T) {
	// Extended IDs are zero-padded to 8 hex chars so Decode infers 29-bit.
	s, err := Encode(EncodeRequest{ID: 0x18FEF100, Extended: true, Data: mustB(t, "FF")})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if s != "18FEF100#FF" {
		t.Errorf("frame = %q, want 18FEF100#FF", s)
	}
}

func TestEncode_FDWithBRS(t *testing.T) {
	// 12-byte payload (legal FD length), BRS set -> flags nibble 1.
	s, err := Encode(EncodeRequest{ID: 0x123, FD: true, BRS: true, Data: make([]byte, 12)})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if s[:6] != "123##1" {
		t.Errorf("frame prefix = %q, want 123##1", s[:6])
	}
}

func TestEncode_RemoteFrame(t *testing.T) {
	s, err := Encode(EncodeRequest{ID: 0x7DF, RTR: true, RemoteDLC: 8})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if s != "7DF#R8" {
		t.Errorf("frame = %q, want 7DF#R8", s)
	}
}

// TestEncode_RoundTrip is the verification anchor: Encode -> Decode recovers
// every field, with no external reference vector.
func TestEncode_RoundTrip(t *testing.T) {
	cases := []EncodeRequest{
		{ID: 0x123, Data: mustB(t, "0102030405060708")},          // classic 8
		{ID: 0x7FF, Data: mustB(t, "AA")},                        // max standard
		{ID: 0x18DAF110, Extended: true, Data: mustB(t, "0211")}, // extended (UDS phys addr)
		{ID: 0x100, FD: true, BRS: true, ESI: true, Data: make([]byte, 16)},
		{ID: 0x200, FD: true, Data: make([]byte, 64)}, // max FD
		{ID: 0x7DF, RTR: true, RemoteDLC: 8},
	}
	for i, c := range cases {
		s, err := Encode(c)
		if err != nil {
			t.Fatalf("case %d Encode: %v", i, err)
		}
		d, err := Decode(s)
		if err != nil {
			t.Fatalf("case %d Decode(%q): %v", i, s, err)
		}
		if d.IDDecimal != c.ID || d.Extended != c.Extended || d.FDF != c.FD {
			t.Errorf("case %d: id/ext/fd = %X/%v/%v, want %X/%v/%v", i, d.IDDecimal, d.Extended, d.FDF, c.ID, c.Extended, c.FD)
		}
		if d.BRS != c.BRS || d.ESI != c.ESI || d.RTR != c.RTR {
			t.Errorf("case %d: brs/esi/rtr = %v/%v/%v, want %v/%v/%v", i, d.BRS, d.ESI, d.RTR, c.BRS, c.ESI, c.RTR)
		}
		if !c.RTR && d.DataHex != upHex(c.Data) {
			t.Errorf("case %d: data = %s, want %s", i, d.DataHex, upHex(c.Data))
		}
	}
}

func TestEncode_Errors(t *testing.T) {
	bad := []EncodeRequest{
		{ID: 0x20000000},                           // > 29-bit
		{ID: 0x800},                                // > 11-bit without Extended
		{ID: 0x1, Data: make([]byte, 9)},           // classic > 8 bytes
		{ID: 0x1, FD: true, Data: make([]byte, 9)}, // illegal FD length (9)
		{ID: 0x1, FD: true, RTR: true},             // RTR on FD
		{ID: 0x1, BRS: true},                       // BRS on classic
		{ID: 0x1, RTR: true, RemoteDLC: 9},         // remote DLC > 8
	}
	for i, c := range bad {
		if _, err := Encode(c); err == nil {
			t.Errorf("case %d (%+v): expected error", i, c)
		}
	}
}

func mustB(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func upHex(b []byte) string {
	return hexUpper(b)
}

func hexUpper(b []byte) string {
	const h = "0123456789ABCDEF"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = h[c>>4]
		out[i*2+1] = h[c&0x0F]
	}
	return string(out)
}
