// SPDX-License-Identifier: AGPL-3.0-or-later

package erspan

import (
	"strings"
	"testing"
)

// Field values are scapy's (scapy.contrib.erspan) decode of the same headers.

func TestDecodeTypeII(t *testing.T) {
	// ver=1 vlan=100 cos=3 en=1 t=0 session_id=42 index=12345, then a frame.
	r, err := Decode("1064682a00003039aabbccddeeff")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 1 || r.Type != "Type II" {
		t.Errorf("version/type = %d/%q", r.Version, r.Type)
	}
	if r.VLAN != 100 || r.COS != 3 || r.SessionID != 42 || r.Truncated {
		t.Errorf("vlan/cos/session/trunc = %d/%d/%d/%v", r.VLAN, r.COS, r.SessionID, r.Truncated)
	}
	if r.EncapType == nil || *r.EncapType != 1 || r.Index == nil || *r.Index != 12345 {
		t.Errorf("encap/index = %v/%v", r.EncapType, r.Index)
	}
	if r.MirroredFrameHex != "AABBCCDDEEFF" {
		t.Errorf("mirrored = %q", r.MirroredFrameHex)
	}
}

func TestDecodeTypeIIMax(t *testing.T) {
	// ver=1 vlan=4094 cos=7 en=3 t=1 session_id=1023 index=0
	r, err := Decode("1ffeffff00000000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.VLAN != 4094 || r.COS != 7 || r.SessionID != 1023 || !r.Truncated {
		t.Errorf("max-field decode wrong: %+v", r)
	}
	if r.EncapType == nil || *r.EncapType != 3 {
		t.Errorf("EncapType = %v; want 3", r.EncapType)
	}
}

func TestDecodeTypeIII(t *testing.T) {
	// ver=2 vlan=200 cos=5 session_id=99 timestamp=0x11223344
	r, err := Decode("20c8a0631122334400000000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 2 || r.Type != "Type III" {
		t.Errorf("version/type = %d/%q", r.Version, r.Type)
	}
	if r.VLAN != 200 || r.COS != 5 || r.SessionID != 99 {
		t.Errorf("vlan/cos/session = %d/%d/%d", r.VLAN, r.COS, r.SessionID)
	}
	if r.Timestamp == nil || *r.Timestamp != 0x11223344 {
		t.Errorf("Timestamp = %v; want 0x11223344", r.Timestamp)
	}
}

func TestDecodeGREWrapped(t *testing.T) {
	// GRE with S bit set (0x10) + protocol 0x88BE + 4-byte sequence, then ERSPAN II.
	gre := "1000" + "88be" + "00000001"
	erspanII := "1064682a00003039aabbccddeeff"
	r, err := Decode(gre + erspanII)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 1 || r.VLAN != 100 || r.SessionID != 42 {
		t.Errorf("GRE-stripped decode wrong: %+v", r)
	}
	if r.MirroredFrameHex != "AABBCCDDEEFF" {
		t.Errorf("mirrored = %q", r.MirroredFrameHex)
	}
}

func TestDecodeRejects(t *testing.T) {
	for _, c := range []string{"", "zz", "1064", "3000000000000000"} { // empty / non-hex / short / bad version 3
		if _, err := Decode(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func TestMonitoringNote(t *testing.T) {
	r, _ := Decode("1064682a00003039")
	if !strings.Contains(strings.Join(r.Notes, " "), "mirror") {
		t.Error("expected the SPAN/mirror monitoring note")
	}
}

func FuzzDecode(f *testing.F) {
	f.Add("1064682a00003039aabbccddeeff")
	f.Add("20c8a0631122334400000000")
	f.Add("100088be000000011064682a00003039aabbccddeeff")
	f.Add("")
	f.Add("10")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
