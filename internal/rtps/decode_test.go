// SPDX-License-Identifier: AGPL-3.0-or-later

package rtps

import "testing"

// The header (magic / version / vendor / GUID prefix) was verified against
// scapy's RTPS layer (scapy.contrib.rtps), which also confirmed the
// INFO_TS + DATA submessage boundaries (id + octetsToNextHeader). The
// submessage walk follows the RTPS-spec octetsToNextHeader boundary.

func TestDecodeHeaderAndWalk(t *testing.T) {
	// RTPS v2.4, vendor 0x0103 (OpenDDS), guid 0102..0c; then INFO_TS (id 9,
	// 8-byte body, LE), DATA (id 0x15, 16-byte body, LE), HEARTBEAT (id 7,
	// 28-byte body, LE).
	const v = "52545053" + "0204" + "0103" + "0102030405060708090a0b0c" +
		"09010800" + "1122334455667788" +
		"15011000" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
		"07011c00" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ProtocolVersion != "2.4" {
		t.Errorf("version = %q, want 2.4", r.ProtocolVersion)
	}
	if r.VendorID != "0x0103" || r.VendorName != "OCI OpenDDS" {
		t.Errorf("vendor = %q/%q", r.VendorID, r.VendorName)
	}
	if r.GUIDPrefix != "0102030405060708090A0B0C" {
		t.Errorf("guid = %q", r.GUIDPrefix)
	}
	if len(r.SubMessages) != 3 {
		t.Fatalf("submessages = %d, want 3 (%+v)", len(r.SubMessages), r.SubMessages)
	}
	want := []struct {
		kind int
		name string
		oct  int
	}{
		{0x09, "INFO_TS", 8},
		{0x15, "DATA", 16},
		{0x07, "HEARTBEAT", 28},
	}
	for i, w := range want {
		sm := r.SubMessages[i]
		if sm.Kind != w.kind || sm.KindName != w.name || sm.OctetsToNext != w.oct {
			t.Errorf("submsg %d = %d/%q/%d, want %d/%q/%d", i, sm.Kind, sm.KindName, sm.OctetsToNext, w.kind, w.name, w.oct)
		}
		if sm.Endianness != "little-endian" {
			t.Errorf("submsg %d endianness = %q", i, sm.Endianness)
		}
	}
}

func TestDecodeInfoDst(t *testing.T) {
	// header + INFO_DST (id 0x0e) carrying a destination GUID prefix.
	const v = "52545053020401010000000000000000000000000e0c0c00" + "aabbccddeeff00112233445566"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.VendorName != "RTI Connext DDS" {
		t.Errorf("vendor = %q", r.VendorName)
	}
	if len(r.SubMessages) != 1 || r.SubMessages[0].KindName != "INFO_DST" {
		t.Fatalf("submsgs = %+v", r.SubMessages)
	}
	if r.SubMessages[0].DestGUIDPrefix != "AABBCCDDEEFF001122334455" {
		t.Errorf("dest guid = %q", r.SubMessages[0].DestGUIDPrefix)
	}
}

func TestDecodeBigEndian(t *testing.T) {
	// A big-endian submessage (flags bit0 = 0): octetsToNextHeader read BE.
	const v = "52545053020401100000000000000000000000000700000401020304"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.VendorName != "Eclipse Cyclone DDS" {
		t.Errorf("vendor = %q", r.VendorName)
	}
	sm := r.SubMessages[0]
	if sm.Endianness != "big-endian" || sm.OctetsToNext != 4 {
		t.Errorf("submsg = %q/%d, want big-endian/4", sm.Endianness, sm.OctetsToNext)
	}
}

func TestDecodeRejectsNonRTPS(t *testing.T) {
	if _, err := Decode("4e4f504500000000000000000000000000000000"); err == nil {
		t.Fatal("expected rejection of non-RTPS magic")
	}
	if _, err := Decode("52545053"); err == nil {
		t.Fatal("expected error on short header")
	}
}
