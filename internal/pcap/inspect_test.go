// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Michael Fornaro

package pcap

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// helpers --------------------------------------------------------------

func leGlobalHeader(snaplen uint32, network uint32) []byte {
	b := make([]byte, globalHeaderLen)
	// magic 0xa1b2c3d4 stored little-endian
	binary.LittleEndian.PutUint32(b[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(b[4:], pcapVersionMajor)
	binary.LittleEndian.PutUint16(b[6:], pcapVersionMinor)
	binary.LittleEndian.PutUint32(b[8:], 0)
	binary.LittleEndian.PutUint32(b[12:], 0)
	binary.LittleEndian.PutUint32(b[16:], snaplen)
	binary.LittleEndian.PutUint32(b[20:], network)
	return b
}

func beGlobalHeader(snaplen uint32, network uint32, nano bool) []byte {
	b := make([]byte, globalHeaderLen)
	magic := uint32(0xd4c3b2a1)
	if nano {
		magic = 0x4d3cb2a1
	}
	// magic stored little-endian per the wire format convention:
	// readers always read the first 4 bytes as LE to dispatch.
	binary.LittleEndian.PutUint32(b[0:], magic)
	binary.BigEndian.PutUint16(b[4:], pcapVersionMajor)
	binary.BigEndian.PutUint16(b[6:], pcapVersionMinor)
	binary.BigEndian.PutUint32(b[8:], 0)
	binary.BigEndian.PutUint32(b[12:], 0)
	binary.BigEndian.PutUint32(b[16:], snaplen)
	binary.BigEndian.PutUint32(b[20:], network)
	return b
}

func leNanoGlobalHeader(snaplen uint32, network uint32) []byte {
	b := make([]byte, globalHeaderLen)
	binary.LittleEndian.PutUint32(b[0:], 0xa1b23c4d)
	binary.LittleEndian.PutUint16(b[4:], pcapVersionMajor)
	binary.LittleEndian.PutUint16(b[6:], pcapVersionMinor)
	binary.LittleEndian.PutUint32(b[8:], 0)
	binary.LittleEndian.PutUint32(b[12:], 0)
	binary.LittleEndian.PutUint32(b[16:], snaplen)
	binary.LittleEndian.PutUint32(b[20:], network)
	return b
}

func leRecord(tsSec, tsFrac, caplen, origlen uint32, payload []byte) []byte {
	b := make([]byte, perPacketHeaderLen+len(payload))
	binary.LittleEndian.PutUint32(b[0:], tsSec)
	binary.LittleEndian.PutUint32(b[4:], tsFrac)
	binary.LittleEndian.PutUint32(b[8:], caplen)
	binary.LittleEndian.PutUint32(b[12:], origlen)
	copy(b[16:], payload)
	return b
}

func beRecord(tsSec, tsFrac, caplen, origlen uint32, payload []byte) []byte {
	b := make([]byte, perPacketHeaderLen+len(payload))
	binary.BigEndian.PutUint32(b[0:], tsSec)
	binary.BigEndian.PutUint32(b[4:], tsFrac)
	binary.BigEndian.PutUint32(b[8:], caplen)
	binary.BigEndian.PutUint32(b[12:], origlen)
	copy(b[16:], payload)
	return b
}

// tests ----------------------------------------------------------------

func TestInspect_LittleEndianMicrosecond_OneRecord(t *testing.T) {
	payload := make([]byte, 20)
	for i := range payload {
		payload[i] = byte(i)
	}
	data := append(leGlobalHeader(65535, 1), leRecord(100, 500000, 20, 20, payload)...)
	s, err := Inspect(data, DefaultInspectOpts())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if s.Endianness != "little" || s.TimestampResolution != "microsecond" {
		t.Errorf("endianness/resolution: %s / %s", s.Endianness, s.TimestampResolution)
	}
	if s.VersionMajor != 2 || s.VersionMinor != 4 {
		t.Errorf("version: %d.%d", s.VersionMajor, s.VersionMinor)
	}
	if s.SnapLength != 65535 {
		t.Errorf("snaplen: %d", s.SnapLength)
	}
	if s.Network != 1 || s.NetworkName != "LINKTYPE_ETHERNET" {
		t.Errorf("network: %d %q", s.Network, s.NetworkName)
	}
	if s.RecordCount != 1 {
		t.Errorf("record count: %d", s.RecordCount)
	}
	if len(s.Records) != 1 {
		t.Fatalf("records returned: %d", len(s.Records))
	}
	r := s.Records[0]
	if r.CapturedLength != 20 || r.OriginalLength != 20 {
		t.Errorf("lengths: cap=%d orig=%d", r.CapturedLength, r.OriginalLength)
	}
	if r.PayloadBytesShown != 20 {
		t.Errorf("payload bytes shown: %d", r.PayloadBytesShown)
	}
	want := strings.ToUpper(hex.EncodeToString(payload))
	if r.PayloadHex != want {
		t.Errorf("payload hex: got %q want %q", r.PayloadHex, want)
	}
}

func TestInspect_BigEndianMicrosecond(t *testing.T) {
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	data := append(beGlobalHeader(65535, 105, false),
		beRecord(50, 0, uint32(len(payload)), uint32(len(payload)), payload)...)
	s, err := Inspect(data, DefaultInspectOpts())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if s.Endianness != "big" || s.TimestampResolution != "microsecond" {
		t.Errorf("endianness/resolution: %s / %s", s.Endianness, s.TimestampResolution)
	}
	if s.Network != 105 || s.NetworkName != "LINKTYPE_IEEE802_11" {
		t.Errorf("network: %d %q", s.Network, s.NetworkName)
	}
}

func TestInspect_LittleEndianNanosecond(t *testing.T) {
	data := append(leNanoGlobalHeader(65535, 127),
		leRecord(10, 500000000, 0, 0, nil)...)
	s, err := Inspect(data, DefaultInspectOpts())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if s.TimestampResolution != "nanosecond" {
		t.Errorf("resolution: %s", s.TimestampResolution)
	}
	if s.NetworkName != "LINKTYPE_IEEE802_11_RADIOTAP" {
		t.Errorf("network: %q", s.NetworkName)
	}
}

func TestInspect_BigEndianNanosecond(t *testing.T) {
	data := beGlobalHeader(65535, 1, true)
	s, err := Inspect(data, DefaultInspectOpts())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if s.Endianness != "big" || s.TimestampResolution != "nanosecond" {
		t.Errorf("endianness/resolution: %s / %s", s.Endianness, s.TimestampResolution)
	}
}

func TestInspect_MultipleRecords_DurationCalc(t *testing.T) {
	// 3 records: t=100, t=105, t=110 → duration = 10s.
	data := leGlobalHeader(65535, 1)
	data = append(data, leRecord(100, 0, 4, 4, []byte{1, 2, 3, 4})...)
	data = append(data, leRecord(105, 0, 4, 4, []byte{5, 6, 7, 8})...)
	data = append(data, leRecord(110, 0, 4, 4, []byte{9, 10, 11, 12})...)
	s, err := Inspect(data, DefaultInspectOpts())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if s.RecordCount != 3 {
		t.Errorf("record count: %d", s.RecordCount)
	}
	if s.TotalRecordBytes != 12 {
		t.Errorf("total bytes: %d", s.TotalRecordBytes)
	}
	if s.DurationSeconds != 10 {
		t.Errorf("duration: %f", s.DurationSeconds)
	}
}

func TestInspect_TruncatedRecord(t *testing.T) {
	// Declare 100 bytes of payload but only supply 10.
	hdr := leRecord(1, 0, 100, 100, nil)[:perPacketHeaderLen]
	data := append(leGlobalHeader(65535, 1), hdr...)
	data = append(data, make([]byte, 10)...)
	s, err := Inspect(data, DefaultInspectOpts())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !s.Records[0].Truncated {
		t.Errorf("expected truncated record")
	}
	found := false
	for _, n := range s.Notes {
		if strings.Contains(n, "truncated") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected truncated note in: %v", s.Notes)
	}
}

func TestInspect_BadMagic(t *testing.T) {
	data := make([]byte, globalHeaderLen)
	binary.LittleEndian.PutUint32(data[0:], 0xDEADBEEF)
	_, err := Inspect(data, DefaultInspectOpts())
	if err == nil {
		t.Fatal("expected error for unrecognised magic")
	}
}

func TestInspect_TruncatedGlobalHeader(t *testing.T) {
	_, err := Inspect(make([]byte, 10), DefaultInspectOpts())
	if err == nil {
		t.Fatal("expected error for short global header")
	}
}

func TestInspect_UnknownLinkType(t *testing.T) {
	data := leGlobalHeader(65535, 999)
	s, err := Inspect(data, DefaultInspectOpts())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !strings.Contains(s.NetworkName, "uncatalogued") {
		t.Errorf("expected uncatalogued link type, got %q", s.NetworkName)
	}
}

func TestInspect_LinkTypeNameSpotCheck(t *testing.T) {
	cases := map[uint32]string{
		0:   "LINKTYPE_NULL (BSD loopback)",
		1:   "LINKTYPE_ETHERNET",
		101: "LINKTYPE_RAW (raw IPv4/v6)",
		105: "LINKTYPE_IEEE802_11",
		113: "LINKTYPE_LINUX_SLL (Linux cooked v1)",
		127: "LINKTYPE_IEEE802_11_RADIOTAP",
		187: "LINKTYPE_BLUETOOTH_HCI_H4",
		228: "LINKTYPE_IPV4",
		229: "LINKTYPE_IPV6",
	}
	for k, v := range cases {
		if got := LinkTypeName(k); got != v {
			t.Errorf("LinkTypeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestInspect_MaxRecords_Caps(t *testing.T) {
	data := leGlobalHeader(65535, 1)
	for i := 0; i < 10; i++ {
		data = append(data, leRecord(uint32(i), 0, 1, 1, []byte{byte(i)})...)
	}
	s, err := Inspect(data, InspectOpts{MaxRecords: 3, MaxPayloadBytes: 16})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if s.RecordCount != 10 {
		t.Errorf("full count: %d", s.RecordCount)
	}
	if len(s.Records) != 3 {
		t.Errorf("returned count: %d", len(s.Records))
	}
}

func TestInspect_MaxPayloadBytes_Caps(t *testing.T) {
	payload := make([]byte, 100)
	for i := range payload {
		payload[i] = byte(i)
	}
	data := append(leGlobalHeader(65535, 1), leRecord(1, 0, 100, 100, payload)...)
	s, err := Inspect(data, InspectOpts{MaxRecords: 1, MaxPayloadBytes: 32})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if s.Records[0].PayloadBytesShown != 32 {
		t.Errorf("payload shown: %d", s.Records[0].PayloadBytesShown)
	}
	if len(s.Records[0].PayloadHex) != 64 {
		t.Errorf("payload hex chars: %d (expected 64)", len(s.Records[0].PayloadHex))
	}
}

func TestInspect_TrailingBytesNote(t *testing.T) {
	// Add 5 trailing bytes after the last full record but
	// less than a record header (16 bytes).
	data := append(leGlobalHeader(65535, 1), leRecord(1, 0, 4, 4, []byte{1, 2, 3, 4})...)
	data = append(data, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE)
	s, err := Inspect(data, DefaultInspectOpts())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	found := false
	for _, n := range s.Notes {
		if strings.Contains(n, "trailing") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected trailing-bytes note in: %v", s.Notes)
	}
}
