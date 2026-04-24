// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Michael Fornaro

package pcap

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// parseRadiotap reads back the fields from a 16-byte radiotap buf using
// the same offsets as RadiotapHeader.Bytes().
func parseRadiotap(b []byte) RadiotapHeader {
	le := binary.LittleEndian
	return RadiotapHeader{
		Flags:     b[8],
		Rate:      b[9],
		Channel:   le.Uint16(b[10:]),
		SignalDBM: int8(b[14]),
	}
}

// ---- basic field round-trip -----------------------------------------------

func TestRadiotapBytes_Fields(t *testing.T) {
	h := RadiotapHeader{
		Channel:   2437, // channel 6
		Flags:     0x10, // FCS present
		SignalDBM: -65,
		Rate:      2, // 1 Mbit/s
	}
	b := h.Bytes()

	if len(b) != radiotapHeaderLen {
		t.Fatalf("len = %d, want %d", len(b), radiotapHeaderLen)
	}

	got := parseRadiotap(b)
	if got.Channel != h.Channel {
		t.Errorf("Channel: got %d, want %d", got.Channel, h.Channel)
	}
	if got.Flags != h.Flags {
		t.Errorf("Flags: got 0x%02x, want 0x%02x", got.Flags, h.Flags)
	}
	if got.SignalDBM != h.SignalDBM {
		t.Errorf("SignalDBM: got %d, want %d", got.SignalDBM, h.SignalDBM)
	}
	if got.Rate != h.Rate {
		t.Errorf("Rate: got %d, want %d", got.Rate, h.Rate)
	}
}

// ---- fixed header fields --------------------------------------------------

func TestRadiotapBytes_FixedFields(t *testing.T) {
	b := RadiotapHeader{Channel: 2412}.Bytes()
	le := binary.LittleEndian

	if b[0] != 0 {
		t.Errorf("it_version = %d, want 0", b[0])
	}
	if b[1] != 0 {
		t.Errorf("it_pad = %d, want 0", b[1])
	}
	if itLen := le.Uint16(b[2:]); itLen != radiotapHeaderLen {
		t.Errorf("it_len = %d, want %d", itLen, radiotapHeaderLen)
	}
	if present := le.Uint32(b[4:]); present != radiotapPresentBitmap {
		t.Errorf("it_present = 0x%08x, want 0x%08x", present, radiotapPresentBitmap)
	}
}

// ---- channel flags: 2 GHz vs 5 GHz heuristic -----------------------------

func TestRadiotapChannelFlags(t *testing.T) {
	le := binary.LittleEndian

	tests := []struct {
		freq      uint16
		wantFlags uint16
		label     string
	}{
		{2412, 0x0080, "2.4 GHz"},
		{2472, 0x0080, "2.4 GHz high"},
		{5180, 0x0100, "5 GHz"},
		{5825, 0x0100, "5 GHz high"},
		{0, 0x0000, "unknown"},
	}

	for _, tc := range tests {
		b := RadiotapHeader{Channel: tc.freq}.Bytes()
		flags := le.Uint16(b[12:])
		if flags != tc.wantFlags {
			t.Errorf("%s (freq=%d): channel flags = 0x%04x, want 0x%04x",
				tc.label, tc.freq, flags, tc.wantFlags)
		}
	}
}

// ---- negative RSSI preservation -------------------------------------------

func TestRadiotapNegativeRSSI(t *testing.T) {
	for _, rssi := range []int8{-50, -90, -100, -1} {
		b := RadiotapHeader{SignalDBM: rssi}.Bytes()
		got := int8(b[14])
		if got != rssi {
			t.Errorf("SignalDBM round-trip: got %d, want %d", got, rssi)
		}
	}
}

// ---- integration: radiotap-prefixed frame survives pcap round-trip --------

func TestRadiotapWriterRoundTrip(t *testing.T) {
	hdr := RadiotapHeader{
		Channel:   5180,
		Flags:     0x00,
		SignalDBM: -72,
		Rate:      12, // 6 Mbit/s
	}
	frame80211 := []byte{
		0x80, 0x00, 0x00, 0x00, // beacon frame control
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst: broadcast
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // bssid
		0x00, 0x00, // seq
	}
	fullFrame := append(hdr.Bytes(), frame80211...)

	var buf bytes.Buffer
	w, err := NewWriter(&buf, LinkTypeIEEE802_11Radiotap)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	ts := time.Unix(1_700_000_000, 500_000).UTC() // 0.5 ms sub-second
	if err := w.WritePacket(ts, fullFrame); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	r, err := NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	if r.LinkType() != LinkTypeIEEE802_11Radiotap {
		t.Errorf("LinkType = %d, want %d", r.LinkType(), LinkTypeIEEE802_11Radiotap)
	}

	gotTs, gotData, err := r.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}

	wantTs := ts.Truncate(time.Microsecond)
	if !gotTs.Equal(wantTs) {
		t.Errorf("ts: got %v, want %v", gotTs, wantTs)
	}
	if !bytes.Equal(gotData, fullFrame) {
		t.Errorf("data mismatch: got %d bytes, want %d bytes", len(gotData), len(fullFrame))
	}

	// Re-parse the radiotap header from the recovered bytes.
	gotHdr := parseRadiotap(gotData)
	if gotHdr.Channel != hdr.Channel {
		t.Errorf("recovered Channel: got %d, want %d", gotHdr.Channel, hdr.Channel)
	}
	if gotHdr.SignalDBM != hdr.SignalDBM {
		t.Errorf("recovered SignalDBM: got %d, want %d", gotHdr.SignalDBM, hdr.SignalDBM)
	}
}
