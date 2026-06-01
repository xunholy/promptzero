// SPDX-License-Identifier: AGPL-3.0-or-later

package ibutton

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestEncode_AN27Vector anchors the encoder against the canonical Maxim
// Application Note 27 worked example: family 0x02, serial 1C B8 01 00
// 00 00 yields CRC 0xA2 — an external reference independent of this
// codebase's own decode tests.
func TestEncode_AN27Vector(t *testing.T) {
	rom, d, err := Encode(0x02, "1CB801000000")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := "021CB801000000A2"
	if got := strings.ToUpper(hex.EncodeToString(rom)); got != want {
		t.Errorf("ROM = %s, want %s", got, want)
	}
	if d.CRC != 0xA2 || !d.CRCValid {
		t.Errorf("CRC = 0x%02X valid=%v, want 0xA2 valid", d.CRC, d.CRCValid)
	}
}

// TestEncode_RepoVectors checks the encoder against the same vectors the
// decode tests assert, so encode and decode stay in lock-step.
func TestEncode_RepoVectors(t *testing.T) {
	cases := []struct {
		family byte
		serial string
		crc    byte
	}{
		{0x01, "020304050607", 0x0F},
		{0x28, "AABBCCDDEEFF", 0x0C},
		{0x01, "000000000000", 0x3D},
	}
	for _, c := range cases {
		_, d, err := Encode(c.family, c.serial)
		if err != nil {
			t.Fatalf("Encode(%02X,%s): %v", c.family, c.serial, err)
		}
		if d.CRC != c.crc {
			t.Errorf("Encode(%02X,%s) CRC = 0x%02X, want 0x%02X", c.family, c.serial, d.CRC, c.crc)
		}
		if !d.CRCValid {
			t.Errorf("Encode(%02X,%s) produced invalid CRC", c.family, c.serial)
		}
	}
}

// TestEncode_RoundTrip confirms Encode → Decode recovers the inputs and
// validates the CRC, the primary internal-consistency guarantee.
func TestEncode_RoundTrip(t *testing.T) {
	rom, _, err := Encode(0x01, "DE:AD:BE:EF:12:34")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	back, err := DecodeBytes(rom)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	if back.FamilyCode != 0x01 {
		t.Errorf("family round-trips to 0x%02X, want 0x01", back.FamilyCode)
	}
	if back.SerialHex != "DEADBEEF1234" {
		t.Errorf("serial round-trips to %s, want DEADBEEF1234", back.SerialHex)
	}
	if !back.CRCValid {
		t.Error("round-tripped ROM has invalid CRC")
	}
}

// TestEncode_ToleratesSeparators confirms the serial accepts the same
// separators / 0x prefix Decode does.
func TestEncode_ToleratesSeparators(t *testing.T) {
	a, _, err := Encode(0x01, "0x02-03-04-05-06-07")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	b, _, err := Encode(0x01, "020304050607")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if hex.EncodeToString(a) != hex.EncodeToString(b) {
		t.Errorf("separator handling diverged: %X vs %X", a, b)
	}
}

// TestEncode_RejectsBadSerial rejects a serial that is not 48 bits.
func TestEncode_RejectsBadSerial(t *testing.T) {
	if _, _, err := Encode(0x01, "0203040506"); err == nil {
		t.Error("expected error for 5-byte serial")
	}
	if _, _, err := Encode(0x01, "02030405060708"); err == nil {
		t.Error("expected error for 7-byte serial")
	}
	if _, _, err := Encode(0x01, "nothex"); err == nil {
		t.Error("expected error for non-hex serial")
	}
}
