// SPDX-License-Identifier: AGPL-3.0-or-later

package wmbus

import (
	"encoding/hex"
	"testing"
)

// validFrame is a Format-A wM-Bus frame with all block CRC-16s valid:
// an Elster (ELS) gas meter, ID 12345678, version 0x33, control SND-NR,
// a 0x7A short-header application block. The block-1 CRC (0xBF8D) and the
// data-block CRC (0xA85A) are the EN 13757 CRC of the respective bytes.
const validFrame = "0D449315785634123303BF8D7A2A0020A85A"

func TestDecodeValidFrame(t *testing.T) {
	r, err := Decode(validFrame)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.BlocksValid {
		t.Errorf("blocks should all be CRC-valid")
	}
	if r.CField != "0x44" || r.CFieldName[:6] != "SND-NR" {
		t.Errorf("c-field = %s / %q", r.CField, r.CFieldName)
	}
	if r.Manufacturer != "ELS" || r.ManufacturerID != "0x1593" {
		t.Errorf("manufacturer = %s / %s, want ELS / 0x1593", r.Manufacturer, r.ManufacturerID)
	}
	if r.MeterID != "12345678" {
		t.Errorf("meter id = %s, want 12345678", r.MeterID)
	}
	if r.Version != 0x33 || r.DeviceType != "0x03" || r.DeviceTypeName != "gas" {
		t.Errorf("version/type = %d / %s / %s", r.Version, r.DeviceType, r.DeviceTypeName)
	}
	if r.CIField != "0x7A" || r.PayloadHex != "7A2A0020" {
		t.Errorf("ci/payload = %s / %s, want 0x7A / 7A2A0020", r.CIField, r.PayloadHex)
	}
}

// TestRealWorldBlock1CRC anchors the EN 13757 CRC-16 to a real meter
// header block (Elster gas, ID 12345678): 2e449315785634123303 -> 0x3363.
func TestRealWorldBlock1CRC(t *testing.T) {
	b, _ := hex.DecodeString("2e449315785634123303")
	if got := crc16Wmbus(b); got != 0x3363 {
		t.Errorf("CRC-16 = 0x%04X, want 0x3363", got)
	}
}

func TestManufacturerFLAG(t *testing.T) {
	// 0x1593 -> ELS; 0x2C2D -> KAM (Kamstrup).
	if m := manufacturerFLAG(0x1593); m != "ELS" {
		t.Errorf("0x1593 -> %q, want ELS", m)
	}
	if m := manufacturerFLAG(0x2C2D); m != "KAM" {
		t.Errorf("0x2C2D -> %q, want KAM", m)
	}
}

func TestDecodeCorruptCRC(t *testing.T) {
	// Flip the last byte of the data-block CRC — must report invalid.
	r, err := Decode("0D449315785634123303BF8D7A2A0020A85B")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.BlocksValid {
		t.Error("expected all_blocks_crc_valid=false for a corrupted CRC")
	}
	// Header still decodes.
	if r.Manufacturer != "ELS" || r.MeterID != "12345678" {
		t.Errorf("header should still decode: %s / %s", r.Manufacturer, r.MeterID)
	}
}

func TestDecodeRejects(t *testing.T) {
	for _, c := range []string{"", "0D44", "zz"} {
		if _, err := Decode(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(validFrame)
	f.Add("0D44")
	f.Add("")
	f.Add("FF449315785634123303BF8D")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
