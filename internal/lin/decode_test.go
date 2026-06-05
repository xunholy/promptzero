// SPDX-License-Identifier: AGPL-3.0-or-later

package lin

import "testing"

// TestPIDParityConstants anchors the PID-parity computation to the
// well-known LIN protected-identifier constants (ISO 17987 / LIN spec):
// frame ID 0x3C -> PID 0x3C, 0x3D -> 0x7D, 0x00 -> 0x80, 0x01 -> 0xC1.
func TestPIDParityConstants(t *testing.T) {
	cases := map[byte]byte{0x3C: 0x3C, 0x3D: 0x7D, 0x00: 0x80, 0x01: 0xC1, 0x02: 0x42}
	for id, want := range cases {
		if got := pidParity(id); got != want {
			t.Errorf("pidParity(0x%02X) = 0x%02X, want 0x%02X", id, got, want)
		}
	}
}

// TestChecksumCarryFold pins the carry-fold behaviour that distinguishes
// the LIN checksum from a plain sum: 0x80 + 0x80 overflows to 0x100, the
// carry folds to 0x01, inverted -> 0xFE.
func TestChecksumCarryFold(t *testing.T) {
	if got := linChecksum([]byte{0x80, 0x80}); got != 0xFE {
		t.Errorf("checksum(0x80,0x80) = 0x%02X, want 0xFE", got)
	}
	if got := linChecksum([]byte{0x00}); got != 0xFF {
		t.Errorf("checksum(0x00) = 0x%02X, want 0xFF", got)
	}
}

func TestDecodeEnhancedFrame(t *testing.T) {
	// ID 0x01 -> PID 0xC1, data 55 93 E5 38, enhanced checksum 0x37.
	r, err := Decode("C15593E53837")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.PID != "0xC1" || r.FrameID != 0x01 || !r.ParityValid {
		t.Errorf("pid/id/parity = %s / %d / %v", r.PID, r.FrameID, r.ParityValid)
	}
	if r.FrameClass != "signal-carrying frame" {
		t.Errorf("class = %q", r.FrameClass)
	}
	if r.DataLength != 4 || r.DataHex != "5593E538" {
		t.Errorf("data = %d / %s", r.DataLength, r.DataHex)
	}
	if !r.ChecksumValid || r.ChecksumType != "enhanced (PID + data)" {
		t.Errorf("checksum = %v / %q", r.ChecksumValid, r.ChecksumType)
	}
}

func TestDecodeDiagnosticClassic(t *testing.T) {
	// ID 0x3C master-request, classic checksum 0xC3.
	r, err := Decode("3C 3C FF FF FF FF FF FF FF C3")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.FrameID != 0x3C || r.FrameClass != "master request (diagnostic)" {
		t.Errorf("id/class = %d / %q", r.FrameID, r.FrameClass)
	}
	if !r.ChecksumValid || r.ChecksumType != "classic (data only)" {
		t.Errorf("checksum = %v / %q", r.ChecksumValid, r.ChecksumType)
	}
}

func TestDecodeSyncByte(t *testing.T) {
	r, err := Decode("55 C1 55 93 E5 38 37")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.SyncByte || r.FrameID != 0x01 || !r.ChecksumValid {
		t.Errorf("sync/id/cksum = %v / %d / %v", r.SyncByte, r.FrameID, r.ChecksumValid)
	}
}

func TestDecodeBadParity(t *testing.T) {
	// PID 0xC0 has ID 0x00 but the parity of a non-0x00 frame — invalid.
	r, err := Decode("C05593E538AA")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ParityValid {
		t.Error("expected parity_valid=false for PID 0xC0 / ID 0x00 (correct PID is 0x80)")
	}
}

func TestDecodeBadChecksum(t *testing.T) {
	r, err := Decode("C15593E53800")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ChecksumValid || r.ChecksumType != "invalid" {
		t.Errorf("expected invalid checksum, got %v / %q", r.ChecksumValid, r.ChecksumType)
	}
}

func TestDecodeRejects(t *testing.T) {
	for _, c := range []string{"", "C1", "zz", "00112233445566778899AABB"} {
		if _, err := Decode(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add("C15593E53837")
	f.Add("55C15593E53837")
	f.Add("")
	f.Add("3C")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
