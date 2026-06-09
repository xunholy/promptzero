// SPDX-License-Identifier: AGPL-3.0-or-later

package ir

import "testing"

// rcaVector is the Flipper firmware's own RCA decoder unit-test capture
// (applications/debug/unit_tests/resources/unit_tests/infrared/test_rca.irtest,
// decoder_input1 → decoder_expected1: address 0x0F, command 0x54), with the
// leading 1000000µs silence stripped so the string begins at the 4000µs leader.
const rcaVector = "3994 3969 552 1945 551 1945 552 1945 551 1945 552 946 551 947 550 1947 548 951 546 1953 542 979 518 1979 517 981 492 1006 491 1006 492 1006 492 1006 492 2005 492 2005 492 1006 492 2005 492 1006 492 2005 492 1006 492 2006 491"

func TestRCA_FlipperVector(t *testing.T) {
	res, err := DecodeRaw(rcaVector)
	if err != nil {
		t.Fatalf("DecodeRaw: %v", err)
	}
	if res.Protocol != "RCA" {
		t.Errorf("protocol = %q, want RCA", res.Protocol)
	}
	if res.Address != 0x0F {
		t.Errorf("address = 0x%02X, want 0x0F", res.Address)
	}
	if res.Command != 0x54 {
		t.Errorf("command = 0x%02X, want 0x54", res.Command)
	}
	if !res.ChecksumValid {
		t.Errorf("expected checksum valid (both inverse fields hold)")
	}
}

// TestRCA_RoundTrip confirms encodeRCA ∘ decodeRCA is identity across the
// 4-bit-address / 8-bit-command space (the verification anchor for the encoder).
func TestRCA_RoundTrip(t *testing.T) {
	for addr := 0; addr <= 0xF; addr++ {
		for _, cmd := range []int{0x00, 0x01, 0x54, 0x7F, 0x80, 0xAB, 0xFF} {
			enc, err := EncodeRaw("RCA", addr, cmd, EncodeOptions{})
			if err != nil {
				t.Fatalf("encode 0x%X/0x%02X: %v", addr, cmd, err)
			}
			res, err := DecodeRaw(enc)
			if err != nil {
				t.Fatalf("decode of encoded 0x%X/0x%02X: %v", addr, cmd, err)
			}
			if res.Address != addr || res.Command != cmd || !res.ChecksumValid {
				t.Errorf("round-trip 0x%X/0x%02X -> 0x%X/0x%02X (valid=%v)", addr, cmd, res.Address, res.Command, res.ChecksumValid)
			}
		}
	}
}

// TestRCA_ChecksumFail flips a command-inverse bit and confirms the frame is
// surfaced unverified rather than asserted valid.
func TestRCA_ChecksumFail(t *testing.T) {
	enc := encodeRCA(0x0F, 0x54)
	// enc[2:] are the 24 bit (mark,space) pairs + stop. Corrupt the first
	// command-inverse bit's space (bit 16 → timing index 2 + 16*2 + 1).
	idx := 2 + 16*2 + 1
	if enc[idx] == rcaOneSpace {
		enc[idx] = rcaZeroSpace
	} else {
		enc[idx] = rcaOneSpace
	}
	res, err := decodeRCA(enc)
	if err != nil {
		t.Fatalf("decode corrupted: %v", err)
	}
	if res.ChecksumValid {
		t.Errorf("corrupted frame reported checksum-valid")
	}
}

// TestRCA_SamsungNotClaimed confirms a Samsung leader (4500/4500) is not claimed
// by the RCA gate (tight ±350µs around 4000).
func TestRCA_SamsungNotClaimed(t *testing.T) {
	sams, err := EncodeRaw("SAMSUNG", 0x07, 0x02, EncodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := DecodeRaw(sams)
	if err != nil {
		t.Fatalf("decode samsung: %v", err)
	}
	if res.Protocol == "RCA" {
		t.Errorf("Samsung frame misdispatched to RCA")
	}
}
