// SPDX-License-Identifier: AGPL-3.0-or-later

package t2t

import "testing"

// A realistic data area: Lock Control TLV, an NDEF Message TLV wrapping a
// Text record ("hi", lang "en"), then the Terminator.
//
//	01 03 AABBCC                       Lock Control (3-byte value)
//	03 09 D1 01 05 54 02 65 6E 68 69   NDEF (Text record "hi")
//	FE                                 Terminator
func TestDecodeTLV_FullDataArea(t *testing.T) {
	res, err := DecodeTLVHex("01 03 AABBCC 03 09 D1010554 02656E6869 FE")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Blocks) != 3 {
		t.Fatalf("want 3 blocks, got %d: %+v", len(res.Blocks), res.Blocks)
	}

	lock := res.Blocks[0]
	if lock.Type != "Lock Control" || lock.Length != 3 || lock.ValueHex != "AABBCC" {
		t.Errorf("lock control block = %+v", lock)
	}

	ndefBlk := res.Blocks[1]
	if ndefBlk.Type != "NDEF Message" || ndefBlk.Offset != 5 || ndefBlk.Length != 9 {
		t.Errorf("ndef block = %+v", ndefBlk)
	}
	if ndefBlk.NDEF == nil || ndefBlk.NDEF.Count != 1 || ndefBlk.NDEF.Records[0].Type != "T" {
		t.Errorf("NDEF not decoded in place: %+v", ndefBlk.NDEF)
	}

	if res.Blocks[2].Type != "Terminator" {
		t.Errorf("block 2 = %s, want Terminator", res.Blocks[2].Type)
	}
}

func TestDecodeTLV_NullSkippedAndTerminatorStops(t *testing.T) {
	// NULL, NULL, Terminator, then trailing bytes that must be ignored.
	res, err := DecodeTLVHex("0000FE 03 0A DEADBEEF")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Blocks) != 3 {
		t.Fatalf("want 3 blocks (NULL, NULL, Terminator), got %d", len(res.Blocks))
	}
	if res.Blocks[0].Type != "NULL" || res.Blocks[1].Type != "NULL" || res.Blocks[2].Type != "Terminator" {
		t.Errorf("block types = %s/%s/%s", res.Blocks[0].Type, res.Blocks[1].Type, res.Blocks[2].Type)
	}
}

func TestDecodeTLV_ThreeByteLength(t *testing.T) {
	// Proprietary TLV with the 0xFF 2-byte length escape: FD FF 0002 AABB.
	res, err := DecodeTLVHex("FDFF0002AABB")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Blocks) != 1 {
		t.Fatalf("want 1 block, got %d", len(res.Blocks))
	}
	b := res.Blocks[0]
	if b.Type != "Proprietary" || b.Length != 2 || b.ValueHex != "AABB" {
		t.Errorf("3-byte-length block = %+v", b)
	}
}

func TestDecodeTLV_UnknownTypeSkipped(t *testing.T) {
	// Unknown TLV 0x7A with length 2, then NDEF-less terminator.
	res, err := DecodeTLVHex("7A02 1234 FE")
	if err != nil {
		t.Fatal(err)
	}
	if res.Blocks[0].Type != "Unknown (0x7A)" || res.Blocks[0].Length != 2 {
		t.Errorf("unknown block = %+v", res.Blocks[0])
	}
}

func TestDecodeTLV_TruncatedValueNoted(t *testing.T) {
	// NDEF TLV declares length 10 but only 1 value byte present.
	res, err := DecodeTLVHex("030AD1")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Notes) == 0 {
		t.Error("truncated value should be noted")
	}
}

func TestDecodeTLV_NoTerminatorNoted(t *testing.T) {
	res, err := DecodeTLVHex("0103AABBCC")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Notes) == 0 {
		t.Error("missing terminator should be noted")
	}
}

func TestDecodeTLV_Errors(t *testing.T) {
	if _, err := DecodeTLVHex(""); err == nil {
		t.Error("empty should error")
	}
	if _, err := DecodeTLVHex("zz"); err == nil {
		t.Error("non-hex should error")
	}
}
