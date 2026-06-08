// SPDX-License-Identifier: AGPL-3.0-or-later

package pocsag

import "testing"

// TestBCHSyndromeOnValidCodewords confirms the canonical idle/sync
// codewords and every synth-built codeword have a zero syndrome —
// pinning the generator polynomial and the syndrome arithmetic.
func TestBCHSyndromeOnValidCodewords(t *testing.T) {
	if s := bchSyndrome(IdleWord); s != 0 {
		t.Errorf("bchSyndrome(IdleWord) = 0x%X; want 0 — idle word must be a valid BCH codeword", s)
	}
	if s := bchSyndrome(SyncWord); s != 0 {
		t.Errorf("bchSyndrome(SyncWord) = 0x%X; want 0 — POCSAG sync word is a valid BCH codeword", s)
	}
	for _, data := range []uint32{0x00000, 0x12345, 0xFFFFF, 0xABCDE, 0x80000, 0x1F2E3} {
		w := buildCodeword(data)
		if s := bchSyndrome(w); s != 0 {
			t.Errorf("bchSyndrome(buildCodeword(0x%05X)=0x%08X) = 0x%X; want 0", data, w, s)
		}
	}
}

// TestBCHCorrectSingleBit flips each of the 31 BCH-protected bit
// positions in a valid codeword and confirms bchCorrect recovers the
// original exactly, reporting one fixed error.
func TestBCHCorrectSingleBit(t *testing.T) {
	for _, data := range []uint32{0x12345, 0xABCDE, 0x00001, 0xFFFFE} {
		want := buildCodeword(data)
		for pos := 1; pos <= 31; pos++ {
			corrupt := want ^ (1 << uint(pos))
			got, nfix, ok := bchCorrect(corrupt)
			if !ok || nfix != 1 || got != want {
				t.Errorf("data 0x%05X bit %d: bchCorrect = (0x%08X, %d, %v); want (0x%08X, 1, true)",
					data, pos, got, nfix, ok, want)
			}
		}
	}
}

// TestBCHCorrectDoubleBit flips pairs of BCH-protected bits and
// confirms bchCorrect recovers the original, reporting two fixed
// errors. (Spot-checks a spread of pairs rather than all 465.)
func TestBCHCorrectDoubleBit(t *testing.T) {
	want := buildCodeword(0x12345)
	pairs := [][2]int{{1, 2}, {1, 31}, {5, 17}, {10, 11}, {15, 30}, {3, 28}, {20, 21}}
	for _, p := range pairs {
		corrupt := want ^ (1 << uint(p[0])) ^ (1 << uint(p[1]))
		got, nfix, ok := bchCorrect(corrupt)
		if !ok || nfix != 2 || got != want {
			t.Errorf("bits %v: bchCorrect = (0x%08X, %d, %v); want (0x%08X, 2, true)",
				p, got, nfix, ok, want)
		}
	}
}

// TestBCHCorrectUncorrectable confirms a 3-bit error (beyond the
// code's t=2 capacity) is reported uncorrectable and the word is left
// untouched — never mis-corrected into a confidently-wrong codeword.
func TestBCHCorrectUncorrectable(t *testing.T) {
	want := buildCodeword(0x12345)
	corrupt := want ^ (1 << 5) ^ (1 << 12) ^ (1 << 20)
	got, nfix, ok := bchCorrect(corrupt)
	if ok || nfix != 0 || got != corrupt {
		t.Errorf("3-bit error: bchCorrect = (0x%08X, %d, %v); want (0x%08X, 0, false)",
			got, nfix, ok, corrupt)
	}
}

// TestDecodeRecoversCorruptedPage is the end-to-end proof: synth a
// page, flip one bit in the address codeword and two bits in the
// message codeword, and confirm the full decode still recovers the
// right address and message — with the corrected-codeword count
// reflecting the repairs.
func TestDecodeRecoversCorruptedPage(t *testing.T) {
	stream, err := Synth(SynthInput{Address: 0x12340, Function: 0, Message: "12345"})
	if err != nil {
		t.Fatalf("Synth: %v", err)
	}
	bitsClean := cleanBits(stream)

	// Locate the batch: preamble (576) + sync (32); the address sits at
	// frame 0 (RIC low 3 bits = 0), i.e. the first batch codeword.
	const off = preambleBits + CodewordBits
	addrStart := off               // address codeword
	msgStart := off + CodewordBits // message codeword
	b := []byte(bitsClean)

	flip := func(i int) {
		if b[i] == '0' {
			b[i] = '1'
		} else {
			b[i] = '0'
		}
	}
	// One error in the address codeword, two in the message codeword —
	// all within BCH's t=2 per-codeword capacity.
	flip(addrStart + 4)
	flip(msgStart + 7)
	flip(msgStart + 19)

	got, err := Decode(string(b))
	if err != nil {
		t.Fatalf("Decode(corrupted): %v", err)
	}
	if got.PageCount != 1 {
		t.Fatalf("PageCount = %d; want 1", got.PageCount)
	}
	p := got.Pages[0]
	if p.Address != 0x12340 {
		t.Errorf("Address = 0x%X; want 0x12340 (BCH should have recovered it)", p.Address)
	}
	if p.Message != "12345" {
		t.Errorf("Message = %q; want '12345' (BCH should have recovered it)", p.Message)
	}
	if got.Corrected != 2 {
		t.Errorf("Corrected = %d; want 2 (address + message codewords)", got.Corrected)
	}
	if got.Uncorrectable != 0 {
		t.Errorf("Uncorrectable = %d; want 0", got.Uncorrectable)
	}
	// Sanity: without correction the corrupted address bits would have
	// produced a different RIC. Confirm the raw (uncorrected) address
	// codeword really was corrupted, so the test isn't a no-op.
	rawAddr := parseBitsToUint32(string(b[addrStart : addrStart+CodewordBits]))
	if bchSyndrome(rawAddr) == 0 {
		t.Fatal("test setup error: address codeword was not actually corrupted")
	}
}

// TestDecodeFlagsUncorrectableCodeword confirms a codeword with three
// bit errors is counted Uncorrectable rather than silently corrected.
func TestDecodeFlagsUncorrectableCodeword(t *testing.T) {
	stream, err := Synth(SynthInput{Address: 0x12340, Function: 0, Message: "12345"})
	if err != nil {
		t.Fatalf("Synth: %v", err)
	}
	b := []byte(cleanBits(stream))
	msgStart := preambleBits + CodewordBits + CodewordBits
	for _, d := range []int{3, 9, 15} { // 3 errors > t=2
		if b[msgStart+d] == '0' {
			b[msgStart+d] = '1'
		} else {
			b[msgStart+d] = '0'
		}
	}
	got, err := Decode(string(b))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Uncorrectable != 1 {
		t.Errorf("Uncorrectable = %d; want 1", got.Uncorrectable)
	}
	// The page is still emitted (best-effort), but the message is suspect.
	if got.PageCount != 1 {
		t.Errorf("PageCount = %d; want 1 (page emitted best-effort)", got.PageCount)
	}
}
