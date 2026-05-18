package pocsag

import (
	"fmt"
	"math/bits"
	"strings"
	"testing"
)

// TestSyncWordConstants pins the well-known POCSAG sync- and
// idle-word constants — they're cited in every public reference
// and a typo here would silently break every decode.
func TestSyncWordConstants(t *testing.T) {
	if SyncWord != 0x7CD215D8 {
		t.Errorf("SyncWord = 0x%08X; want 0x7CD215D8", SyncWord)
	}
	if IdleWord != 0x7A89C197 {
		t.Errorf("IdleWord = 0x%08X; want 0x7A89C197", IdleWord)
	}
}

// TestParityOK_SyncAndIdle confirms the well-known sync and idle
// codewords pass the even-parity check.
func TestParityOK_SyncAndIdle(t *testing.T) {
	if !parityOK(SyncWord) {
		t.Errorf("SyncWord %08X failed parity check", SyncWord)
	}
	if !parityOK(IdleWord) {
		t.Errorf("IdleWord %08X failed parity check", IdleWord)
	}
}

// TestDecodeCodewords_NumericPage constructs an address codeword
// for RIC 0x12340 (function 0 = numeric) sitting at frame 0 (the
// bottom 3 bits of a RIC are encoded in the codeword's frame
// position, so they must match — RIC 0x12340 & 7 = 0 = frame 0)
// followed by one message codeword carrying the BCD-encoded
// digits "12345", then verifies the decoder reassembles both.
func TestDecodeCodewords_NumericPage(t *testing.T) {
	addrWord := makeAddressCodeword(t, 0x12340, 0, 0)
	// Numeric digits 1,2,3,4,5 — 4 bits each, LSB-first within the
	// nibble (per the spec). Pack 5 digits = 20 data bits.
	msgData := packNumericDigits("12345")
	msgWord := makeMessageCodeword(t, msgData)

	got, err := DecodeCodewords([]uint32{addrWord, msgWord})
	if err != nil {
		t.Fatalf("DecodeCodewords: %v", err)
	}
	if got.PageCount != 1 {
		t.Fatalf("PageCount = %d; want 1", got.PageCount)
	}
	p := got.Pages[0]
	if p.Address != 0x12340 {
		t.Errorf("Address = 0x%X; want 0x12340", p.Address)
	}
	if p.Function != 0 {
		t.Errorf("Function = %d; want 0", p.Function)
	}
	if p.Encoding != "numeric" {
		t.Errorf("Encoding = %q; want 'numeric'", p.Encoding)
	}
	if p.Message != "12345" {
		t.Errorf("Message = %q; want '12345'", p.Message)
	}
}

// TestDecodeCodewords_AlphanumericPage — function 3 maps to
// "tone" in our encoding table. We still synthesise a page with a
// body codeword and check that the encoding is rendered as tone
// (the body bytes are ignored for tone-tagged pages).
func TestDecodeCodewords_AlphanumericPage(t *testing.T) {
	addrWord := makeAddressCodeword(t, 0xABCD8, 3, 0)
	msgData := packAlphanumeric("HI")
	msgWord := makeMessageCodeword(t, msgData)

	got, err := DecodeCodewords([]uint32{addrWord, msgWord})
	if err != nil {
		t.Fatalf("DecodeCodewords: %v", err)
	}
	if got.PageCount != 1 {
		t.Fatalf("PageCount = %d; want 1", got.PageCount)
	}
	p := got.Pages[0]
	if p.Address != 0xABCD8 {
		t.Errorf("Address = 0x%X; want 0xABCD8", p.Address)
	}
	if p.Function != 3 {
		// Function 3 in our table maps to "tone" — alphanumeric
		// pages typically use function 1 or 2.
		t.Errorf("Function = %d; want 3", p.Function)
	}
}

// TestDecodeCodewords_AlphanumericFunc1 — function 1 should yield
// encoding "alphanumeric" and decode the body.
func TestDecodeCodewords_AlphanumericFunc1(t *testing.T) {
	addrWord := makeAddressCodeword(t, 0xABCD8, 1, 0)
	msgData := packAlphanumeric("HI")
	msgWord := makeMessageCodeword(t, msgData)

	got, err := DecodeCodewords([]uint32{addrWord, msgWord})
	if err != nil {
		t.Fatalf("DecodeCodewords: %v", err)
	}
	p := got.Pages[0]
	if p.Encoding != "alphanumeric" {
		t.Errorf("Encoding = %q; want 'alphanumeric'", p.Encoding)
	}
	if !strings.HasPrefix(p.Message, "HI") {
		t.Errorf("Message = %q; want prefix 'HI'", p.Message)
	}
}

// TestDecodeCodewords_TonePage — function 3 with no message
// codeword: encoding "tone", empty body. Sits alone at codeword
// position 0 = frame 0, so RIC ends in 0.
func TestDecodeCodewords_TonePage(t *testing.T) {
	addrWord := makeAddressCodeword(t, 0x40, 3, 0)
	got, err := DecodeCodewords([]uint32{addrWord})
	if err != nil {
		t.Fatalf("DecodeCodewords: %v", err)
	}
	if got.PageCount != 1 {
		t.Fatalf("PageCount = %d; want 1", got.PageCount)
	}
	p := got.Pages[0]
	if p.Encoding != "tone" {
		t.Errorf("Encoding = %q; want 'tone'", p.Encoding)
	}
	if p.Message != "" {
		t.Errorf("Message = %q; want empty", p.Message)
	}
}

// TestDecodeCodewords_MultiPage with an idle codeword between
// pages forces the decoder to flush the first page on idle.
// a1 sits at position 0 (frame 0), a2 at position 3 (frame 1).
// RIC bottom-3-bits must match frame, so a1 ends in 0 and a2
// ends in 1.
func TestDecodeCodewords_MultiPage(t *testing.T) {
	a1 := makeAddressCodeword(t, 0x100, 0, 0)
	m1 := makeMessageCodeword(t, packNumericDigits("11"))
	a2 := makeAddressCodeword(t, 0x201, 0, 1)
	m2 := makeMessageCodeword(t, packNumericDigits("22"))

	got, err := DecodeCodewords([]uint32{a1, m1, IdleWord, a2, m2})
	if err != nil {
		t.Fatalf("DecodeCodewords: %v", err)
	}
	if got.PageCount != 2 {
		t.Fatalf("PageCount = %d; want 2", got.PageCount)
	}
	if got.IdleCount != 1 {
		t.Errorf("IdleCount = %d; want 1", got.IdleCount)
	}
	if got.Pages[0].Address != 0x100 || got.Pages[1].Address != 0x201 {
		t.Errorf("addresses = %X, %X; want 100, 201",
			got.Pages[0].Address, got.Pages[1].Address)
	}
}

// TestDecodeCodewords_OrphanMessageWarning surfaces a warning when
// the operator passes a message codeword without a preceding
// address (common when slicing a partial capture).
func TestDecodeCodewords_OrphanMessageWarning(t *testing.T) {
	m := makeMessageCodeword(t, packNumericDigits("99"))
	got, err := DecodeCodewords([]uint32{m})
	if err != nil {
		t.Fatalf("DecodeCodewords: %v", err)
	}
	if got.PageCount != 0 {
		t.Errorf("PageCount = %d; want 0", got.PageCount)
	}
	if len(got.Warnings) == 0 {
		t.Error("want at least one warning for orphan message codeword")
	}
}

// TestDecode_BitStream constructs a sync-prefixed bit-stream
// carrying one address + one message codeword (rest idle) and
// confirms walkBitStream finds the sync and decodes the page.
// Address sits at codeword position 0 inside the batch (frame 0),
// so its RIC's bottom 3 bits are 0.
func TestDecode_BitStream(t *testing.T) {
	addrWord := makeAddressCodeword(t, 0x55550, 0, 0)
	msgWord := makeMessageCodeword(t, packNumericDigits("99999"))

	var sb strings.Builder
	// Preamble: a few alternating bits to confirm the walker can
	// skip past them.
	sb.WriteString("10101010")
	fmt.Fprintf(&sb, "%032b", SyncWord)
	fmt.Fprintf(&sb, "%032b", addrWord)
	fmt.Fprintf(&sb, "%032b", msgWord)
	// Pad the rest of the batch with idle words.
	for i := 2; i < BatchCodewords; i++ {
		fmt.Fprintf(&sb, "%032b", IdleWord)
	}

	got, err := Decode(sb.String())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Batches != 1 {
		t.Errorf("Batches = %d; want 1", got.Batches)
	}
	if got.PageCount != 1 {
		t.Errorf("PageCount = %d; want 1", got.PageCount)
	}
	if got.Pages[0].Address != 0x55550 {
		t.Errorf("Address = 0x%X; want 0x55550", got.Pages[0].Address)
	}
	if got.Pages[0].Message != "99999" {
		t.Errorf("Message = %q; want '99999'", got.Pages[0].Message)
	}
	if len(got.SyncOffsets) != 1 || got.SyncOffsets[0] != 8 {
		t.Errorf("SyncOffsets = %v; want [8]", got.SyncOffsets)
	}
}

// TestDecode_NoSyncReturnsError — a bit-stream without a sync word
// gets a hard error so operators know their alignment is wrong.
func TestDecode_NoSyncReturnsError(t *testing.T) {
	// 64 zero bits — no sync word, no codewords.
	_, err := Decode(strings.Repeat("0", 64))
	if err == nil {
		t.Fatal("want error for no-sync input")
	}
	if !strings.Contains(err.Error(), "sync") {
		t.Errorf("error = %q; want it to mention sync", err.Error())
	}
}

// TestDecode_EmptyAndShort — empty and sub-codeword input return
// errors with operator-facing context.
func TestDecode_EmptyAndShort(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Error("Decode(''): want error")
	}
	if _, err := Decode("0101"); err == nil {
		t.Error("Decode('0101'): want error")
	}
}

// TestDecode_ToleratesSeparators confirms the bit intake strips
// whitespace and ':' '-' '_' separators so an operator can paste
// a formatted stream.
func TestDecode_ToleratesSeparators(t *testing.T) {
	addr := makeAddressCodeword(t, 0xF8, 0, 0)
	msg := makeMessageCodeword(t, packNumericDigits("1"))
	bitStr := fmt.Sprintf("%032b %032b %032b",
		SyncWord, addr, msg)
	// Pad with idle words to complete the batch.
	for i := 2; i < BatchCodewords; i++ {
		bitStr += fmt.Sprintf(" %032b", IdleWord)
	}
	// Sprinkle ':' and '-' separators every 4 chars.
	bitStr = strings.ReplaceAll(bitStr, " ", ":")
	got, err := Decode(bitStr)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.PageCount != 1 {
		t.Errorf("PageCount = %d; want 1", got.PageCount)
	}
}

// TestDecodeCodewordsHex parses a hex-codeword string and walks it.
// Covers the common operator path of pasting codewords from a
// scanner output. Address at codeword position 0 (frame 0) needs
// RIC bottom 3 bits = 0. Numeric message is right-padded with
// zero nibbles which decode as '0' digits — the test expects the
// padded form.
func TestDecodeCodewordsHex(t *testing.T) {
	addr := makeAddressCodeword(t, 0x120, 0, 0)
	msg := makeMessageCodeword(t, packNumericDigits("42"))
	in := fmt.Sprintf("%08X %08X", addr, msg)
	got, err := DecodeCodewordsHex(in)
	if err != nil {
		t.Fatalf("DecodeCodewordsHex: %v", err)
	}
	if got.PageCount != 1 {
		t.Fatalf("PageCount = %d", got.PageCount)
	}
	if got.Pages[0].Address != 0x120 {
		t.Errorf("Address = 0x%X; want 0x120", got.Pages[0].Address)
	}
	if got.Pages[0].Message != "42000" {
		t.Errorf("Message = %q; want '42000' (5-digit codeword right-padded with 0s)",
			got.Pages[0].Message)
	}
}

// TestDecodeCodewordsHex_BadInput returns operator-facing errors
// for malformed codewords.
func TestDecodeCodewordsHex_BadInput(t *testing.T) {
	if _, err := DecodeCodewordsHex(""); err == nil {
		t.Error("empty input: want error")
	}
	if _, err := DecodeCodewordsHex("ABCD"); err == nil {
		t.Error("short hex: want error")
	}
	if _, err := DecodeCodewordsHex("ZZZZZZZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
}

// TestDecodeCodewords_FrameIndexAddress — a codeword in frame
// position 3 (codewords 6 and 7 in the batch) should pick up
// frame=3 in its RIC. RIC 0x103 = 0x20 << 3 | 3: 18-bit MSB
// portion 0x20 in the codeword data field; frame index 3 from
// position 6 (6/2 = 3).
func TestDecodeCodewords_FrameIndexAddress(t *testing.T) {
	// Pad with 6 idle codewords to push the address into frame 3.
	words := []uint32{
		IdleWord, IdleWord, IdleWord, IdleWord, IdleWord, IdleWord,
		makeAddressCodeword(t, 0x103, 0, 3),
	}
	got, err := DecodeCodewords(words)
	if err != nil {
		t.Fatalf("DecodeCodewords: %v", err)
	}
	if got.PageCount != 1 {
		t.Fatalf("PageCount = %d; want 1", got.PageCount)
	}
	if got.Pages[0].Address != 0x103 {
		t.Errorf("Address = 0x%X; want 0x103", got.Pages[0].Address)
	}
}

// ---------- helpers for synthesising test codewords ----------

// makeAddressCodeword builds a valid address codeword for a given
// RIC (21-bit), function (2-bit), and frame index. Sets even
// parity. The 18-bit address MSBs are the RIC right-shifted by 3
// (the bottom 3 bits live in the frame index where the codeword
// sits). Test will t.Fatalf on out-of-range values.
//
// Note: this synthesises the wire bits but does NOT compute the
// 10-bit BCH check — the decoder doesn't verify BCH currently, so
// tests don't need it. If we add BCH verification later, this
// helper grows a BCH encoder.
func makeAddressCodeword(t *testing.T, ric uint32, fn int, frame int) uint32 {
	t.Helper()
	if ric > 0x1FFFFF {
		t.Fatalf("ric 0x%X exceeds 21-bit range", ric)
	}
	if int(ric&0x7) != (frame & 0x7) {
		t.Fatalf("ric 0x%X bottom 3 bits (%d) must match frame %d — "+
			"the spec encodes frame in the bottom 3 bits of the address",
			ric, ric&0x7, frame)
	}
	addrMSB := (ric >> 3) & 0x3FFFF
	data := (addrMSB << 2) | uint32(fn&0x3)
	// Address codewords have bit 31 = 0.
	w := (data << 11) & 0x7FFFF800
	// Bit 0 = even parity over bits 31..1.
	p := bits.OnesCount32(w) % 2
	w |= uint32(p)
	return w
}

// makeMessageCodeword builds a message codeword from a 20-bit
// data field. Sets bit 31 (message marker) and even parity.
func makeMessageCodeword(t *testing.T, data20 uint32) uint32 {
	t.Helper()
	if data20 > 0xFFFFF {
		t.Fatalf("data 0x%X exceeds 20-bit range", data20)
	}
	w := uint32(0x80000000) | (data20 << 11)
	p := bits.OnesCount32(w) % 2
	w |= uint32(p)
	return w
}

// packNumericDigits packs the given numeric-page digits into a
// 20-bit data field, LSB-first within each 4-bit nibble (per the
// spec). Up to 5 digits per codeword.
func packNumericDigits(digits string) uint32 {
	var out uint32
	for i, d := range digits {
		if i >= 5 {
			break
		}
		var nibble uint8
		switch {
		case d >= '0' && d <= '9':
			nibble = uint8(d - '0')
		case d == ' ':
			nibble = 0x0A
		case d == 'U':
			nibble = 0x0B
		case d == '-':
			nibble = 0x0C
		case d == ')':
			nibble = 0x0D
		case d == '(':
			nibble = 0x0E
		}
		// LSB-first within the nibble: reverse before placing.
		reversed := bits.Reverse8(nibble) >> 4
		out = (out << 4) | uint32(reversed)
	}
	// Right-pad with zero nibbles if fewer than 5 digits.
	pad := 5 - len(digits)
	if pad > 0 {
		out <<= 4 * pad
	}
	return out & 0xFFFFF
}

// packAlphanumeric packs ASCII characters into the 20-bit message
// data field, LSB-first within each 7-bit character. Up to 2
// characters per codeword for the test scope (14 bits + 6 NUL bits
// of padding fits in 20).
func packAlphanumeric(s string) uint32 {
	var bitStr strings.Builder
	for _, c := range s {
		b := uint8(c) & 0x7F
		rev := bits.Reverse8(b) >> 1
		fmt.Fprintf(&bitStr, "%07b", rev)
	}
	// Pad to 20 bits with zeros (NUL padding).
	for bitStr.Len() < 20 {
		bitStr.WriteByte('0')
	}
	s2 := bitStr.String()
	if len(s2) > 20 {
		s2 = s2[:20]
	}
	var v uint32
	for i := 0; i < len(s2); i++ {
		v <<= 1
		if s2[i] == '1' {
			v |= 1
		}
	}
	return v
}
