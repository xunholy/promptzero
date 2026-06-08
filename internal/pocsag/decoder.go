// Package pocsag decodes POCSAG (Post Office Code Standardisation
// Advisory Group) paging-protocol bit-streams — ITU-R M.584-2 — into
// structured pages with address, function (numeric / alphanumeric),
// and decoded message text. Pure offline parser; no transport, no
// hardware.
//
// Wrap-vs-native judgement: POCSAG is a public specification with
// well-defined codeword shape (32-bit codewords; BCH(31,21,2) error
// correction; numeric / alphanumeric content tables published in
// the ITU-R recommendation). The walker is a few hundred lines of
// bit-twiddling. Wrapping a FAP for this would add an SD-card
// install step + a firmware-fork dependency for what is, ultimately,
// a recursive descent over a bit-stream. We implement natively so
// operators can paste a multimon-ng / rtl_433 bit-stream (or a
// Flipper-side codeword dump) and decode pages offline.
//
// What this package covers:
//   - Sync-word detection (0x7CD215D8) at any bit offset
//   - Batch / frame / codeword walking with idle-word skip
//   - Address codeword decoding (21-bit RIC + 2-bit function)
//   - Numeric message decoding (4-bit BCD with the extended table)
//   - Alphanumeric message decoding (7-bit ASCII, LSB-first packing
//     across codeword boundaries)
//   - Codeword input form for callers who already have 32-bit
//     codewords from a Flipper-side analyzer
//   - BCH(31,21,2) error correction — maximum-likelihood
//     (minimum-Hamming-weight) correction of up to two bit errors
//     per codeword, so a noisy over-the-air capture decodes to the
//     right address / message instead of a silently-wrong one. The
//     correction is unique for ≤2 errors (the code's minimum
//     distance is 5); ≥3-error words are flagged uncorrectable and
//     left untouched rather than mis-corrected.
//
// What this package does NOT cover (deliberately out of scope):
//   - FSK demodulation (operators bring a pre-demodulated bit
//     stream via multimon-ng -a POCSAG1200, rtl_433, or a Flipper
//     FSK sub-GHz capture pre-extracted to bits)
//   - Page transmission (Synth builds a valid bit-stream — preamble
//   - sync + batch — but an RF TX stage is a separate concern)
package pocsag

import (
	"encoding/hex"
	"fmt"
	"math/bits"
	"strings"
)

// Sync- and idle-word values, per ITU-R M.584-2.
const (
	// SyncWord precedes every batch (1 sync + 8 frames of 2 codewords).
	SyncWord uint32 = 0x7CD215D8
	// IdleWord fills frames that the transmitter hasn't allocated.
	IdleWord uint32 = 0x7A89C197
	// CodewordBits is the wire size of one codeword.
	CodewordBits = 32
	// FrameCodewords is the codeword count per frame.
	FrameCodewords = 2
	// BatchFrames is the frame count per batch.
	BatchFrames = 8
	// BatchCodewords is the codeword count per batch (excluding sync).
	BatchCodewords = FrameCodewords * BatchFrames
)

// FunctionTag is the 2-bit function field of an address codeword.
// Decimal 0 = numeric message; 1/2 = alphanumeric (kept distinct
// because some networks use the bit to mark priority); 3 = tone /
// no-message.
type FunctionTag int

// Page is one decoded paging message — an address, a function tag,
// and the decoded body. Encoding records whether the body was
// rendered from the numeric or alphanumeric table; Codewords
// preserves the raw 32-bit codewords for callers who want to
// re-render or cross-reference.
type Page struct {
	// Address is the 21-bit RIC (Radio Identity Code) — 18 bits
	// from the address codeword's data field + 3 bits from the
	// frame index where the codeword sat.
	Address uint32 `json:"address"`
	// AddressHex is the operator-facing zero-padded hex form, no
	// 0x prefix.
	AddressHex string `json:"address_hex"`
	// Function is the 2-bit function code (0-3). 0 is the
	// canonical "numeric" mode; 1-2 are alphanumeric on most
	// networks; 3 is tone-only / no-message.
	Function int `json:"function"`
	// Encoding is "numeric", "alphanumeric", or "tone" (function
	// 3, no message body). Reflects how Message was decoded.
	Encoding string `json:"encoding"`
	// Message is the decoded text. Empty for tone-only pages.
	Message string `json:"message"`
	// Codewords is the raw 32-bit codeword list — the address
	// codeword first, then any message codewords. Hex with no
	// separators, uppercase.
	Codewords []string `json:"codewords"`
}

// Result is the top-level decode outcome.
type Result struct {
	// Pages is every fully-collected page in order.
	Pages []Page `json:"pages"`
	// PageCount is len(Pages), surfaced for callers that consume
	// JSON directly.
	PageCount int `json:"page_count"`
	// Batches counts how many sync-aligned batches the walker
	// recognised in the input.
	Batches int `json:"batches"`
	// CodewordCount counts non-idle codewords processed.
	CodewordCount int `json:"codeword_count"`
	// IdleCount counts idle codewords (filled, transmitter-side
	// padding).
	IdleCount int `json:"idle_count"`
	// ParityErrors counts codewords whose even-parity bit didn't
	// match the rest of the codeword — a cheap data-integrity
	// indicator, measured on the raw (pre-correction) codeword.
	ParityErrors int `json:"parity_errors"`
	// Corrected counts codewords the BCH(31,21,2) decoder repaired
	// (1- or 2-bit errors). These pages decoded from the recovered
	// codeword, not the raw one.
	Corrected int `json:"corrected"`
	// Uncorrectable counts codewords with a non-zero BCH syndrome
	// that no ≤2-bit correction resolved (≥3 bit errors). Such
	// codewords are left untouched and decoded best-effort from
	// their raw bits — treat the resulting page as suspect.
	Uncorrectable int `json:"uncorrectable"`
	// SyncOffsets records the bit offsets at which SyncWord
	// matches were found. Useful for operators verifying their
	// bit-stream alignment.
	SyncOffsets []int `json:"sync_offsets,omitempty"`
	// Warnings collects non-fatal observations (truncated final
	// batch, codeword shorter than 32 bits, etc.). Empty when
	// the bit-stream walked cleanly.
	Warnings []string `json:"warnings,omitempty"`
}

// Decode reads a bit-string ('0'/'1' characters, whitespace
// tolerated) and walks every batch it finds. The walker looks for
// SyncWord at every bit offset — POCSAG transmissions in the wild
// often include preamble bits before sync, so we don't require the
// stream to start at sync. After each sync the next 16 codewords
// are processed as one batch; the walker continues scanning past
// the batch for the next sync.
func Decode(bitStream string) (Result, error) {
	bits := cleanBits(bitStream)
	if bits == "" {
		return Result{}, fmt.Errorf("pocsag: empty bit-stream")
	}
	if len(bits) < CodewordBits {
		return Result{}, fmt.Errorf("pocsag: bit-stream %d bits < one codeword (%d)", len(bits), CodewordBits)
	}
	return walkBitStream(bits)
}

// DecodeCodewords accepts a list of 32-bit codewords (no sync
// detection — the caller has already aligned). Useful when the
// operator extracted codewords from a Flipper-side analyzer or a
// recorded scan. Each codeword can be given as a hex string with
// or without the 0x prefix; the function tolerates ':' '-'
// whitespace separators between codewords.
func DecodeCodewords(words []uint32) (Result, error) {
	if len(words) == 0 {
		return Result{}, fmt.Errorf("pocsag: empty codeword list")
	}
	return processCodewords(words, 0)
}

// DecodeCodewordsHex is a hex-string variant of DecodeCodewords.
// Splits on comma / whitespace / ':' / '-' separators so operators
// can paste copy-paste-style dumps.
func DecodeCodewordsHex(s string) (Result, error) {
	parts := splitHexCodewords(s)
	if len(parts) == 0 {
		return Result{}, fmt.Errorf("pocsag: empty codeword input")
	}
	words := make([]uint32, 0, len(parts))
	for i, p := range parts {
		w, err := parseHexCodeword(p)
		if err != nil {
			return Result{}, fmt.Errorf("pocsag: codeword %d (%q): %w", i+1, p, err)
		}
		words = append(words, w)
	}
	return DecodeCodewords(words)
}

// walkBitStream is the bit-stream variant — it scans for SyncWord
// at each offset, then processes the 16 codewords that follow as
// one batch, then continues scanning.
func walkBitStream(bits string) (Result, error) {
	syncBits := uint32String(SyncWord)
	res := Result{}
	off := 0
	for off+CodewordBits <= len(bits) {
		idx := strings.Index(bits[off:], syncBits)
		if idx < 0 {
			break
		}
		syncOff := off + idx
		res.SyncOffsets = append(res.SyncOffsets, syncOff)
		batchStart := syncOff + CodewordBits
		if batchStart+BatchCodewords*CodewordBits > len(bits) {
			// Final sync without a complete trailing batch — record
			// the warning, walk what we have.
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("incomplete batch at sync offset %d: %d bits left, want %d",
					syncOff, len(bits)-batchStart, BatchCodewords*CodewordBits))
		}
		words := make([]uint32, 0, BatchCodewords)
		for i := 0; i < BatchCodewords; i++ {
			start := batchStart + i*CodewordBits
			end := start + CodewordBits
			if end > len(bits) {
				break
			}
			words = append(words, parseBitsToUint32(bits[start:end]))
		}
		batchRes, err := processCodewords(words, 0)
		if err != nil {
			return res, err
		}
		res.Pages = append(res.Pages, batchRes.Pages...)
		res.CodewordCount += batchRes.CodewordCount
		res.IdleCount += batchRes.IdleCount
		res.ParityErrors += batchRes.ParityErrors
		res.Corrected += batchRes.Corrected
		res.Uncorrectable += batchRes.Uncorrectable
		res.Batches++
		off = batchStart + BatchCodewords*CodewordBits
	}
	res.PageCount = len(res.Pages)
	if res.Batches == 0 {
		return res, fmt.Errorf("pocsag: no sync codeword (0x%08X) found in %d-bit stream", SyncWord, len(bits))
	}
	return res, nil
}

// processCodewords walks an already-aligned codeword list — used
// directly by DecodeCodewords and by walkBitStream once it has a
// batch. The startFrame argument is the frame index for the first
// codeword (0 by default; non-zero when the caller knows the
// codewords are mid-batch).
func processCodewords(words []uint32, startFrame int) (Result, error) {
	res := Result{}
	var current *Page
	var msgBits string
	for i, w := range words {
		frame := (startFrame + i) / FrameCodewords
		if frame >= BatchFrames {
			frame = frame % BatchFrames
		}
		// BCH(31,21,2) correction up front, before classification, so a
		// corrupted idle (or address / message) word is recovered rather
		// than mis-read. Clean codewords have a zero syndrome and pass
		// through unchanged; ≥3-error words are flagged and left raw.
		raw := w
		if cw, nfix, ok := bchCorrect(raw); !ok {
			res.Uncorrectable++
		} else if nfix > 0 {
			res.Corrected++
			w = cw
		}
		if w == IdleWord {
			res.IdleCount++
			if current != nil {
				flushPage(&res, current, msgBits)
				current = nil
				msgBits = ""
			}
			continue
		}
		res.CodewordCount++
		if !parityOK(raw) {
			res.ParityErrors++
		}
		if (w & 0x80000000) == 0 {
			// Address codeword.
			if current != nil {
				flushPage(&res, current, msgBits)
			}
			data := (w >> 11) & 0xFFFFF
			addrMSB := uint32(data >> 2)
			fn := int(data & 0x3)
			ric := (addrMSB << 3) | uint32(frame&0x7)
			current = &Page{
				Address:    ric,
				AddressHex: fmt.Sprintf("%07X", ric),
				Function:   fn,
				Encoding:   encodingForFunction(fn),
				Codewords:  []string{fmt.Sprintf("%08X", w)},
			}
			msgBits = ""
		} else {
			// Message codeword.
			if current == nil {
				// Message codeword without a leading address — common
				// when the operator passes a partial bit-stream.
				// Record but don't fail.
				res.Warnings = append(res.Warnings,
					fmt.Sprintf("message codeword at index %d with no preceding address — dropped", i))
				continue
			}
			data := (w >> 11) & 0xFFFFF
			msgBits += fmt.Sprintf("%020b", data)
			current.Codewords = append(current.Codewords, fmt.Sprintf("%08X", w))
		}
	}
	if current != nil {
		flushPage(&res, current, msgBits)
	}
	res.PageCount = len(res.Pages)
	return res, nil
}

// flushPage decodes msgBits per the page's encoding and appends.
func flushPage(res *Result, p *Page, msgBits string) {
	switch p.Encoding {
	case "numeric":
		p.Message = decodeNumeric(msgBits)
	case "alphanumeric":
		p.Message = decodeAlphanumeric(msgBits)
	case "tone":
		// Tone-only: function 3, no body.
		p.Message = ""
	}
	res.Pages = append(res.Pages, *p)
}

// encodingForFunction maps the 2-bit function code to a human
// encoding label. Function 0 is the canonical numeric mode;
// functions 1 and 2 are alphanumeric on most networks; function 3
// is tone-only (no body).
func encodingForFunction(f int) string {
	switch f {
	case 0:
		return "numeric"
	case 3:
		return "tone"
	default:
		return "alphanumeric"
	}
}

// pocsagNumericTable maps the 4-bit nibbles operators see in
// POCSAG numeric pages to their display characters. Source:
// ITU-R M.584-2 §3.3 (numeric message format).
var pocsagNumericTable = [16]byte{
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', ' ', 'U', '-', ')', '(', ' ',
}

// decodeNumeric renders a numeric-message bit-stream — 4-bit
// digits, LSB-first within each digit (per the spec's "bit-reverse
// within each character" rule).
func decodeNumeric(bitStr string) string {
	var sb strings.Builder
	for off := 0; off+4 <= len(bitStr); off += 4 {
		nibble := parseBitsToUint8(bitStr[off : off+4])
		// LSB-first → reverse the 4 bits for lookup.
		nibble = bits.Reverse8(nibble) >> 4
		sb.WriteByte(pocsagNumericTable[nibble&0x0F])
	}
	return sb.String()
}

// decodeAlphanumeric renders an alphanumeric-message bit-stream —
// 7-bit ASCII characters, LSB-first within each character, packed
// across codeword boundaries. Strips trailing NUL / DEL padding
// that transmitters use to fill the final codeword.
func decodeAlphanumeric(bitStr string) string {
	var sb strings.Builder
	for off := 0; off+7 <= len(bitStr); off += 7 {
		b := parseBitsToUint8(bitStr[off : off+7])
		// LSB-first → reverse 7 bits.
		b = bits.Reverse8(b) >> 1
		if b == 0 || b == 0x7F {
			continue
		}
		sb.WriteByte(b)
	}
	return sb.String()
}

// bchSyndrome computes the BCH(31,21) syndrome of a codeword — the
// remainder of its 31-bit code part (bits 31..1; bit 0 is the
// separate even-parity bit, outside the BCH code) modulo the
// generator g(x) = bchGenerator. A valid codeword yields 0.
func bchSyndrome(w uint32) uint32 {
	reg := w >> 1 // 31-bit BCH code part: x^30 (bit 31) … x^0 (bit 1)
	for i := 30; i >= 10; i-- {
		if reg&(1<<uint(i)) != 0 {
			reg ^= bchGenerator << uint(i-10)
		}
	}
	return reg & 0x3FF
}

// bchCorrect performs maximum-likelihood BCH(31,21,2) decoding: it
// returns the minimum-Hamming-weight codeword within two bit-flips
// of w (searching the 31 BCH-protected bit positions 1..31). The
// code's minimum distance is 5, so for any error of weight ≤2 the
// coset leader is unique — the first match found is provably the
// maximum-likelihood codeword, never an ambiguous guess.
//
// Returns (corrected, errorsFixed, true) when w is a valid codeword
// (errorsFixed 0) or correctable (1 or 2). Returns (w, 0, false)
// when the syndrome is non-zero and no ≤2-bit flip clears it (≥3
// errors) — the caller leaves the word raw rather than mis-correct.
func bchCorrect(w uint32) (uint32, int, bool) {
	if bchSyndrome(w) == 0 {
		return w, 0, true
	}
	// Single-bit errors (positions 1..31; bit 0 is parity, not BCH).
	for i := 1; i <= 31; i++ {
		if bchSyndrome(w^(1<<uint(i))) == 0 {
			return w ^ (1 << uint(i)), 1, true
		}
	}
	// Two-bit errors.
	for i := 1; i <= 31; i++ {
		for j := i + 1; j <= 31; j++ {
			if bchSyndrome(w^(1<<uint(i))^(1<<uint(j))) == 0 {
				return w ^ (1 << uint(i)) ^ (1 << uint(j)), 2, true
			}
		}
	}
	return w, 0, false // uncorrectable (≥3 bit errors)
}

// parityOK confirms the codeword's bit-0 even-parity bit matches
// the parity of bits 31..1. Doesn't catch many errors but the
// per-codeword cost is one popcount.
func parityOK(w uint32) bool {
	p := bits.OnesCount32(w&0xFFFFFFFE) % 2
	return uint32(p) == (w & 1)
}

// uint32String renders a uint32 as a 32-character '0'/'1' string
// for sub-string searching in the bit-stream.
func uint32String(w uint32) string {
	return fmt.Sprintf("%032b", w)
}

// parseBitsToUint32 parses a string of '0'/'1' (exactly 32 chars)
// into a uint32. Callers guarantee length.
func parseBitsToUint32(s string) uint32 {
	var v uint32
	for i := 0; i < len(s); i++ {
		v <<= 1
		if s[i] == '1' {
			v |= 1
		}
	}
	return v
}

// parseBitsToUint8 parses a string of '0'/'1' (≤8 chars) into a
// uint8. Callers guarantee length.
func parseBitsToUint8(s string) uint8 {
	var v uint8
	for i := 0; i < len(s); i++ {
		v <<= 1
		if s[i] == '1' {
			v |= 1
		}
	}
	return v
}

// cleanBits strips whitespace, ':' '-' '_' separators from the bit
// intake. Mirrors emv / ble separator handling.
func cleanBits(s string) string {
	repl := strings.NewReplacer(
		" ", "",
		"\t", "",
		"\n", "",
		"\r", "",
		":", "",
		"-", "",
		"_", "",
	)
	return repl.Replace(strings.TrimSpace(s))
}

// splitHexCodewords splits a hex-codeword input string on common
// separators (comma, whitespace, ':' '-').
func splitHexCodewords(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	repl := strings.NewReplacer("\t", " ", "\n", " ", "\r", " ", ",", " ", ":", " ", "-", " ")
	s = repl.Replace(s)
	parts := strings.Fields(s)
	return parts
}

// parseHexCodeword parses a hex codeword (with or without 0x
// prefix) into a uint32. Requires exactly 4 bytes (8 hex chars)
// after prefix stripping.
func parseHexCodeword(s string) (uint32, error) {
	s = strings.TrimPrefix(strings.ToLower(s), "0x")
	if len(s) != 8 {
		return 0, fmt.Errorf("codeword must be 8 hex chars (32 bits), got %d", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return 0, err
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), nil
}
