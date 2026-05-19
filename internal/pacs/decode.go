// Package pacs decodes Physical Access Control System (PACS)
// credential payloads — the upper-layer encoding that sits on
// top of the Wiegand bit-stream produced by an HID Prox /
// iCLASS / EM-style reader.
//
// Wrap-vs-native judgement
//
//	Native. The HID format catalogue is fully public via the
//	HID OEM-format spec sheets, the Proxmark3 Iceman codebase
//	(`hidpacs.go` table), and decades of community
//	reverse-engineering. Each format is a small fixed-width
//	bit-field layout with one or more parity bits — pure
//	bit-twiddling, no crypto, no state. Operators feed the
//	raw bit string that drops out of `wiegand_decode` (or a
//	proxmark3 lf hid demod) and get the documented
//	facility-code / card-number / OEM-code fields plus a
//	parity-validity check.
//
// What this package covers
//
//   - Input convention: a bit string ("0"/"1" only) of one of
//     the recognised widths. Hex+bit-length input is also
//     accepted for convenience (hex is left-aligned into a
//     bit buffer of exactly the declared width, MSB first).
//
//   - Recognised formats and their wire layouts:
//
//   - **HID H10301 26-bit** — the canonical HID Prox format.
//     P + 8 FC + 16 CN + P. Bit 0 is even parity over bits
//     1-12; bit 25 is odd parity over bits 13-24.
//
//   - **HID H10306 34-bit** — extended FC range. P + 16 FC
//
//   - 16 CN + P. Bit 0 is even parity over bits 1-16; bit
//     33 is odd parity over bits 17-32.
//
//   - **HID H10304 37-bit** — wide CN. P + 16 FC + 19 CN +
//     P. Bit 0 is even parity over bits 1-18; bit 36 is odd
//     parity over bits 18-35.
//
//   - **HID H10302 37-bit** — no FC, 35-bit CN. P + 35 CN +
//     P. Bit 0 is even parity over bits 1-18; bit 36 is odd
//     parity over bits 18-35.
//
//   - **HID Corporate 1000 35-bit** — proprietary. 2 leading
//     parity bits (even/odd over a complex bit pattern per
//     HID OEM spec) + 12 FC + 20 CN + trailing parity.
//
//   - **HID Corporate 1000 48-bit** — extended variant. 2
//     parity bits + 22 FC + 23 CN + trailing parity.
//
//   - When the input length matches a single recognised
//     format, the decoder returns that format. When the
//     length matches multiple formats (e.g. 37-bit could be
//     H10304 OR H10302), the decoder returns all candidates
//     and lets the caller pick by parity-validity or by
//     facility-code sanity.
//
//   - Parity is computed and surfaced as parity_valid bool
//     for each candidate. A failed parity bit doesn't
//     suppress the candidate (the bit-pattern is still useful
//     for debugging) but is clearly flagged.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - The reader-layer Wiegand bit-stream extraction —
//     `wiegand_decode` already handles that.
//
//   - The crypto layer of iCLASS Standard or Elite (3DES key
//     diversification, MAC validation) — payload-level
//     decryption is a separate Spec.
//
//   - DESFire AID / EV1 application records — those are NFC
//     APDU exchanges decoded by `desfire_decode`.
//
//   - LF / EM4xxx baseband modulation (Manchester /
//     biphase) — `em4100_decode` handles EM-style baseband.
//
//   - Cardholder-database lookup — facility-code / card-number
//     to "who owns this badge" mapping is the operator's
//     job (the PACS database is external).
package pacs

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the top-level decoded view.
type Result struct {
	BitLength  int         `json:"bit_length"`
	BitsRaw    string      `json:"bits_raw"`
	HexLeft    string      `json:"hex_msb_first"`
	Candidates []Candidate `json:"candidates"`
	Notes      []string    `json:"notes,omitempty"`
}

// Candidate is one decoded PACS format interpretation.
type Candidate struct {
	Format       string `json:"format"`
	Spec         string `json:"spec_summary"`
	FacilityCode uint64 `json:"facility_code,omitempty"`
	CardNumber   uint64 `json:"card_number"`
	OEMCode      uint64 `json:"oem_code,omitempty"`
	Issue        uint64 `json:"issue_code,omitempty"`
	ParityValid  bool   `json:"parity_valid"`
	ParityNotes  string `json:"parity_notes,omitempty"`
}

// DecodeBits parses a bit-string PACS payload.
func DecodeBits(bits string) (*Result, error) {
	bits = strings.TrimSpace(bits)
	if bits == "" {
		return nil, fmt.Errorf("empty bits")
	}
	for i, r := range bits {
		if r != '0' && r != '1' {
			return nil, fmt.Errorf("invalid bit %q at index %d (only '0' and '1' allowed)",
				r, i)
		}
	}
	return decode(bits)
}

// DecodeHex parses a hex-encoded PACS payload with a declared
// bit count. The hex bytes are left-aligned into a bit buffer
// of exactly bitLen bits (MSB first). Unused trailing bits in
// the last byte are silently discarded; callers are expected
// to provide a bitLen consistent with what `wiegand_decode` or
// the reader actually emitted.
func DecodeHex(hexStr string, bitLen int) (*Result, error) {
	clean := stripSeparators(hexStr)
	if clean == "" {
		return nil, fmt.Errorf("empty hex")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("hex must have even length, got %d", len(clean))
	}
	if bitLen <= 0 {
		return nil, fmt.Errorf("bit_length must be > 0, got %d", bitLen)
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if bitLen > len(b)*8 {
		return nil, fmt.Errorf("bit_length %d exceeds hex capacity %d", bitLen, len(b)*8)
	}
	var sb strings.Builder
	for i := 0; i < bitLen; i++ {
		bit := (b[i/8] >> (7 - uint(i%8))) & 1
		if bit == 1 {
			sb.WriteByte('1')
		} else {
			sb.WriteByte('0')
		}
	}
	return decode(sb.String())
}

func decode(bits string) (*Result, error) {
	r := &Result{
		BitLength: len(bits),
		BitsRaw:   bits,
		HexLeft:   bitsToHex(bits),
	}
	switch len(bits) {
	case 26:
		r.Candidates = append(r.Candidates, decodeH10301(bits))
	case 34:
		r.Candidates = append(r.Candidates, decodeH10306(bits))
	case 35:
		r.Candidates = append(r.Candidates, decodeCorp1000_35(bits))
	case 37:
		r.Candidates = append(r.Candidates,
			decodeH10304(bits),
			decodeH10302(bits))
	case 48:
		r.Candidates = append(r.Candidates, decodeCorp1000_48(bits))
	default:
		r.Notes = append(r.Notes, fmt.Sprintf(
			"bit length %d does not match any catalogued HID format "+
				"(known widths: 26 / 34 / 35 / 37 / 48). Raw bits and "+
				"hex returned for manual inspection.", len(bits)))
	}
	return r, nil
}

func decodeH10301(b string) Candidate {
	// 1 P + 8 FC + 16 CN + 1 P (26 bits total).
	fc := bitsToUint(b[1:9])
	cn := bitsToUint(b[9:25])
	leadingP := bitsToUint(b[:1])
	trailingP := bitsToUint(b[25:])
	// Even parity bit 0 over bits 1-12.
	evenOK := parityEven(b[1:13]) == int(leadingP)
	// Odd parity bit 25 over bits 13-24.
	oddOK := parityOdd(b[13:25]) == int(trailingP)
	return Candidate{
		Format:       "HID H10301 26-bit",
		Spec:         "Even parity (1) + 8-bit facility code + 16-bit card number + odd parity (1)",
		FacilityCode: fc,
		CardNumber:   cn,
		ParityValid:  evenOK && oddOK,
		ParityNotes:  parityNotes(evenOK, oddOK),
	}
}

func decodeH10306(b string) Candidate {
	// 1 P + 16 FC + 16 CN + 1 P (34 bits total).
	fc := bitsToUint(b[1:17])
	cn := bitsToUint(b[17:33])
	leadingP := bitsToUint(b[:1])
	trailingP := bitsToUint(b[33:])
	evenOK := parityEven(b[1:17]) == int(leadingP)
	oddOK := parityOdd(b[17:33]) == int(trailingP)
	return Candidate{
		Format:       "HID H10306 34-bit",
		Spec:         "Even parity (1) + 16-bit facility code + 16-bit card number + odd parity (1)",
		FacilityCode: fc,
		CardNumber:   cn,
		ParityValid:  evenOK && oddOK,
		ParityNotes:  parityNotes(evenOK, oddOK),
	}
}

func decodeH10304(b string) Candidate {
	// 1 P + 16 FC + 19 CN + 1 P (37 bits total).
	fc := bitsToUint(b[1:17])
	cn := bitsToUint(b[17:36])
	leadingP := bitsToUint(b[:1])
	trailingP := bitsToUint(b[36:])
	evenOK := parityEven(b[1:19]) == int(leadingP)
	oddOK := parityOdd(b[18:36]) == int(trailingP)
	return Candidate{
		Format:       "HID H10304 37-bit",
		Spec:         "Even parity (1) + 16-bit facility code + 19-bit card number + odd parity (1)",
		FacilityCode: fc,
		CardNumber:   cn,
		ParityValid:  evenOK && oddOK,
		ParityNotes:  parityNotes(evenOK, oddOK),
	}
}

func decodeH10302(b string) Candidate {
	// 1 P + 35 CN + 1 P (37 bits total). No FC.
	cn := bitsToUint(b[1:36])
	leadingP := bitsToUint(b[:1])
	trailingP := bitsToUint(b[36:])
	evenOK := parityEven(b[1:19]) == int(leadingP)
	oddOK := parityOdd(b[18:36]) == int(trailingP)
	return Candidate{
		Format:      "HID H10302 37-bit (no facility code)",
		Spec:        "Even parity (1) + 35-bit card number + odd parity (1)",
		CardNumber:  cn,
		ParityValid: evenOK && oddOK,
		ParityNotes: parityNotes(evenOK, oddOK),
	}
}

func decodeCorp1000_35(b string) Candidate {
	// HID Corporate 1000 35-bit per HID OEM spec.
	// Layout: P P + 12 FC + 20 CN + P (35 bits total).
	// Parity scheme: bit 0 (even) over bits 2,4,6,...,32;
	// bit 1 (odd) over bits 1-33; bit 34 (odd) over bits 1-33.
	// We compute and surface validity but don't suppress on
	// failure.
	fc := bitsToUint(b[2:14])
	cn := bitsToUint(b[14:34])
	p0 := bitsToUint(b[:1])
	p1 := bitsToUint(b[1:2])
	p34 := bitsToUint(b[34:])

	// Even parity over bits 2,4,6,...,32 (every other bit).
	evenCnt := 0
	for i := 2; i < 34; i += 2 {
		if b[i] == '1' {
			evenCnt++
		}
	}
	evenOK := (evenCnt%2 == 0) == (p0 == 0)

	// Odd parity p1 over bits 1-33 (33 bits inclusive).
	odd1Cnt := 0
	for i := 1; i < 34; i++ {
		if b[i] == '1' {
			odd1Cnt++
		}
	}
	odd1OK := (odd1Cnt%2 == 1) == (p1 == 1)

	// Odd parity p34 over bits 1-33 (same range).
	odd34OK := (odd1Cnt%2 == 1) == (p34 == 1)

	all := evenOK && odd1OK && odd34OK
	notes := fmt.Sprintf("even-bit parity %v / leading odd parity %v / trailing odd parity %v",
		evenOK, odd1OK, odd34OK)
	return Candidate{
		Format:       "HID Corporate 1000 35-bit",
		Spec:         "Even parity (1) + odd parity (1) + 12-bit facility code + 20-bit card number + odd parity (1)",
		FacilityCode: fc,
		CardNumber:   cn,
		ParityValid:  all,
		ParityNotes:  notes,
	}
}

func decodeCorp1000_48(b string) Candidate {
	// HID Corporate 1000 48-bit. Layout: P P + 22 FC + 23 CN + P.
	fc := bitsToUint(b[2:24])
	cn := bitsToUint(b[24:47])
	p0 := bitsToUint(b[:1])
	p1 := bitsToUint(b[1:2])
	p47 := bitsToUint(b[47:])

	evenCnt := 0
	for i := 2; i < 47; i += 2 {
		if b[i] == '1' {
			evenCnt++
		}
	}
	evenOK := (evenCnt%2 == 0) == (p0 == 0)

	oddCnt := 0
	for i := 1; i < 47; i++ {
		if b[i] == '1' {
			oddCnt++
		}
	}
	odd1OK := (oddCnt%2 == 1) == (p1 == 1)
	odd47OK := (oddCnt%2 == 1) == (p47 == 1)

	all := evenOK && odd1OK && odd47OK
	notes := fmt.Sprintf("even-bit parity %v / leading odd parity %v / trailing odd parity %v",
		evenOK, odd1OK, odd47OK)
	return Candidate{
		Format:       "HID Corporate 1000 48-bit",
		Spec:         "Even parity (1) + odd parity (1) + 22-bit facility code + 23-bit card number + odd parity (1)",
		FacilityCode: fc,
		CardNumber:   cn,
		ParityValid:  all,
		ParityNotes:  notes,
	}
}

// parityEven returns 0 if the count of '1' bits in s is even,
// 1 if odd (i.e. the bit that would make the overall count
// even).
func parityEven(s string) int {
	cnt := 0
	for _, r := range s {
		if r == '1' {
			cnt++
		}
	}
	if cnt%2 == 0 {
		return 0
	}
	return 1
}

// parityOdd returns 0 if the count of '1' bits in s is odd,
// 1 if even.
func parityOdd(s string) int {
	cnt := 0
	for _, r := range s {
		if r == '1' {
			cnt++
		}
	}
	if cnt%2 == 1 {
		return 0
	}
	return 1
}

func parityNotes(evenOK, oddOK bool) string {
	return fmt.Sprintf("leading even parity %v / trailing odd parity %v", evenOK, oddOK)
}

func bitsToUint(s string) uint64 {
	var v uint64
	for _, r := range s {
		v <<= 1
		if r == '1' {
			v |= 1
		}
	}
	return v
}

func bitsToHex(bits string) string {
	if len(bits) == 0 {
		return ""
	}
	// Pad to a byte boundary.
	pad := (8 - (len(bits) % 8)) % 8
	padded := bits + strings.Repeat("0", pad)
	out := make([]byte, len(padded)/8)
	for i := 0; i < len(out); i++ {
		var b byte
		for j := 0; j < 8; j++ {
			b <<= 1
			if padded[i*8+j] == '1' {
				b |= 1
			}
		}
		out[i] = b
	}
	return strings.ToUpper(hex.EncodeToString(out))
}

func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
