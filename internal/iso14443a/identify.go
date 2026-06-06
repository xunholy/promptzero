// Package iso14443a identifies ISO/IEC 14443-3 Type A NFC tags
// from their anti-collision response (ATQA + SAK + UID, plus
// optional ATS). Pure offline parser; no transport, no
// hardware.
//
// Wrap-vs-native judgement: the ATQA / SAK encoding and the
// per-vendor tag-type table are public — NXP application notes
// AN10833 (Table 6) for the Mifare family, AN10927 for UID
// formats, ISO/IEC 14443-3 §6.3 for ATQA bit semantics, and
// 14443-4 §5.2 for ATS structure. Wrapping a FAP for this
// would require an SD-card install + a firmware-fork dependency
// for a pure lookup + bitfield walker. We implement natively so
// operators can paste a Flipper / Proxmark "nfc read" output
// (which always surfaces ATQA + SAK + UID) and identify the
// card type offline — without re-presenting the card to the
// reader.
//
// Pairs with the Bruce / Proxmark / Flipper "nfc read"
// transports (which return the raw ATQA / SAK / UID values) and
// with `mifare_classic_decode_block` (which decodes the content
// once the type is known).
//
// What this package covers:
//   - ATQA bitfield decode: UID size hint, bit-frame anti-
//     collision, 14443-4 compliance hint, RFU bits
//   - SAK bitfield decode: cascade bit, 14443-4 compliance,
//     14443-3 only, RFU bits
//   - Tag-type identification from the (ATQA, SAK) combination
//     — Mifare Classic 1K / 4K / Mini, Mifare Ultralight /
//     NTAG, Mifare DESFire EV1/2/3, JCOP, SmartMX with Classic
//     emulation, Mifare Plus, Infineon variants
//   - UID classification: 4 / 7 / 10-byte length, manufacturer
//     name from the first byte (or after the cascade tag),
//     cascade-byte presence
//   - Optional ATS (Answer To Select) parsing: TL + T0 + FSCI →
//     FSC max frame size, the TA(1) bit-rate capability (the
//     divisors supported each direction), the TB(1) FWI → FWT
//     frame-waiting and SFGI → SFGT start-up-guard times, the
//     TC(1) NAD / CID protocol options, and the historical bytes
//     — to parity with the Type B ATQB decoder (internal/iso14443b)
//
// What this package does NOT cover (deliberately out of scope):
//   - Reading the actual card (operators bring the
//     anti-collision result from their reader)
//   - ISO 14443B (Type B) — separate spec (internal/iso14443b)
package iso14443a

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// ATQA is the decoded Answer To Request - Type A. It's 2 bytes
// on the wire (low byte first); we accept it either way around
// and surface both numeric and bitfield views.
type ATQA struct {
	// Raw is the assembled 16-bit value (high byte << 8 | low byte).
	Raw int `json:"raw"`
	// Hex is the operator-facing 4-character uppercase hex form
	// ("0044", "0344").
	Hex string `json:"hex"`
	// UIDSize is "single" (4 bytes), "double" (7 bytes), or
	// "triple" (10 bytes) — driven by bits 6-7 of the low byte.
	UIDSize string `json:"uid_size"`
	// BitFrameAnticollision is the low-nibble bit-frame anti-
	// collision hint (bits 0-4 of the low byte). Usually only
	// one bit is set; we surface the raw nibble for callers.
	BitFrameAnticollision int `json:"bit_frame_anticollision"`
	// Proprietary is non-zero when the high byte carries
	// vendor-specific bits (e.g. 0x03 for DESFire's "0344",
	// 0x00 for everything else).
	Proprietary int `json:"proprietary"`
	// RFU is non-zero when reserved bits are set (signal of a
	// non-standard reader response).
	RFU int `json:"rfu"`
}

// SAK is the decoded Select Acknowledge - Type A. 1 byte on the
// wire. Bit layout per ISO/IEC 14443-3 §6.4.2 Table 9.
type SAK struct {
	// Raw is the byte value.
	Raw int `json:"raw"`
	// Hex is the operator-facing 2-character form ("08", "20").
	Hex string `json:"hex"`
	// Cascade reports whether bit 2 (0x04) is set — when set,
	// the UID is not yet complete and another anti-collision
	// round is needed. We only see the final SAK in a complete
	// capture, so Cascade=true here means the capture is a
	// mid-cascade snapshot.
	Cascade bool `json:"cascade"`
	// ISO144434Compliant reports whether bit 5 (0x20) is set —
	// the tag supports ISO/IEC 14443-4 (block-oriented
	// protocol).
	ISO144434Compliant bool `json:"iso14443_4_compliant"`
	// ISO144433Only reports whether the tag is ISO 14443-3 only
	// (bit 5 clear). The two are mutually exclusive but we
	// surface both as derived booleans for caller convenience.
	ISO144433Only bool `json:"iso14443_3_only"`
}

// UIDInfo is the decoded view of the UID bytes.
type UIDInfo struct {
	// Hex is the operator-facing uppercase form, no separators.
	Hex string `json:"hex"`
	// LengthBytes is 4 / 7 / 10 — the three documented UID
	// sizes. Any other length is surfaced and flagged via
	// LengthInvalid.
	LengthBytes int `json:"length_bytes"`
	// LengthInvalid is true when the UID length doesn't match
	// the 4 / 7 / 10 set.
	LengthInvalid bool `json:"length_invalid"`
	// CascadeTag is true when the first byte is 0x88 (the
	// official Cascade Tag indicating more UID bytes follow in
	// subsequent SELECT rounds). Random / proprietary UIDs
	// don't set this.
	CascadeTag bool `json:"cascade_tag"`
	// ManufacturerCode is the byte that identifies the IC
	// manufacturer per ISO/IEC 7816-6. For 4-byte UIDs without
	// a cascade tag this is byte 0; for 7-byte UIDs it's byte 0
	// (no cascade in the captured frame). For UIDs starting
	// with 0x88 the cascade tag is followed by 3 bytes of the
	// previous SELECT's UID; the manufacturer byte sits at
	// offset 0 of the next cascade round (not always visible
	// from a single ATQA/SAK/UID snapshot).
	ManufacturerCode int    `json:"manufacturer_code"`
	ManufacturerName string `json:"manufacturer_name,omitempty"`
}

// ATS is the decoded Answer To Select (ISO 14443-4 §5.2). Only
// tags with SAK bit 5 set support ATS; the decoder is invoked
// when the caller provides it.
type ATS struct {
	// LengthByte is the first byte (TL) — total length of the
	// ATS in bytes (including TL itself).
	LengthByte int `json:"length_byte"`
	// FormatByte is T0 (the second byte), present when TL >= 2.
	// Indicates which of TA / TB / TC interface bytes are
	// present and the FSCI (Frame Size for proximity Card Index)
	// in the low nibble.
	FormatByte int `json:"format_byte,omitempty"`
	// TA1Present / TB1Present / TC1Present mirror the documented
	// presence flags (T0 bits 4-6). When present, the interface
	// bytes are field-decoded below (to parity with the Type B
	// ATQB decoder in internal/iso14443b).
	TA1Present bool `json:"ta1_present"`
	TB1Present bool `json:"tb1_present"`
	TC1Present bool `json:"tc1_present"`
	// FSCI is the low nibble of T0 (Frame Size for proximity
	// Card Index, 0-8). Maps to FSC via the documented table.
	FSCI int `json:"fsci"`
	FSC  int `json:"fsc,omitempty"`
	// BitRate is the decoded TA(1) bit-rate capability (ISO
	// 14443-4 §5.2.2): the divisors the card supports in each
	// direction (106 kbit/s is always supported). nil when TA(1)
	// is absent.
	BitRate *ATSBitRate `json:"bit_rate,omitempty"`
	// FWI / FWTms come from the high nibble of TB(1) (ISO 14443-4
	// §5.2.5): the Frame Waiting Time the reader must allow.
	FWI   int     `json:"fwi,omitempty"`
	FWTms float64 `json:"fwt_ms,omitempty"`
	// SFGI / SFGTms come from the low nibble of TB(1) (§5.2.5):
	// the Start-up Frame Guard Time the card needs after ATS.
	SFGI   int     `json:"sfgi,omitempty"`
	SFGTms float64 `json:"sfgt_ms,omitempty"`
	// NADSupported / CIDSupported come from TC(1) (§5.2.4).
	NADSupported bool `json:"nad_supported,omitempty"`
	CIDSupported bool `json:"cid_supported,omitempty"`
	// InterfaceBytesHex is the raw TA1 / TB1 / TC1 bytes (when
	// present) as hex (kept alongside the decoded fields).
	InterfaceBytesHex string `json:"interface_bytes_hex,omitempty"`
	// HistoricalBytesHex is the rest of the ATS — the
	// historical bytes, vendor-specific. Often carries an
	// IC version string or proprietary tag identifier.
	HistoricalBytesHex string `json:"historical_bytes_hex,omitempty"`
	// HistoricalASCII is the printable-ASCII rendering of
	// the historical bytes — useful when the bytes carry an
	// ASCII vendor string.
	HistoricalASCII string `json:"historical_ascii,omitempty"`
}

// Identification is the top-level result of an identify call.
type Identification struct {
	// ATQA / SAK / UID are the parsed inputs.
	ATQA    ATQA    `json:"atqa"`
	SAK     SAK     `json:"sak"`
	UIDInfo UIDInfo `json:"uid"`
	// TagType is the recognised card type from the
	// (ATQA, SAK) combination ("Mifare Classic 1K",
	// "Mifare DESFire EV1/2/3", "Mifare Ultralight / NTAG", etc.)
	// or "Unknown" when no entry matches.
	TagType string `json:"tag_type"`
	// TagFamily groups identified types into a coarser family
	// ("Mifare Classic", "Mifare Ultralight / NTAG", "DESFire",
	// "ISO 14443-4", "Other"). Useful for routing to follow-on
	// Specs.
	TagFamily string `json:"tag_family,omitempty"`
	// ATS is the parsed Answer To Select when the caller
	// supplied it. nil otherwise.
	ATS *ATS `json:"ats,omitempty"`
}

// Identify decodes the ATQA + SAK + UID strings (with optional
// ATS) into the structured Identification.
//
// All inputs accept the same separators as our other pure-
// decoder packages (':' / '-' / '_' / whitespace), and ATQA
// is accepted in either byte order ("0004" or "0400") — we
// canonicalise to high-byte-then-low-byte.
func Identify(atqaHex, sakHex, uidHex, atsHex string) (Identification, error) {
	atqa, err := parseATQA(atqaHex)
	if err != nil {
		return Identification{}, fmt.Errorf("iso14443a: ATQA: %w", err)
	}
	sak, err := parseSAK(sakHex)
	if err != nil {
		return Identification{}, fmt.Errorf("iso14443a: SAK: %w", err)
	}
	uid, err := parseUID(uidHex)
	if err != nil {
		return Identification{}, fmt.Errorf("iso14443a: UID: %w", err)
	}
	out := Identification{
		ATQA:    atqa,
		SAK:     sak,
		UIDInfo: uid,
	}
	out.TagType, out.TagFamily = identifyTagType(atqa, sak)
	if atsHex != "" {
		ats, err := parseATS(atsHex)
		if err != nil {
			return out, fmt.Errorf("iso14443a: ATS: %w", err)
		}
		out.ATS = &ats
	}
	return out, nil
}

// parseATQA decodes the 2-byte Answer To Request. We take the
// input string as the canonical big-endian-rendered value
// ("0044", "0344") — the form every public table uses. Wire-
// byte order is the operator's tool's concern; if a tool displays
// it backwards the operator can reverse before calling.
func parseATQA(s string) (ATQA, error) {
	cleaned := stripSeparators(s)
	if cleaned == "" {
		return ATQA{}, fmt.Errorf("empty")
	}
	if len(cleaned) != 4 {
		return ATQA{}, fmt.Errorf("want 4 hex chars (2 bytes), got %d", len(cleaned))
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return ATQA{}, fmt.Errorf("invalid hex: %w", err)
	}
	// Decode the input as a big-endian 16-bit value — the form
	// printed in NXP application notes and every public table.
	hi := b[0]
	lo := b[1]
	raw := int(hi)<<8 | int(lo)
	// Auto-detect reversed input: if the BE form isn't in our
	// table but the LE form is, swap. This rescues operators who
	// paste from tools that show wire byte order.
	if _, _, ok := lookupTagType(raw, -1); !ok {
		swapped := int(lo)<<8 | int(hi)
		if _, _, ok := lookupTagType(swapped, -1); ok {
			raw = swapped
			hi, lo = lo, hi
		}
	}
	return ATQA{
		Raw:                   raw,
		Hex:                   fmt.Sprintf("%04X", raw),
		UIDSize:               atqaUIDSize(lo),
		BitFrameAnticollision: int(lo & 0x1F),
		Proprietary:           int(hi & 0x0F),
		RFU:                   int(hi&0xF0) | int(lo&0x20),
	}, nil
}

// lookupTagType wraps the (ATQA, SAK) → tag-type table for the
// ATQA parser's endian-detection probe. Returns (type, family, ok).
//
// Pass sak = -1 to query "any SAK known with this ATQA" — used
// during ATQA endian detection when the SAK hasn't been parsed
// yet. Pass the actual SAK to query the exact pair.
func lookupTagType(atqa, sak int) (string, string, bool) {
	if sak >= 0 {
		if entry, ok := tagTypes[tagKey{atqa: atqa, sak: sak}]; ok {
			return entry.tagType, entry.family, true
		}
	}
	// ATQA-only probe: try every SAK already in the table.
	for k, entry := range tagTypes {
		if k.atqa == atqa {
			return entry.tagType, entry.family, true
		}
	}
	return "", "", false
}

// atqaUIDSize returns "single" / "double" / "triple" / "unknown"
// from bits 6-7 of the low byte.
func atqaUIDSize(lo byte) string {
	switch (lo >> 6) & 0x03 {
	case 0:
		return "single (4-byte)"
	case 1:
		return "double (7-byte)"
	case 2:
		return "triple (10-byte)"
	}
	return "RFU"
}

// parseSAK decodes the 1-byte SAK.
func parseSAK(s string) (SAK, error) {
	cleaned := stripSeparators(s)
	if cleaned == "" {
		return SAK{}, fmt.Errorf("empty")
	}
	if len(cleaned) != 2 {
		return SAK{}, fmt.Errorf("want 2 hex chars (1 byte), got %d", len(cleaned))
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return SAK{}, fmt.Errorf("invalid hex: %w", err)
	}
	v := b[0]
	return SAK{
		Raw:                int(v),
		Hex:                fmt.Sprintf("%02X", v),
		Cascade:            v&0x04 != 0,
		ISO144434Compliant: v&0x20 != 0,
		ISO144433Only:      v&0x20 == 0,
	}, nil
}

// parseUID decodes the variable-length UID.
func parseUID(s string) (UIDInfo, error) {
	cleaned := stripSeparators(s)
	if cleaned == "" {
		return UIDInfo{}, fmt.Errorf("empty")
	}
	if len(cleaned)%2 != 0 {
		return UIDInfo{}, fmt.Errorf("want even number of hex chars, got %d", len(cleaned))
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return UIDInfo{}, fmt.Errorf("invalid hex: %w", err)
	}
	out := UIDInfo{
		Hex:           strings.ToUpper(cleaned),
		LengthBytes:   len(b),
		LengthInvalid: len(b) != 4 && len(b) != 7 && len(b) != 10,
		CascadeTag:    b[0] == 0x88,
	}
	// Manufacturer code: for non-cascade UIDs it's byte 0; for
	// cascade-tag UIDs the manufacturer sits at the first byte
	// after the cascade tag. We render whichever is more useful.
	if out.CascadeTag && len(b) > 1 {
		out.ManufacturerCode = int(b[1])
	} else {
		out.ManufacturerCode = int(b[0])
	}
	if name, ok := manufacturers[byte(out.ManufacturerCode)]; ok {
		out.ManufacturerName = name
	}
	return out, nil
}

// parseATS decodes the Answer To Select.
//
//	TL (1) + T0 (1) + optional TA1 / TB1 / TC1 + historical bytes
//
// TL is the total length of the ATS including TL itself. T0
// bits 4-6 indicate TA1/TB1/TC1 presence; low nibble is FSCI
// (Frame Size for proximity Card Index).
func parseATS(s string) (ATS, error) {
	cleaned := stripSeparators(s)
	if cleaned == "" {
		return ATS{}, fmt.Errorf("empty")
	}
	if len(cleaned)%2 != 0 {
		return ATS{}, fmt.Errorf("want even number of hex chars, got %d", len(cleaned))
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return ATS{}, fmt.Errorf("invalid hex: %w", err)
	}
	out := ATS{LengthByte: int(b[0])}
	if len(b) < int(b[0]) {
		return out, fmt.Errorf("declared TL %d exceeds buffer length %d", b[0], len(b))
	}
	if int(b[0]) < 2 {
		// Only TL — no T0 / interface bytes / historicals.
		return out, nil
	}
	t0 := b[1]
	out.FormatByte = int(t0)
	out.FSCI = int(t0 & 0x0F)
	out.FSC = fsciToFSC(out.FSCI)
	out.TA1Present = t0&0x10 != 0
	out.TB1Present = t0&0x20 != 0
	out.TC1Present = t0&0x40 != 0
	off := 2
	var ifBytes []byte
	if out.TA1Present && off < len(b) {
		ta1 := b[off]
		ifBytes = append(ifBytes, ta1)
		out.BitRate = decodeATSBitRate(ta1)
		off++
	}
	if out.TB1Present && off < len(b) {
		tb1 := b[off]
		ifBytes = append(ifBytes, tb1)
		out.FWI = int(tb1 >> 4)
		out.FWTms = atsFrameTimeMs(out.FWI)
		out.SFGI = int(tb1 & 0x0F)
		out.SFGTms = atsFrameTimeMs(out.SFGI)
		off++
	}
	if out.TC1Present && off < len(b) {
		tc1 := b[off]
		ifBytes = append(ifBytes, tc1)
		out.NADSupported = tc1&0x01 != 0
		out.CIDSupported = tc1&0x02 != 0
		off++
	}
	if len(ifBytes) > 0 {
		out.InterfaceBytesHex = hexString(ifBytes)
	}
	if off < len(b) {
		hist := b[off:]
		out.HistoricalBytesHex = hexString(hist)
		out.HistoricalASCII = asciiPreview(hist)
	}
	return out, nil
}

// fsciToFSC maps the FSCI nibble (0-8) to the Frame Size for
// proximity Card (FSC, bytes) per ISO 14443-4 §5.2.5 Table 4.
func fsciToFSC(fsci int) int {
	table := []int{16, 24, 32, 40, 48, 64, 96, 128, 256}
	if fsci < 0 || fsci >= len(table) {
		return 0
	}
	return table[fsci]
}

// ATSBitRate is the decoded TA(1) bit-rate capability of the ATS
// (ISO 14443-4 §5.2.2). 106 kbit/s (the base rate) is always
// supported and is always present in each list.
type ATSBitRate struct {
	SameBitrateBothDirections bool  `json:"same_bitrate_both_directions"`
	PICCtoPCDkbit             []int `json:"picc_to_pcd_kbit"` // DS divisors (card → reader)
	PCDtoPICCkbit             []int `json:"pcd_to_picc_kbit"` // DR divisors (reader → card)
}

// decodeATSBitRate decodes TA(1): bit 8 = same rate both ways; bits
// 7-5 = DS (PICC→PCD) for 848/424/212; bits 3-1 = DR (PCD→PICC) for
// 848/424/212 (ISO 14443-4 §5.2.2). Bit 4 / bit 0 are RFU.
func decodeATSBitRate(ta1 byte) *ATSBitRate {
	r := &ATSBitRate{
		SameBitrateBothDirections: ta1&0x80 != 0,
		PICCtoPCDkbit:             []int{106},
		PCDtoPICCkbit:             []int{106},
	}
	if ta1&0x10 != 0 { // DS bit5 → 2x
		r.PICCtoPCDkbit = append(r.PICCtoPCDkbit, 212)
	}
	if ta1&0x20 != 0 { // DS bit6 → 4x
		r.PICCtoPCDkbit = append(r.PICCtoPCDkbit, 424)
	}
	if ta1&0x40 != 0 { // DS bit7 → 8x
		r.PICCtoPCDkbit = append(r.PICCtoPCDkbit, 848)
	}
	if ta1&0x02 != 0 { // DR bit1 → 2x
		r.PCDtoPICCkbit = append(r.PCDtoPICCkbit, 212)
	}
	if ta1&0x04 != 0 { // DR bit2 → 4x
		r.PCDtoPICCkbit = append(r.PCDtoPICCkbit, 424)
	}
	if ta1&0x08 != 0 { // DR bit3 → 8x
		r.PCDtoPICCkbit = append(r.PCDtoPICCkbit, 848)
	}
	return r
}

// atsFrameTimeMs converts an FWI / SFGI integer (0-14) to its time
// in milliseconds: (256 × 16 / fc) × 2^n with fc = 13.56 MHz, i.e.
// 0.302064 ms × 2^n (ISO 14443-4 §5.2.5). 15 is RFU → 0.
func atsFrameTimeMs(n int) float64 {
	if n < 0 || n > 14 {
		return 0
	}
	return 0.302064 * float64(int(1)<<uint(n))
}

// asciiPreview renders bytes as ASCII with '.' for non-printable.
func asciiPreview(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c <= 0x7E {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}

// hexString renders bytes as uppercase no-separator hex.
func hexString(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}

// stripSeparators mirrors the convention across our pure-decoder
// packages.
func stripSeparators(s string) string {
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
