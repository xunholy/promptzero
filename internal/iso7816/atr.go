// Package iso7816 decodes ISO/IEC 7816-3 Answer To Reset (ATR)
// strings — the response every contact smart card sends when
// reset. Pure offline parser; no transport, no hardware.
//
// Wrap-vs-native judgement: ISO 7816-3 is a fully public
// standard. The ATR walker is a chain of optional interface
// bytes (TAi / TBi / TCi / TDi) driven by the high-nibble flags
// of the preceding TDi, followed by K historical bytes and an
// optional TCK check byte. Wrapping a FAP for this would
// require an SD-card install + a firmware-fork dependency for a
// pure walker. Native delivers offline analysis — operators
// paste an ATR from any PC/SC reader output (the `pcsc_scan`
// tool, `gscriptor`, `pcscd` logs) and identify the card type
// without a card present.
//
// What this package covers:
//   - TS (Initial Character) convention detection — direct
//     (0x3B) vs inverse (0x3F)
//   - T0 (Format Character) decode — Y1 (interface-byte
//     presence flags) + K (historical-byte count)
//   - Interface-byte chain walk — TA / TB / TC / TD for each
//     round, with TDi driving the next round's T (protocol
//     type) + presence flags
//   - Per-round protocol identification (T=0 character-oriented,
//     T=1 block-oriented, T=15 global parameters)
//   - Historical-bytes decode — Category Indicator (first
//     byte: 0x00 / 0x10 / 0x80 / 0x8x compact-TLV / 0x9x life-
//     cycle / others), printable-ASCII preview
//   - Optional TCK (Check Character) extraction + XOR
//     validation when present (TCK is required when any T != 0)
//   - TA1-specific decode: clock conversion factor Fi + work
//     etu factor Di, used to compute the card's bit rate
//
// What this package does NOT cover (deliberately out of scope):
//   - PC/SC-specific framing around the ATR (operators bring
//     the bare ATR bytes)
//   - Full Compact-TLV historical-bytes dissection (just the
//     Category Indicator byte + raw historical hex) — happy to
//     add when a caller materialises with a concrete need
//   - Reading the actual card or driving a reader
//   - PPS (Protocol and Parameters Selection) — that's a
//     post-ATR exchange, not the ATR itself
package iso7816

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Convention names the bit-encoding convention selected by TS.
type Convention string

const (
	// ConventionDirect — TS = 0x3B. LSB first, '1' = high level.
	ConventionDirect Convention = "direct"
	// ConventionInverse — TS = 0x3F. MSB first, '1' = low level.
	ConventionInverse Convention = "inverse"
)

// InterfaceByte is one (round, kind, value) triple in the
// interface-byte chain.
type InterfaceByte struct {
	// Round is the 1-based round index (TA1 / TB1 / TC1 / TD1
	// are round 1, TA2 / TB2 / TC2 / TD2 are round 2, etc.).
	Round int `json:"round"`
	// Kind is "TA" / "TB" / "TC" / "TD".
	Kind string `json:"kind"`
	// Raw is the byte value.
	Raw int `json:"raw"`
	// Hex is the operator-facing 2-character form.
	Hex string `json:"hex"`
	// Decoded carries per-byte field decode (e.g. TA1 → Fi/Di,
	// TDi → next-round T + Y nibbles). nil for bytes we don't
	// dissect further.
	Decoded map[string]any `json:"decoded,omitempty"`
}

// ATR is the top-level decoded view.
type ATR struct {
	// TS is the raw Initial Character byte.
	TS int `json:"ts"`
	// TSHex is the operator-facing 2-character form.
	TSHex string `json:"ts_hex"`
	// Convention is "direct" (0x3B) or "inverse" (0x3F).
	Convention Convention `json:"convention"`
	// T0 is the raw Format Character byte.
	T0 int `json:"t0"`
	// T0Hex is the operator-facing form.
	T0Hex string `json:"t0_hex"`
	// HistoricalBytesCount is K — the count surfaced in T0.
	HistoricalBytesCount int `json:"historical_bytes_count"`
	// InterfaceBytes is the ordered list of TA/TB/TC/TD bytes
	// in the chain.
	InterfaceBytes []InterfaceByte `json:"interface_bytes,omitempty"`
	// ProtocolsAnnounced is the list of distinct T values seen
	// in TDi low nibbles. T=0 + T=1 are the common ones.
	ProtocolsAnnounced []int `json:"protocols_announced,omitempty"`
	// HistoricalBytesHex is the raw historical bytes.
	HistoricalBytesHex string `json:"historical_bytes_hex,omitempty"`
	// HistoricalASCII is the printable-ASCII rendering of the
	// historical bytes (non-printable → '.').
	HistoricalASCII string `json:"historical_ascii,omitempty"`
	// HistoricalCategoryIndicator is the first historical byte
	// when present (Category Indicator per ISO 7816-4 §8).
	HistoricalCategoryIndicator string `json:"historical_category_indicator,omitempty"`
	// TCK is the Check Character byte (XOR of T0 onwards) when
	// present. TCK is required when any non-T=0 protocol is
	// announced.
	TCK *int `json:"tck,omitempty"`
	// TCKValid mirrors the integrity check.
	TCKValid bool `json:"tck_valid"`
	// TCKExpected reports the computed XOR value for callers
	// debugging a TCK mismatch.
	TCKExpected int `json:"tck_expected"`
	// PayloadHex is the raw input bytes (uppercase, no
	// separators).
	PayloadHex string `json:"payload_hex"`
}

// Decode parses a hex-encoded ATR string. Tolerates ':' / '-'
// / '_' / whitespace separators.
func Decode(hexBlob string) (ATR, error) {
	cleaned := stripSeparators(hexBlob)
	if cleaned == "" {
		return ATR{}, fmt.Errorf("iso7816: empty ATR input")
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return ATR{}, fmt.Errorf("iso7816: invalid hex: %w", err)
	}
	return DecodeBytes(b)
}

// DecodeBytes is the byte-slice variant of Decode.
func DecodeBytes(b []byte) (ATR, error) {
	if len(b) < 2 {
		return ATR{}, fmt.Errorf("iso7816: ATR %d bytes < 2-byte minimum (TS + T0)", len(b))
	}
	ts := b[0]
	var conv Convention
	switch ts {
	case 0x3B:
		conv = ConventionDirect
	case 0x3F:
		conv = ConventionInverse
	default:
		return ATR{}, fmt.Errorf("iso7816: TS = 0x%02X is not 0x3B (direct) or 0x3F (inverse)", ts)
	}
	t0 := b[1]
	out := ATR{
		TS:                   int(ts),
		TSHex:                fmt.Sprintf("%02X", ts),
		Convention:           conv,
		T0:                   int(t0),
		T0Hex:                fmt.Sprintf("%02X", t0),
		HistoricalBytesCount: int(t0 & 0x0F),
		PayloadHex:           hexString(b),
	}
	// Walk interface-byte rounds. Y1 is the high nibble of T0;
	// subsequent Y comes from the high nibble of the previous
	// TDi.
	y := byte(t0 >> 4)
	off := 2
	round := 1
	protocols := map[int]bool{}
	for y != 0 {
		taPresent := y&0x01 != 0
		tbPresent := y&0x02 != 0
		tcPresent := y&0x04 != 0
		tdPresent := y&0x08 != 0
		if taPresent {
			if off >= len(b) {
				return out, fmt.Errorf("iso7816: TA%d missing at offset %d", round, off)
			}
			ib := InterfaceByte{
				Round: round,
				Kind:  "TA",
				Raw:   int(b[off]),
				Hex:   fmt.Sprintf("%02X", b[off]),
			}
			if round == 1 {
				ib.Decoded = decodeTA1(b[off])
			}
			out.InterfaceBytes = append(out.InterfaceBytes, ib)
			off++
		}
		if tbPresent {
			if off >= len(b) {
				return out, fmt.Errorf("iso7816: TB%d missing at offset %d", round, off)
			}
			out.InterfaceBytes = append(out.InterfaceBytes, InterfaceByte{
				Round: round,
				Kind:  "TB",
				Raw:   int(b[off]),
				Hex:   fmt.Sprintf("%02X", b[off]),
			})
			off++
		}
		if tcPresent {
			if off >= len(b) {
				return out, fmt.Errorf("iso7816: TC%d missing at offset %d", round, off)
			}
			out.InterfaceBytes = append(out.InterfaceBytes, InterfaceByte{
				Round: round,
				Kind:  "TC",
				Raw:   int(b[off]),
				Hex:   fmt.Sprintf("%02X", b[off]),
			})
			off++
		}
		if tdPresent {
			if off >= len(b) {
				return out, fmt.Errorf("iso7816: TD%d missing at offset %d", round, off)
			}
			td := b[off]
			nextY := td >> 4
			proto := int(td & 0x0F)
			protocols[proto] = true
			out.InterfaceBytes = append(out.InterfaceBytes, InterfaceByte{
				Round: round,
				Kind:  "TD",
				Raw:   int(td),
				Hex:   fmt.Sprintf("%02X", td),
				Decoded: map[string]any{
					"next_protocol_type": proto,
					"next_y":             int(nextY),
				},
			})
			off++
			y = nextY
			round++
		} else {
			break
		}
	}
	// Historical bytes
	k := out.HistoricalBytesCount
	if k > 0 {
		end := off + k
		if end > len(b) {
			return out, fmt.Errorf("iso7816: historical bytes %d exceed buffer (only %d left)",
				k, len(b)-off)
		}
		hist := b[off:end]
		out.HistoricalBytesHex = hexString(hist)
		out.HistoricalASCII = asciiPreview(hist)
		if len(hist) > 0 {
			out.HistoricalCategoryIndicator = categoryIndicatorName(hist[0])
		}
		off = end
	}
	// Sort protocols announced (deterministic JSON).
	for p := range protocols {
		out.ProtocolsAnnounced = append(out.ProtocolsAnnounced, p)
	}
	sortInts(out.ProtocolsAnnounced)
	// TCK: required when any T != 0 is announced. Compute the
	// XOR of T0 onward (excluding TS) and compare.
	needsTCK := false
	for p := range protocols {
		if p != 0 {
			needsTCK = true
		}
	}
	if off < len(b) {
		tck := int(b[off])
		out.TCK = &tck
		var x byte
		for i := 1; i < off; i++ {
			x ^= b[i]
		}
		out.TCKExpected = int(x)
		out.TCKValid = byte(tck) == x
		off++
	}
	if needsTCK && out.TCK == nil {
		return out, fmt.Errorf("iso7816: TCK required (non-T=0 protocol announced) but absent")
	}
	if off < len(b) {
		return out, fmt.Errorf("iso7816: %d trailing bytes after ATR", len(b)-off)
	}
	return out, nil
}

// decodeTA1 decodes the TA1 byte — clock conversion factor Fi
// (high nibble) and work etu factor Di (low nibble). Per
// ISO/IEC 7816-3 §8.3 Tables 7 and 8. Used to compute the
// card's bit rate from the reader clock: bit_rate = clock × Di / Fi.
func decodeTA1(b byte) map[string]any {
	fi := (b >> 4) & 0x0F
	di := b & 0x0F
	return map[string]any{
		"fi":       int(fi),
		"di":       int(di),
		"fi_value": fiTable[fi],
		"di_value": diTable[di],
	}
}

// fiTable maps the Fi nibble (high nibble of TA1) to the clock
// rate conversion integer per ISO 7816-3 Table 7.
var fiTable = [16]int{
	372, 372, 558, 744, 1116, 1488, 1860, 0,
	0, 512, 768, 1024, 1536, 2048, 0, 0,
}

// diTable maps the Di nibble (low nibble of TA1) to the baud
// rate adjustment integer per ISO 7816-3 Table 8.
var diTable = [16]int{
	0, 1, 2, 4, 8, 16, 32, 64,
	12, 20, 0, 0, 0, 0, 0, 0,
}

// categoryIndicatorName maps the first historical byte to its
// canonical name per ISO 7816-4 §8 Table 38. The Category
// Indicator drives the format of the rest of the historical
// bytes — most modern cards use 0x80 (compact-TLV).
func categoryIndicatorName(c byte) string {
	switch {
	case c == 0x00:
		return "0x00 — historical bytes are status indicator + 6 reserved + (status word optional)"
	case c == 0x10:
		return "0x10 — DIR data reference present"
	case c == 0x80:
		return "0x80 — Compact-TLV objects (status indicator may follow)"
	case c == 0x81:
		return "0x81 — Compact-TLV objects + status indicator at the end"
	case c >= 0x82 && c <= 0x8F:
		return "0x82-0x8F — RFU compact-TLV format"
	case c == 0x90:
		return "0x90 — proprietary, but follows TLV-like rules"
	}
	return fmt.Sprintf("0x%02X — proprietary / RFU", c)
}

// hexString renders bytes as uppercase no-separator hex.
func hexString(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
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

// sortInts sorts a slice of ints in-place ascending. Tiny
// helper to keep ProtocolsAnnounced deterministic in JSON
// output without pulling in sort.
func sortInts(a []int) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
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
