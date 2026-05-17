// Package emv decodes EMV BER-TLV structures from contactless and
// contact payment card APDU responses. Pure offline parser — no
// hardware, no network — so the same code paths run in unit tests
// and in any host-side tooling that consumes captured EMV data
// (saved NFC reads, debugger transcripts, EMV Co specification
// examples).
//
// Wrap-vs-native judgement: EMV BER-TLV is a well-documented
// public format (EMV Book 3 §B Annex B). The walker is ~100 lines
// of bit-twiddling over a byte slice. Wrapping a FAP for this
// would add an SD-card install step + a firmware-fork dependency
// for what is, ultimately, a recursive descent parser. We
// implement natively here so operators can decode an EMV transcript
// they pasted from a forum post without a Flipper attached.
//
// What this package covers:
//   - BER-TLV walker with multi-byte tag + length support
//   - Constructed vs primitive recognition (per the BER class+P/C bit)
//   - Curated tag-name table for the ~80 most-common EMV tags
//
// What this package does NOT cover (deliberately out of scope):
//   - Cryptogram verification (Application Cryptogram derivation,
//     CDA, DDA — these need issuer public keys we don't have)
//   - Online authorisation flow (issuer scripting, ARPC)
//   - TLV write / re-encode (round-tripping a tree back to bytes —
//     happy to add if a caller materialises)
package emv

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// TLV is one decoded BER-TLV entry. Constructed entries carry their
// child TLVs in Children; primitive entries carry the raw value
// bytes in Value (Children is nil).
type TLV struct {
	// Tag is the BER tag as a uint32 — the encoded big-endian bytes
	// of the tag identifier. Single-byte tags use the low byte;
	// multi-byte tags pack into successively higher bytes (so 0x9F02
	// is the most common Amount Authorised tag, 0x5F2A is the
	// Transaction Currency Code, etc.). Stored as uint32 so the
	// tag-name lookup map can key on it without a string conversion.
	Tag uint32 `json:"tag"`
	// TagHex is the operator-facing rendering of Tag — always
	// uppercase, no 0x prefix, no leading zeros. Matches the format
	// every EMV book / forum post uses ("9F02", "5F2A").
	TagHex string `json:"tag_hex"`
	// Name is the canonical EMV name for the tag, or "" when the
	// tag isn't in the curated lookup table.
	Name string `json:"name,omitempty"`
	// Constructed reports whether the value bytes contain nested
	// TLVs (per BER class+P/C bit). When true, Children holds the
	// parsed sub-tree and Value is the raw bytes (kept for callers
	// that want to re-emit the original structure).
	Constructed bool   `json:"constructed"`
	Value       []byte `json:"value,omitempty"`
	// ValueHex is the operator-facing hex rendering of Value.
	// Convenient for JSON output without forcing every caller to
	// re-encode.
	ValueHex string `json:"value_hex,omitempty"`
	// Children is non-nil iff Constructed is true. May be empty
	// when a constructed tag's body is zero-length (legal per the
	// spec, occasionally seen in templated responses).
	Children []TLV `json:"children,omitempty"`
}

// Parse decodes a hex-encoded EMV BER-TLV blob (the common form
// operator-supplied EMV captures take) into a flat list of
// top-level TLVs. Constructed tags are walked recursively into
// each TLV's Children. Returns an error on malformed input
// (truncated tag/length, length-exceeds-buffer, length-encoding
// reserved value).
func Parse(hexBlob string) ([]TLV, error) {
	cleaned := stripSeparators(hexBlob)
	if cleaned == "" {
		return nil, fmt.Errorf("emv: empty input")
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("emv: invalid hex: %w", err)
	}
	return ParseBytes(b)
}

// ParseBytes is the byte-slice variant of Parse for callers that
// already have raw EMV bytes (e.g. from a PC/SC reader). Same
// recursive walker; same error contract.
func ParseBytes(b []byte) ([]TLV, error) {
	out, n, err := parseAll(b)
	if err != nil {
		return nil, err
	}
	if n != len(b) {
		return out, fmt.Errorf("emv: trailing bytes after TLV stream: %d bytes left", len(b)-n)
	}
	return out, nil
}

// parseAll walks `b` until it hits the end or an error, returning
// the parsed TLVs and the number of bytes consumed.
func parseAll(b []byte) ([]TLV, int, error) {
	var out []TLV
	off := 0
	for off < len(b) {
		// EMV permits inter-TLV 0x00 padding bytes (sometimes used
		// to round responses to a record boundary). Skip them.
		if b[off] == 0x00 {
			off++
			continue
		}
		tlv, consumed, err := parseOne(b[off:])
		if err != nil {
			return out, off, fmt.Errorf("emv: at offset %d: %w", off, err)
		}
		out = append(out, tlv)
		off += consumed
	}
	return out, off, nil
}

// parseOne decodes a single TLV starting at b[0] and returns the
// decoded entry plus the number of bytes consumed. Recurses into
// constructed values.
func parseOne(b []byte) (TLV, int, error) {
	if len(b) == 0 {
		return TLV{}, 0, fmt.Errorf("unexpected end of input")
	}
	tag, tagLen, constructed, err := readTag(b)
	if err != nil {
		return TLV{}, 0, err
	}
	if tagLen >= len(b) {
		return TLV{}, 0, fmt.Errorf("truncated TLV: tag has no length byte")
	}
	length, lengthLen, err := readLength(b[tagLen:])
	if err != nil {
		return TLV{}, 0, err
	}
	headerLen := tagLen + lengthLen
	end := headerLen + length
	if end > len(b) {
		return TLV{}, 0, fmt.Errorf("TLV length %d exceeds remaining buffer (%d bytes)", length, len(b)-headerLen)
	}
	value := b[headerLen:end]

	tlv := TLV{
		Tag:         tag,
		TagHex:      formatTag(tag),
		Name:        TagName(tag),
		Constructed: constructed,
		Value:       value,
		ValueHex:    strings.ToUpper(hex.EncodeToString(value)),
	}
	if constructed {
		children, _, err := parseAll(value)
		if err != nil {
			return tlv, end, fmt.Errorf("inside constructed %s: %w", tlv.TagHex, err)
		}
		tlv.Children = children
	}
	return tlv, end, nil
}

// readTag decodes the BER tag at b[0]. Returns (tag-as-uint32,
// length-of-tag-in-bytes, constructed flag).
//
// BER tag layout:
//   - Byte 1: bits 8-7 = class, bit 6 = P/C, bits 5-1 = tag number.
//   - If tag bits 5-1 == 11111 (0x1F), tag continues in subsequent
//     bytes — each has high bit = 1 to indicate "more follows",
//     low 7 bits carry tag data. Last continuation byte has high
//     bit = 0.
//
// Tag is packed into uint32 as the raw concatenated bytes (so 0x9F02
// becomes 0x00009F02, 0x5F2A becomes 0x00005F2A). This matches the
// "tag hex" form every EMV reference uses.
func readTag(b []byte) (tag uint32, length int, constructed bool, err error) {
	if len(b) == 0 {
		return 0, 0, false, fmt.Errorf("readTag: empty input")
	}
	first := b[0]
	constructed = first&0x20 != 0
	tag = uint32(first)
	length = 1
	if first&0x1F != 0x1F {
		// Single-byte tag.
		return tag, length, constructed, nil
	}
	// Multi-byte tag — continue while high bit is set.
	for {
		if length >= len(b) {
			return 0, 0, false, fmt.Errorf("readTag: truncated multi-byte tag")
		}
		// Defend against an obscenely long multi-byte tag — EMV
		// reserves up to 4 bytes total. Anything more is malformed.
		if length >= 4 {
			return 0, 0, false, fmt.Errorf("readTag: multi-byte tag exceeds 4 bytes")
		}
		next := b[length]
		tag = (tag << 8) | uint32(next)
		length++
		if next&0x80 == 0 {
			// Last byte (high bit 0).
			return tag, length, constructed, nil
		}
	}
}

// readLength decodes the BER length field at b[0]. Returns
// (length-value, length-of-length-field-in-bytes).
//
// BER length forms:
//   - Short form: 0x00-0x7F → length is the byte itself, 1 byte total.
//   - Long form: 0x81-0x84 → low nibble = number of length bytes
//     that follow (max 4 = 32-bit length).
//   - 0x80 and 0x85-0xFE are reserved / forbidden in EMV (which uses
//     definite length only); we reject them.
func readLength(b []byte) (length int, fieldLen int, err error) {
	if len(b) == 0 {
		return 0, 0, fmt.Errorf("readLength: empty input")
	}
	first := b[0]
	if first&0x80 == 0 {
		return int(first), 1, nil
	}
	numBytes := int(first & 0x7F)
	if numBytes == 0 {
		// 0x80 = indefinite length — EMV forbids it.
		return 0, 0, fmt.Errorf("readLength: indefinite-length form not permitted in EMV")
	}
	if numBytes > 4 {
		return 0, 0, fmt.Errorf("readLength: long-form length > 4 bytes (got %d)", numBytes)
	}
	if 1+numBytes > len(b) {
		return 0, 0, fmt.Errorf("readLength: truncated long-form length")
	}
	var l int
	for i := 0; i < numBytes; i++ {
		l = (l << 8) | int(b[1+i])
	}
	return l, 1 + numBytes, nil
}

// formatTag renders a packed tag uint32 as the canonical uppercase
// hex string EMV references use ("9F02", "5F2A", "5A"). Single-byte
// tags get exactly 2 hex chars; multi-byte tags get the natural
// concatenated form with no zero-padding.
func formatTag(tag uint32) string {
	switch {
	case tag <= 0xFF:
		return fmt.Sprintf("%02X", tag)
	case tag <= 0xFFFF:
		return fmt.Sprintf("%04X", tag)
	case tag <= 0xFFFFFF:
		return fmt.Sprintf("%06X", tag)
	default:
		return fmt.Sprintf("%08X", tag)
	}
}

// stripSeparators removes the whitespace and separators operators
// commonly use when pasting EMV hex (spaces from a hex dump, colons
// from PC/SC traces, dashes from forum posts).
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
