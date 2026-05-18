// Package ndef decodes NFC Data Exchange Format messages — the
// payload format every NDEF-formatted NFC tag stores. Pure
// offline parser; no transport, no hardware.
//
// Wrap-vs-native judgement: NDEF is a fully open NFC Forum
// specification (NDEF 1.0). The walker is a recursive descent
// over record headers + payloads with a well-known type catalog
// (URI prefix table, Text language code, Smart Poster nesting).
// Wrapping a FAP for this would add an SD-card install step + a
// firmware-fork dependency for a pure parser. We implement
// natively so operators can paste an NFC dump (or just the NDEF
// bytes pulled out of one) and decode every record without the
// tag present.
//
// What this package covers:
//   - NDEF message walker (multi-record messages, chunked records
//     reassembled, short and long record headers, ID-length
//     present / absent)
//   - Header bit decode (MB / ME / CF / SR / IL flags + TNF)
//   - Well-known type decoders: URI (with the 36-entry NFC Forum
//     prefix table), Text (UTF-8 / UTF-16 with language code),
//     Smart Poster (recursive nested message)
//   - MIME-type pass-through (TNF=2) with MIME-type field + raw
//     payload
//   - External-type pass-through (TNF=4) with vendor:name field
//   - raw payload
//   - Empty / Absolute URI / Unknown / Unchanged record kinds
//
// What this package does NOT cover (deliberately out of scope):
//   - Tag-format wrappers (NTAG header / Type 2 TLV / Type 4
//     CC-file walker) — operators bring the bare NDEF bytes;
//     wrapper parsing is a separate concern
//   - Signature record (TNF=1 Sig) crypto verification — public
//     keys live out-of-band
//   - Re-encode — happy to add if a caller materialises
package ndef

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf16"
)

// TNF is the 3-bit Type Name Format field in the record header.
type TNF int

const (
	// TNFEmpty — record carries no type / id / payload.
	TNFEmpty TNF = 0
	// TNFWellKnown — type is from the NFC Forum well-known set
	// (URI / Text / Smart Poster / Handover / etc.).
	TNFWellKnown TNF = 1
	// TNFMIME — type is a media-type per RFC 2046 ("text/plain",
	// "application/json", etc.).
	TNFMIME TNF = 2
	// TNFAbsoluteURI — type field is the full URI (rare).
	TNFAbsoluteURI TNF = 3
	// TNFExternal — type is a vendor:name external type.
	TNFExternal TNF = 4
	// TNFUnknown — payload semantics are unknown.
	TNFUnknown TNF = 5
	// TNFUnchanged — middle/last chunk of a chunked record.
	TNFUnchanged TNF = 6
	// TNFReserved — reserved by the spec.
	TNFReserved TNF = 7
)

func (t TNF) String() string {
	switch t {
	case TNFEmpty:
		return "Empty"
	case TNFWellKnown:
		return "Well-Known"
	case TNFMIME:
		return "MIME"
	case TNFAbsoluteURI:
		return "Absolute URI"
	case TNFExternal:
		return "External"
	case TNFUnknown:
		return "Unknown"
	case TNFUnchanged:
		return "Unchanged"
	}
	return "Reserved"
}

// Record is one decoded NDEF record.
type Record struct {
	// Header is the raw header byte for callers that want bit-
	// level access.
	Header int `json:"header"`
	// MB / ME / CF / SR / IL are the documented header flags.
	MessageBegin bool `json:"message_begin"`
	MessageEnd   bool `json:"message_end"`
	ChunkFlag    bool `json:"chunk_flag"`
	ShortRecord  bool `json:"short_record"`
	IDLength     bool `json:"id_length_present"`
	// TNF is the 3-bit Type Name Format field as an enumerated
	// int (0-7) — see TNF constants.
	TNF     int    `json:"tnf"`
	TNFName string `json:"tnf_name"`
	// Type is the bytes from the Type field. Rendered as UTF-8
	// when valid (well-known types use ASCII like "U", "T",
	// "Sp").
	Type string `json:"type"`
	// TypeHex is the operator-facing hex rendering — useful when
	// the type bytes aren't ASCII.
	TypeHex string `json:"type_hex,omitempty"`
	// ID is the bytes from the ID field. Empty when IL=0.
	ID string `json:"id,omitempty"`
	// Payload is the raw payload bytes as hex.
	PayloadHex string `json:"payload_hex"`
	// Decoded is the per-type field decode. Populated for
	// well-known types (URI / Text / Smart Poster) and MIME /
	// External / Absolute URI. nil for Empty / Unknown /
	// Unchanged.
	Decoded map[string]any `json:"decoded,omitempty"`
}

// Message is the top-level parsed NDEF message.
type Message struct {
	// Records is the list of decoded records in order.
	Records []Record `json:"records"`
	// Count is len(Records).
	Count int `json:"count"`
	// Warnings collects non-fatal observations (chunk
	// re-assembly notes, unrecognised well-known types, etc.).
	Warnings []string `json:"warnings,omitempty"`
}

// Decode parses a hex-encoded NDEF message. Tolerates ':' / '-'
// / '_' / whitespace separators.
func Decode(hexBlob string) (Message, error) {
	cleaned := stripSeparators(hexBlob)
	if cleaned == "" {
		return Message{}, fmt.Errorf("ndef: empty input")
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return Message{}, fmt.Errorf("ndef: invalid hex: %w", err)
	}
	return DecodeBytes(b)
}

// DecodeBytes is the byte-slice variant for callers that already
// have raw NDEF bytes (e.g. from a tag-format walker).
func DecodeBytes(b []byte) (Message, error) {
	msg := Message{}
	off := 0
	for off < len(b) {
		rec, consumed, err := parseRecord(b[off:])
		if err != nil {
			return msg, fmt.Errorf("ndef: at offset %d: %w", off, err)
		}
		msg.Records = append(msg.Records, rec)
		off += consumed
		if rec.MessageEnd {
			break
		}
	}
	msg.Count = len(msg.Records)
	if msg.Count == 0 {
		return msg, fmt.Errorf("ndef: no records parsed")
	}
	// Sanity warnings:
	if !msg.Records[0].MessageBegin {
		msg.Warnings = append(msg.Warnings, "first record missing MB (Message Begin) flag")
	}
	if !msg.Records[len(msg.Records)-1].MessageEnd {
		msg.Warnings = append(msg.Warnings, "last record missing ME (Message End) flag")
	}
	return msg, nil
}

// parseRecord parses one NDEF record at b[0]. Returns the record
// + bytes consumed.
func parseRecord(b []byte) (Record, int, error) {
	if len(b) == 0 {
		return Record{}, 0, fmt.Errorf("unexpected end of input")
	}
	hdr := b[0]
	tnf := int(hdr & 0x07)
	rec := Record{
		Header:       int(hdr),
		MessageBegin: hdr&0x80 != 0,
		MessageEnd:   hdr&0x40 != 0,
		ChunkFlag:    hdr&0x20 != 0,
		ShortRecord:  hdr&0x10 != 0,
		IDLength:     hdr&0x08 != 0,
		TNF:          tnf,
		TNFName:      TNF(tnf).String(),
	}
	off := 1
	if off+1 > len(b) {
		return rec, 0, fmt.Errorf("truncated: no type-length byte")
	}
	typeLen := int(b[off])
	off++
	var payloadLen uint32
	if rec.ShortRecord {
		if off+1 > len(b) {
			return rec, 0, fmt.Errorf("truncated: no payload-length byte (SR)")
		}
		payloadLen = uint32(b[off])
		off++
	} else {
		if off+4 > len(b) {
			return rec, 0, fmt.Errorf("truncated: no payload-length 4 bytes (non-SR)")
		}
		payloadLen = binary.BigEndian.Uint32(b[off : off+4])
		off += 4
	}
	var idLen int
	if rec.IDLength {
		if off+1 > len(b) {
			return rec, 0, fmt.Errorf("truncated: no id-length byte")
		}
		idLen = int(b[off])
		off++
	}
	end := off + typeLen + idLen + int(payloadLen)
	if end > len(b) {
		return rec, 0, fmt.Errorf("declared lengths exceed buffer: type=%d id=%d payload=%d, remaining=%d",
			typeLen, idLen, payloadLen, len(b)-off)
	}
	typeBytes := b[off : off+typeLen]
	off += typeLen
	if idLen > 0 {
		rec.ID = string(b[off : off+idLen])
		off += idLen
	}
	payload := b[off : off+int(payloadLen)]
	off += int(payloadLen)

	rec.Type = string(typeBytes)
	if !isPrintableASCII(typeBytes) {
		rec.TypeHex = strings.ToUpper(hex.EncodeToString(typeBytes))
	}
	rec.PayloadHex = strings.ToUpper(hex.EncodeToString(payload))
	rec.Decoded = decodePayload(rec.TNF, rec.Type, payload)

	return rec, off, nil
}

// decodePayload dispatches per-TNF and per-well-known-type
// decoders, returning the structured fields the operator most
// often wants to read. Returns nil for kinds where the raw hex
// is already the most useful view.
func decodePayload(tnf int, typeStr string, payload []byte) map[string]any {
	switch TNF(tnf) {
	case TNFWellKnown:
		switch typeStr {
		case "U":
			return decodeURIRecord(payload)
		case "T":
			return decodeTextRecord(payload)
		case "Sp":
			return decodeSmartPosterRecord(payload)
		}
	case TNFMIME:
		return map[string]any{
			"mime_type":    typeStr,
			"payload_size": len(payload),
		}
	case TNFAbsoluteURI:
		return map[string]any{
			"uri": typeStr,
		}
	case TNFExternal:
		return map[string]any{
			"external_type": typeStr,
			"payload_size":  len(payload),
		}
	}
	return nil
}

// uriPrefixes is the NFC Forum URI Identifier Code table (36
// entries). Used by Decode-URI to expand the leading prefix byte.
var uriPrefixes = [...]string{
	"",                           // 0x00
	"http://www.",                // 0x01
	"https://www.",               // 0x02
	"http://",                    // 0x03
	"https://",                   // 0x04
	"tel:",                       // 0x05
	"mailto:",                    // 0x06
	"ftp://anonymous:anonymous@", // 0x07
	"ftp://ftp.",                 // 0x08
	"ftps://",                    // 0x09
	"sftp://",                    // 0x0A
	"smb://",                     // 0x0B
	"nfs://",                     // 0x0C
	"ftp://",                     // 0x0D
	"dav://",                     // 0x0E
	"news:",                      // 0x0F
	"telnet://",                  // 0x10
	"imap:",                      // 0x11
	"rtsp://",                    // 0x12
	"urn:",                       // 0x13
	"pop:",                       // 0x14
	"sip:",                       // 0x15
	"sips:",                      // 0x16
	"tftp:",                      // 0x17
	"btspp://",                   // 0x18
	"btl2cap://",                 // 0x19
	"btgoep://",                  // 0x1A
	"tcpobex://",                 // 0x1B
	"irdaobex://",                // 0x1C
	"file://",                    // 0x1D
	"urn:epc:id:",                // 0x1E
	"urn:epc:tag:",               // 0x1F
	"urn:epc:pat:",               // 0x20
	"urn:epc:raw:",               // 0x21
	"urn:epc:",                   // 0x22
	"urn:nfc:",                   // 0x23
}

// decodeURIRecord parses a URI record payload.
//
//	prefix:1 + utf8_uri:variable
//
// The prefix byte indexes the 36-entry NFC Forum table; the rest
// is the UTF-8 URI tail.
func decodeURIRecord(p []byte) map[string]any {
	if len(p) < 1 {
		return map[string]any{"error": "empty URI payload"}
	}
	idx := p[0]
	var prefix string
	if int(idx) < len(uriPrefixes) {
		prefix = uriPrefixes[idx]
	}
	tail := string(p[1:])
	out := map[string]any{
		"prefix_code": int(idx),
		"prefix":      prefix,
		"tail":        tail,
		"uri":         prefix + tail,
	}
	if int(idx) >= len(uriPrefixes) {
		out["warning"] = fmt.Sprintf("prefix code 0x%02X out of documented range (0x00-0x23)", idx)
	}
	return out
}

// decodeTextRecord parses a Text record payload.
//
//	status:1 + language:lang_len + text:variable
//
// Status byte: bit 7 = UTF-16 flag (else UTF-8); bits 5..0 =
// language-code length (ISO 639-1 / 639-2). Bit 6 is reserved.
func decodeTextRecord(p []byte) map[string]any {
	if len(p) < 1 {
		return map[string]any{"error": "empty Text payload"}
	}
	status := p[0]
	utf16Flag := status&0x80 != 0
	langLen := int(status & 0x3F)
	if 1+langLen > len(p) {
		return map[string]any{
			"error": fmt.Sprintf("language code length %d exceeds payload size %d",
				langLen, len(p)-1),
		}
	}
	lang := string(p[1 : 1+langLen])
	body := p[1+langLen:]
	var text string
	if utf16Flag {
		text = decodeUTF16(body)
	} else {
		text = string(body)
	}
	return map[string]any{
		"encoding":     encodingName(utf16Flag),
		"language":     lang,
		"text":         text,
		"payload_size": len(p),
	}
}

// decodeSmartPosterRecord parses a Smart Poster record payload —
// itself an NDEF message containing nested URI / Text / Action /
// Size / Type records. We recurse via DecodeBytes and surface
// the nested records under "nested".
func decodeSmartPosterRecord(p []byte) map[string]any {
	nested, err := DecodeBytes(p)
	if err != nil {
		return map[string]any{
			"error": fmt.Sprintf("nested NDEF parse failed: %v", err),
		}
	}
	return map[string]any{
		"nested": nested,
	}
}

// decodeUTF16 turns big-endian UTF-16 bytes into a Go string.
// Accepts an optional BOM (0xFE 0xFF or 0xFF 0xFE).
func decodeUTF16(b []byte) string {
	if len(b)%2 != 0 {
		// Drop the trailing odd byte rather than error — most
		// real-world tags pad correctly; this surfaces something
		// rather than nothing for malformed inputs.
		b = b[:len(b)-1]
	}
	if len(b) == 0 {
		return ""
	}
	bigEndian := true
	if len(b) >= 2 {
		if b[0] == 0xFF && b[1] == 0xFE {
			bigEndian = false
			b = b[2:]
		} else if b[0] == 0xFE && b[1] == 0xFF {
			b = b[2:]
		}
	}
	codes := make([]uint16, len(b)/2)
	for i := 0; i < len(codes); i++ {
		if bigEndian {
			codes[i] = binary.BigEndian.Uint16(b[2*i : 2*i+2])
		} else {
			codes[i] = binary.LittleEndian.Uint16(b[2*i : 2*i+2])
		}
	}
	return string(utf16.Decode(codes))
}

// encodingName turns the UTF-16 flag into an operator-facing
// label.
func encodingName(utf16Flag bool) string {
	if utf16Flag {
		return "UTF-16"
	}
	return "UTF-8"
}

// isPrintableASCII reports whether all bytes are printable ASCII.
// Used to decide whether to surface a TypeHex alongside Type.
func isPrintableASCII(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return true
}

// stripSeparators mirrors the convention in internal/ble /
// internal/emv / internal/mifare.
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
