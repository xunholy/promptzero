// SPDX-License-Identifier: AGPL-3.0-or-later

package ndef

import (
	"fmt"
	"strings"
)

// EncodeRecord describes one NDEF record to build. Kind selects the
// well-known type: "uri" (NFC Forum URI record, type "U") or "text" (Text
// record, type "T"). For text, Lang defaults to "en".
type EncodeRecord struct {
	Kind string `json:"kind"`
	URI  string `json:"uri,omitempty"`
	Text string `json:"text,omitempty"`
	Lang string `json:"lang,omitempty"`
}

// Encode builds the raw bytes of an NDEF message from a list of records —
// the inverse of DecodeBytes. The first record gets MB (Message Begin), the
// last gets ME (Message End); each uses a short-record length when its
// payload is < 256 bytes. Supports the two highest-runner well-known types,
// URI and Text, both round-trip-verified against Decode.
//
// # Wrap-vs-native judgement
//
// Native, and the inverse of the existing parser. The NDEF record layout +
// the URI Identifier Code table are public (NFC Forum NDEF + RTD specs);
// encoding is pure byte assembly + a prefix-abbreviation lookup — no crypto,
// no hardware. It produces the bytes an operator writes to an NFC tag
// (e.g. a spoofed URI or text record); generation only, no tag write/TX, so
// it is Low risk like the parser. Correctness is verifiable two ways:
// round-trip against Decode and hand-computed record bytes.
//
// # Deliberately deferred
//
// Smart Poster, MIME, External, and chunked records — the URI + Text RTDs
// cover the overwhelming majority of tag-writing use; the rest can be added
// when there's a verified need. ID fields are omitted (IL=0).
func Encode(records []EncodeRecord) ([]byte, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("ndef: no records to encode")
	}
	var out []byte
	for i, r := range records {
		var typeStr string
		var payload []byte
		var err error
		switch strings.ToLower(strings.TrimSpace(r.Kind)) {
		case "uri":
			typeStr = "U"
			payload = encodeURIPayload(r.URI)
		case "text":
			typeStr = "T"
			payload, err = encodeTextPayload(r.Text, r.Lang)
		default:
			return nil, fmt.Errorf("ndef: record %d: unsupported kind %q (supported: uri, text)", i, r.Kind)
		}
		if err != nil {
			return nil, fmt.Errorf("ndef: record %d: %w", i, err)
		}
		out = append(out, encodeWellKnownRecord(typeStr, payload, i == 0, i == len(records)-1)...)
	}
	return out, nil
}

// encodeWellKnownRecord assembles a single TNF=WellKnown record: header byte
// (MB/ME/SR + TNF=1), 1-byte type length, payload length (1 byte short or 4
// bytes), the type, and the payload. IL=0 (no ID), CF=0 (not chunked).
func encodeWellKnownRecord(typeStr string, payload []byte, mb, me bool) []byte {
	hdr := byte(TNFWellKnown) // TNF in low 3 bits
	if mb {
		hdr |= 0x80
	}
	if me {
		hdr |= 0x40
	}
	short := len(payload) < 256
	if short {
		hdr |= 0x10 // SR
	}
	rec := []byte{hdr, byte(len(typeStr))}
	if short {
		rec = append(rec, byte(len(payload)))
	} else {
		n := uint32(len(payload))
		rec = append(rec, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	rec = append(rec, typeStr...)
	rec = append(rec, payload...)
	return rec
}

// encodeURIPayload builds a URI record payload: the longest-matching prefix
// abbreviation code followed by the remaining tail. Mirrors decodeURIRecord.
func encodeURIPayload(uri string) []byte {
	code := byte(0x00)
	tail := uri
	bestLen := 0
	for i, p := range uriPrefixes {
		if i == 0 || p == "" {
			continue
		}
		if len(p) > bestLen && strings.HasPrefix(uri, p) {
			bestLen = len(p)
			code = byte(i)
			tail = uri[len(p):]
		}
	}
	return append([]byte{code}, tail...)
}

// encodeTextPayload builds a Text record payload: a status byte (UTF-8, so
// bit7=0, low 6 bits = language-code length) + language code + UTF-8 text.
// Mirrors decodeTextRecord.
func encodeTextPayload(text, lang string) ([]byte, error) {
	if lang == "" {
		lang = "en"
	}
	if len(lang) > 0x3F {
		return nil, fmt.Errorf("language code %q is %d bytes; max 63", lang, len(lang))
	}
	out := make([]byte, 0, 1+len(lang)+len(text))
	out = append(out, byte(len(lang))) // bit7=0 → UTF-8
	out = append(out, lang...)
	out = append(out, text...)
	return out, nil
}
