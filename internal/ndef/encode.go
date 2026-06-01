// SPDX-License-Identifier: AGPL-3.0-or-later

package ndef

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// EncodeRecord describes one NDEF record to build. Kind selects the
// well-known type: "uri" (URI record, type "U"), "text" (Text record, type
// "T"), or "smartposter" (Smart Poster, type "Sp" — a record whose payload
// is a nested NDEF message of a URI + optional title Text + optional Action).
// For text/smartposter, Lang defaults to "en". For smartposter: URI is the
// target, Text is the optional title, Action is "" / "do" (launch) / "save" /
// "edit".
type EncodeRecord struct {
	Kind   string `json:"kind"`
	URI    string `json:"uri,omitempty"`
	Text   string `json:"text,omitempty"`
	Lang   string `json:"lang,omitempty"`
	Action string `json:"action,omitempty"`
	// Type is the record type for "mime" (a MIME media type, e.g.
	// "text/vcard") and "external" (a "domain:type" name, e.g.
	// "android.com:pkg" for an Android Application Record).
	Type string `json:"type,omitempty"`
	// Payload is the raw payload as hex for "mime"/"external". When empty,
	// Text (UTF-8) is used as the payload — the common case (vCard text, an
	// AAR package name).
	Payload string `json:"payload,omitempty"`
}

// Encode builds the raw bytes of an NDEF message from a list of records —
// the inverse of DecodeBytes. The first record gets MB (Message Begin), the
// last gets ME (Message End); each uses a short-record length when its
// payload is < 256 bytes. Supports the highest-runner record types — URI,
// Text, and Smart Poster (well-known); MIME media-type records; and External
// records (TNF 0x04, e.g. an Android Application Record "android.com:pkg")
// — all round-trip-verified against Decode.
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
// Chunked records and the Empty / Unknown / Absolute-URI / Unchanged TNFs —
// the supported set covers the overwhelming majority of tag-writing use; the
// rest can be added when there's a verified need. ID fields are omitted (IL=0).
func Encode(records []EncodeRecord) ([]byte, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("ndef: no records to encode")
	}
	var out []byte
	for i, r := range records {
		tnf := TNFWellKnown
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
		case "smartposter", "sp":
			typeStr = "Sp"
			payload, err = buildSmartPosterPayload(r)
		case "mime":
			if strings.TrimSpace(r.Type) == "" {
				return nil, fmt.Errorf("ndef: record %d: mime requires a type (e.g. text/vcard)", i)
			}
			tnf, typeStr = TNFMIME, r.Type
			payload, err = recordPayload(r)
		case "external", "aar":
			if !strings.Contains(r.Type, ":") {
				return nil, fmt.Errorf("ndef: record %d: external requires a domain:type (e.g. android.com:pkg)", i)
			}
			tnf, typeStr = TNFExternal, r.Type
			payload, err = recordPayload(r)
		default:
			return nil, fmt.Errorf("ndef: record %d: unsupported kind %q (supported: uri, text, smartposter, mime, external)", i, r.Kind)
		}
		if err != nil {
			return nil, fmt.Errorf("ndef: record %d: %w", i, err)
		}
		out = append(out, encodeRecord(tnf, typeStr, payload, i == 0, i == len(records)-1)...)
	}
	return out, nil
}

// recordPayload returns the payload bytes for a mime/external record: the
// hex-decoded Payload if set, otherwise the UTF-8 Text (the common case for
// vCard bodies and AAR package names).
func recordPayload(r EncodeRecord) ([]byte, error) {
	if s := strings.TrimSpace(r.Payload); s != "" {
		clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "").Replace(s)
		b, err := hex.DecodeString(clean)
		if err != nil {
			return nil, fmt.Errorf("payload is not valid hex: %w", err)
		}
		return b, nil
	}
	return []byte(r.Text), nil
}

// encodeWellKnownRecord assembles a single TNF=WellKnown record (used for the
// nested URI/Text/Action records inside a Smart Poster).
func encodeWellKnownRecord(typeStr string, payload []byte, mb, me bool) []byte {
	return encodeRecord(TNFWellKnown, typeStr, payload, mb, me)
}

// encodeRecord assembles one NDEF record: header byte (MB/ME/SR + TNF in the
// low 3 bits), 1-byte type length, payload length (1 byte short or 4 bytes),
// the type, and the payload. IL=0 (no ID), CF=0 (not chunked).
func encodeRecord(tnf TNF, typeStr string, payload []byte, mb, me bool) []byte {
	hdr := byte(tnf) // TNF in low 3 bits
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

// buildSmartPosterPayload builds the payload of a Smart Poster ("Sp")
// record: a nested NDEF message of a URI record (the target, required), an
// optional Text title, and an optional Action record. The decoder re-parses
// this payload as a sub-message (decodeSmartPosterRecord).
func buildSmartPosterPayload(r EncodeRecord) ([]byte, error) {
	if r.URI == "" {
		return nil, fmt.Errorf("smartposter requires a uri")
	}
	type irec struct {
		typ     string
		payload []byte
	}
	inner := []irec{{"U", encodeURIPayload(r.URI)}}
	if r.Text != "" {
		tp, err := encodeTextPayload(r.Text, r.Lang)
		if err != nil {
			return nil, err
		}
		inner = append(inner, irec{"T", tp})
	}
	if r.Action != "" {
		code, ok := actionCode(r.Action)
		if !ok {
			return nil, fmt.Errorf("invalid smartposter action %q (do/launch, save, edit)", r.Action)
		}
		inner = append(inner, irec{"act", []byte{code}})
	}
	var out []byte
	for i, ir := range inner {
		out = append(out, encodeWellKnownRecord(ir.typ, ir.payload, i == 0, i == len(inner)-1)...)
	}
	return out, nil
}

// actionCode maps a Smart Poster action name to its 1-byte RTD code
// (NFC Forum RTD-Action): 0 = do/launch, 1 = save for later, 2 = open
// for editing.
func actionCode(a string) (byte, bool) {
	switch strings.ToLower(strings.TrimSpace(a)) {
	case "do", "launch", "exec", "0":
		return 0, true
	case "save", "1":
		return 1, true
	case "edit", "open", "2":
		return 2, true
	default:
		return 0, false
	}
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
