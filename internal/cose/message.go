// SPDX-License-Identifier: AGPL-3.0-or-later

package cose

import (
	"fmt"

	"github.com/xunholy/promptzero/internal/cbordecode"
)

// COSE message CBOR tags (IANA "CBOR Tags" / RFC 9052 §2).
const (
	tagCOSESign    = 98 // COSE_Sign (multi-signer)
	tagCOSESign1   = 18 // COSE_Sign1 (single signer)
	tagCOSEEncrypt = 96 // COSE_Encrypt (multi-recipient)
	tagCOSEEnc0    = 16 // COSE_Encrypt0 (single recipient)
	tagCOSEMac     = 97 // COSE_Mac (multi-recipient, tagged)
	tagCOSEMac0    = 17 // COSE_Mac0 (single recipient)
)

// Header is the decoded subset of COSE header parameters (IANA "COSE
// Header Parameters", RFC 9052 §3.1) most useful for triage. Less common
// parameters are collected, by integer label, into Other.
type Header struct {
	Algorithm    string            `json:"algorithm,omitempty"` // label 1
	AlgID        *int64            `json:"algorithm_id,omitempty"`
	Critical     []int64           `json:"critical,omitempty"`       // label 2 (crit)
	ContentType  string            `json:"content_type,omitempty"`   // label 3
	KeyIDHex     string            `json:"key_id_hex,omitempty"`     // label 4 (kid)
	IVHex        string            `json:"iv_hex,omitempty"`         // label 5
	PartialIVHex string            `json:"partial_iv_hex,omitempty"` // label 6
	Other        map[string]string `json:"other,omitempty"`
}

// Message is a decoded COSE message (RFC 9052). Only the fields relevant to
// the message type are populated. Signature / tag / ciphertext bytes are
// surfaced as hex; the signature and recipient counts are reported for the
// multi-recipient structures rather than fully recursing.
type Message struct {
	Type            string  `json:"type"` // COSE_Sign1 / COSE_Sign / COSE_Mac0 / COSE_Mac / COSE_Encrypt0 / COSE_Encrypt / …
	Tag             *uint64 `json:"tag,omitempty"`
	Tagged          bool    `json:"tagged"`
	Protected       Header  `json:"protected_header"`
	Unprotected     Header  `json:"unprotected_header"`
	PayloadHex      string  `json:"payload_hex,omitempty"`
	PayloadDetached bool    `json:"payload_detached"`

	// Single-recipient final elements.
	SignatureHex  string `json:"signature_hex,omitempty"`  // COSE_Sign1
	TagHex        string `json:"tag_hex,omitempty"`        // COSE_Mac0 authentication tag
	CiphertextHex string `json:"ciphertext_hex,omitempty"` // COSE_Encrypt0

	// Multi-recipient structures.
	SignatureCount *int `json:"signature_count,omitempty"` // COSE_Sign
	RecipientCount *int `json:"recipient_count,omitempty"` // COSE_Mac / COSE_Encrypt

	Note string `json:"note"`
}

// DecodeMessage parses raw CBOR bytes as a COSE message and surfaces its
// structure: message type, decoded protected & unprotected headers,
// payload, and the type-specific final element(s). It does NOT verify any
// signature or MAC and cannot decrypt — those need keys an operator
// inspecting a captured artifact won't have — so the result carries an
// explicit not-verified note.
func DecodeMessage(raw []byte) (*Message, error) {
	v, err := cbordecode.DecodeBytes(raw)
	if err != nil {
		return nil, fmt.Errorf("cose: %w", err)
	}

	out := &Message{Note: "structure only — signature/MAC NOT verified and ciphertext NOT decrypted (keys required)"}

	// Resolve an optional COSE message tag to its array body.
	if v.MajorType == 6 && v.Tag != nil {
		out.Tag = v.Tag
		out.Tagged = true
		if v.TagValue == nil {
			return nil, fmt.Errorf("cose: empty COSE tag %d", *v.Tag)
		}
		v = v.TagValue
	}

	if v.MajorType != 4 {
		return nil, fmt.Errorf("cose: not a COSE message (expected a CBOR array, got %s)", v.MajorName)
	}
	arr := v.Array
	n := len(arr)

	// Classify the message. A tag is authoritative; otherwise fall back to
	// the array shape, which cannot tell Sign1 from Mac0 (both 4 elements).
	kind, err := classify(out.Tag, n)
	if err != nil {
		return nil, err
	}
	out.Type = kind

	// A tag is authoritative for the type but says nothing about element
	// count: a malformed (or adversarial) message can carry the right tag
	// on a too-short array. Validate the minimum before indexing so a
	// crafted frame errors instead of panicking.
	if need := requiredElements(kind); n < need {
		return nil, fmt.Errorf("cose: %s needs at least %d elements, got %d", kind, need, n)
	}

	// Elements 0 and 1 are always the protected (bstr-wrapped CBOR map) and
	// unprotected (CBOR map) headers.
	out.Protected = decodeProtectedHeader(arr[0])
	out.Unprotected = decodeHeaderMap(arr[1])

	switch kind {
	case "COSE_Sign1":
		setPayload(out, arr[2])
		out.SignatureHex = bytesOf(arr[3])
	case "COSE_Mac0":
		setPayload(out, arr[2])
		out.TagHex = bytesOf(arr[3])
	case "COSE_Sign1/Mac0 (untagged)":
		setPayload(out, arr[2])
		out.SignatureHex = bytesOf(arr[3]) // final element: signature or MAC tag
	case "COSE_Encrypt0":
		out.CiphertextHex = bytesOf(arr[2])
	case "COSE_Sign":
		setPayload(out, arr[2])
		if arr[3].MajorType == 4 {
			c := len(arr[3].Array)
			out.SignatureCount = &c
		}
	case "COSE_Mac":
		setPayload(out, arr[2])
		out.TagHex = bytesOf(arr[3])
		if n >= 5 && arr[4].MajorType == 4 {
			c := len(arr[4].Array)
			out.RecipientCount = &c
		}
	case "COSE_Encrypt":
		out.CiphertextHex = bytesOf(arr[2])
		if n >= 4 && arr[3].MajorType == 4 {
			c := len(arr[3].Array)
			out.RecipientCount = &c
		}
	}
	return out, nil
}

// classify maps a COSE tag (authoritative) or an untagged array length to a
// message type.
func classify(tag *uint64, n int) (string, error) {
	if tag != nil {
		switch *tag {
		case tagCOSESign1:
			return "COSE_Sign1", nil
		case tagCOSESign:
			return "COSE_Sign", nil
		case tagCOSEMac0:
			return "COSE_Mac0", nil
		case tagCOSEMac:
			return "COSE_Mac", nil
		case tagCOSEEnc0:
			return "COSE_Encrypt0", nil
		case tagCOSEEncrypt:
			return "COSE_Encrypt", nil
		default:
			return "", fmt.Errorf("cose: CBOR tag %d is not a COSE message tag", *tag)
		}
	}
	// Untagged: classify by array length. Sign1 and Mac0 share 4 elements.
	switch n {
	case 3:
		return "COSE_Encrypt0", nil
	case 4:
		return "COSE_Sign1/Mac0 (untagged)", nil
	default:
		return "", fmt.Errorf("cose: untagged %d-element array is not a recognised single-recipient COSE message", n)
	}
}

// requiredElements is the minimum CBOR array length for each COSE message
// type (RFC 9052 §2): the recipients/signatures array is mandatory in the
// multi-recipient structures, so they require one more element than their
// single-recipient counterparts.
func requiredElements(kind string) int {
	switch kind {
	case "COSE_Encrypt0":
		return 3
	case "COSE_Mac":
		return 5
	default: // Sign1, Mac0, Sign1/Mac0 (untagged), Sign, Encrypt
		return 4
	}
}

// decodeProtectedHeader decodes element 0 — a byte string wrapping a CBOR
// header map (empty byte string means an empty header).
func decodeProtectedHeader(v *cbordecode.Value) Header {
	if v == nil || v.MajorType != 2 || v.Bytes == "" {
		return Header{}
	}
	inner, err := cbordecode.Decode(v.Bytes) // v.Bytes is hex
	if err != nil || inner.MajorType != 5 {
		return Header{}
	}
	return decodeHeaderMap(inner)
}

// decodeHeaderMap interprets a CBOR header map into a Header.
func decodeHeaderMap(m *cbordecode.Value) Header {
	h := Header{}
	if m == nil || m.MajorType != 5 {
		return h
	}
	for _, e := range m.Map {
		lbl, ok := e.Key.AsInt()
		if !ok {
			continue
		}
		switch lbl {
		case 1: // alg
			if alg, ok := e.Value.AsInt(); ok {
				a := alg
				h.AlgID = &a
				h.Algorithm = AlgorithmName(alg)
			}
		case 2: // crit
			if e.Value != nil && e.Value.MajorType == 4 {
				for _, item := range e.Value.Array {
					if c, ok := item.AsInt(); ok {
						h.Critical = append(h.Critical, c)
					}
				}
			}
		case 3: // content type (int CoAP content-format or text MIME)
			if e.Value != nil {
				if e.Value.Text != "" {
					h.ContentType = e.Value.Text
				} else if ct, ok := e.Value.AsInt(); ok {
					h.ContentType = fmt.Sprintf("ContentFormat(%d)", ct)
				}
			}
		case 4: // kid
			h.KeyIDHex = bytesOf(e.Value)
		case 5: // IV
			h.IVHex = bytesOf(e.Value)
		case 6: // Partial IV
			h.PartialIVHex = bytesOf(e.Value)
		default:
			if h.Other == nil {
				h.Other = map[string]string{}
			}
			h.Other[fmt.Sprintf("%d", lbl)] = describeHeaderValue(e.Value)
		}
	}
	return h
}

// setPayload records the payload bytes, or marks it detached when the
// payload slot is CBOR null / absent.
func setPayload(out *Message, v *cbordecode.Value) {
	if v == nil || v.MajorType != 2 || v.Bytes == "" {
		out.PayloadDetached = true
		return
	}
	out.PayloadHex = v.Bytes
}

// bytesOf returns the hex of a CBOR byte string, or "".
func bytesOf(v *cbordecode.Value) string {
	if v == nil || v.MajorType != 2 {
		return ""
	}
	return v.Bytes
}

// describeHeaderValue renders a short description of an arbitrary header value.
func describeHeaderValue(v *cbordecode.Value) string {
	if v == nil {
		return ""
	}
	switch {
	case v.Text != "":
		return v.Text
	case v.Uint != nil:
		return fmt.Sprintf("%d", *v.Uint)
	case v.Int != nil:
		return fmt.Sprintf("%d", *v.Int)
	case v.Bytes != "":
		return "0x" + v.Bytes
	default:
		return v.MajorName
	}
}
