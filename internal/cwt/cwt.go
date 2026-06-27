// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cwt decodes a CWT (CBOR Web Token, RFC 8392) — the CBOR-native
// counterpart of a JWT, used for OAuth / proof-of-possession on
// constrained / IoT devices. It is the missing member of PromptZero's
// token-decoder set (jwt, paseto, macaroon).
//
// A CWT is a CBOR claims map, usually wrapped in a single-recipient COSE
// message (COSE_Sign1 / COSE_Mac0, or COSE_Encrypt0 when the claims are
// encrypted), and optionally carried under the CWT CBOR tag (61). This
// decoder unwraps that envelope, reports the signing algorithm from the
// COSE protected header, and surfaces the standard claims (iss / sub / aud
// / exp / nbf / iat / cti, IANA "CWT Claims") with the timestamps rendered
// both as epoch seconds and RFC 3339.
//
// It does NOT verify the signature or MAC — that needs the issuer's key,
// which an operator inspecting a captured token won't have — so the result
// carries an explicit "not verified" note. Encrypted (COSE_Encrypt0)
// payloads can't be decoded without the key and are reported as such.
package cwt

import (
	"fmt"
	"time"

	"github.com/xunholy/promptzero/internal/cbordecode"
	"github.com/xunholy/promptzero/internal/cose"
)

// COSE message CBOR tags (IANA "CBOR Tags").
const (
	tagCWT       = 61
	tagCOSESign1 = 18
	tagCOSEMac0  = 17
	tagCOSEEnc0  = 16
	tagCOSESign  = 98
	tagCOSEMac   = 97
	tagCOSEEnc   = 96
)

// Claims is the decoded CWT claims set (RFC 8392 §3.1.1).
type Claims struct {
	Issuer    string `json:"iss,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Audience  string `json:"aud,omitempty"`
	ExpiresAt *Time  `json:"exp,omitempty"`
	NotBefore *Time  `json:"nbf,omitempty"`
	IssuedAt  *Time  `json:"iat,omitempty"`
	CWTIDHex  string `json:"cti_hex,omitempty"`
	// Additional holds any claim outside the standard seven, keyed by its
	// integer or text label, with a short value description.
	Additional map[string]string `json:"additional,omitempty"`
}

// Time is a CWT NumericDate rendered both ways.
type Time struct {
	Epoch   int64  `json:"epoch"`
	RFC3339 string `json:"rfc3339"`
}

// CWT is the decoded token.
type CWT struct {
	CWTTagged        bool    `json:"cwt_tagged"` // wrapped in the CWT tag (61)
	COSEType         string  `json:"cose_type"`  // COSE_Sign1 / COSE_Mac0 / COSE_Encrypt0 / unsecured / …
	Algorithm        string  `json:"algorithm,omitempty"`
	AlgorithmID      *int64  `json:"algorithm_id,omitempty"`
	PayloadEncrypted bool    `json:"payload_encrypted"` // COSE_Encrypt0 — claims not decodable
	Claims           *Claims `json:"claims,omitempty"`
	Note             string  `json:"note"`
}

// Decode parses raw CWT bytes.
func Decode(raw []byte) (*CWT, error) {
	v, err := cbordecode.DecodeBytes(raw)
	if err != nil {
		return nil, fmt.Errorf("cwt: %w", err)
	}

	out := &CWT{Note: "signature/MAC NOT verified — issuer key required; claims shown as-is"}

	// Optional outer CWT tag (61).
	if v.MajorType == 6 && v.Tag != nil && *v.Tag == tagCWT {
		out.CWTTagged = true
		if v.TagValue == nil {
			return nil, fmt.Errorf("cwt: empty CWT tag")
		}
		v = v.TagValue
	}

	// Resolve a COSE message tag, if present, to its array body.
	var coseTag *uint64
	if v.MajorType == 6 && v.Tag != nil {
		coseTag = v.Tag
		if v.TagValue == nil {
			return nil, fmt.Errorf("cwt: empty COSE tag %d", *v.Tag)
		}
		v = v.TagValue
	}

	switch v.MajorType {
	case 5: // bare claims map — an unsecured CWT
		out.COSEType = "unsecured"
		claims, err := decodeClaims(v)
		if err != nil {
			return nil, err
		}
		out.Claims = claims
		return out, nil

	case 4: // a COSE message array
		return decodeCOSEArray(v, coseTag, out)

	default:
		return nil, fmt.Errorf("cwt: unexpected top-level CBOR %s (want a COSE message array or claims map)", v.MajorName)
	}
}

// decodeCOSEArray handles the COSE single-recipient message array shapes.
func decodeCOSEArray(arr *cbordecode.Value, coseTag *uint64, out *CWT) (*CWT, error) {
	n := len(arr.Array)

	switch {
	case coseTag != nil && *coseTag == tagCOSEEnc0, coseTag != nil && *coseTag == tagCOSEEnc, n == 3:
		// Encrypt0 (3-element): [protected, unprotected, ciphertext].
		out.COSEType = "COSE_Encrypt0"
		out.PayloadEncrypted = true
		out.Note = "payload is encrypted (COSE_Encrypt0) — claims require the decryption key; " + out.Note
		readAlg(arr, out)
		return out, nil
	case coseTag != nil && *coseTag == tagCOSESign1:
		out.COSEType = "COSE_Sign1"
	case coseTag != nil && *coseTag == tagCOSEMac0:
		out.COSEType = "COSE_Mac0"
	case coseTag != nil && *coseTag == tagCOSESign:
		out.COSEType = "COSE_Sign"
	case coseTag != nil && *coseTag == tagCOSEMac:
		out.COSEType = "COSE_Mac"
	case n == 4:
		// Untagged 4-element array: COSE_Sign1 and COSE_Mac0 share this
		// shape and are indistinguishable without the tag.
		out.COSEType = "COSE_Sign1/Mac0 (untagged)"
	default:
		return nil, fmt.Errorf("cwt: unrecognised COSE message array of %d elements", n)
	}

	if n < 3 {
		return nil, fmt.Errorf("cwt: COSE message array too short (%d elements)", n)
	}
	readAlg(arr, out)

	// The payload (element 2) is a byte string whose content is the CWT
	// claims set (a CBOR map). A nil/empty payload is a detached payload.
	payload := arr.Array[2]
	if payload.MajorType != 2 || payload.Bytes == "" {
		out.Note = "no embedded claims payload (detached or empty); " + out.Note
		return out, nil
	}
	inner, err := cbordecode.Decode(payload.Bytes) // payload.Bytes is hex
	if err != nil {
		return nil, fmt.Errorf("cwt: decoding claims payload: %w", err)
	}
	if inner.MajorType != 5 {
		return nil, fmt.Errorf("cwt: claims payload is %s, want a CBOR map", inner.MajorName)
	}
	claims, err := decodeClaims(inner)
	if err != nil {
		return nil, err
	}
	out.Claims = claims
	return out, nil
}

// readAlg pulls the signing algorithm from the COSE protected header
// (element 0: a byte string wrapping a CBOR header map; label 1 = alg).
func readAlg(arr *cbordecode.Value, out *CWT) {
	if len(arr.Array) == 0 {
		return
	}
	prot := arr.Array[0]
	if prot.MajorType != 2 || prot.Bytes == "" {
		return // empty protected header
	}
	hdr, err := cbordecode.Decode(prot.Bytes)
	if err != nil || hdr.MajorType != 5 {
		return
	}
	for _, e := range hdr.Map {
		if lbl, ok := e.Key.AsInt(); ok && lbl == 1 {
			if alg, ok := e.Value.AsInt(); ok {
				a := alg
				out.AlgorithmID = &a
				out.Algorithm = cose.AlgorithmName(alg)
			}
			return
		}
	}
}

// decodeClaims interprets a CWT claims map.
func decodeClaims(m *cbordecode.Value) (*Claims, error) {
	c := &Claims{}
	for _, e := range m.Map {
		lbl, isInt := e.Key.AsInt()
		if !isInt {
			// Text-keyed custom claim.
			if e.Key != nil && e.Key.MajorType == 3 {
				addAdditional(c, e.Key.Text, e.Value)
			}
			continue
		}
		switch lbl {
		case 1:
			c.Issuer = e.Value.Text
		case 2:
			c.Subject = e.Value.Text
		case 3:
			c.Audience = e.Value.Text
		case 4:
			c.ExpiresAt = asTime(e.Value)
		case 5:
			c.NotBefore = asTime(e.Value)
		case 6:
			c.IssuedAt = asTime(e.Value)
		case 7:
			c.CWTIDHex = e.Value.Bytes
		default:
			addAdditional(c, fmt.Sprintf("%d", lbl), e.Value)
		}
	}
	return c, nil
}

func addAdditional(c *Claims, key string, v *cbordecode.Value) {
	if c.Additional == nil {
		c.Additional = map[string]string{}
	}
	c.Additional[key] = describeValue(v)
}

// describeValue renders a short, safe description of an arbitrary claim value.
func describeValue(v *cbordecode.Value) string {
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

// asTime reads a CWT NumericDate (epoch seconds; integer or float).
func asTime(v *cbordecode.Value) *Time {
	if v == nil {
		return nil
	}
	var secs int64
	switch {
	case v.Uint != nil:
		secs = int64(*v.Uint)
	case v.Int != nil:
		secs = *v.Int
	case v.Float != nil:
		secs = int64(*v.Float)
	default:
		return nil
	}
	return &Time{Epoch: secs, RFC3339: time.Unix(secs, 0).UTC().Format(time.RFC3339)}
}
