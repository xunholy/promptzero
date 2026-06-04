// SPDX-License-Identifier: AGPL-3.0-or-later

// Package saml decodes a SAML 2.0 message (a SAMLRequest / SAMLResponse value
// captured from an SSO flow) into its XML and the high-signal fields a pentester
// triages: the message type, Issuer, Destination, NameID, the assertion
// Conditions / AudienceRestriction, and — crucially — whether the message is
// signed (the golden-SAML / unsigned-assertion attack surface). It is the SSO
// counterpart of jwt_decode / paseto_decode for the web-auth decode stack: an
// operator pastes a SAMLRequest from a redirect URL or a SAMLResponse from a
// POST body and gets the readable XML + key fields without a SAML library or a
// manual base64-then-inflate dance. Pure offline transform; no network or
// device.
//
// # Bindings
//
//   - HTTP-Redirect: the value is base64(raw-DEFLATE(xml)) (RFC-1951 DEFLATE,
//     no zlib/gzip wrapper) — used for the GET-redirect SAMLRequest.
//   - HTTP-POST: the value is base64(xml) — used for the POSTed SAMLResponse.
//
// Decode auto-detects: it base64-decodes, then tries raw-DEFLATE; if that
// inflates to XML the binding is HTTP-Redirect, otherwise the base64 bytes are
// treated as the raw XML (HTTP-POST). Percent-encoding (when pasted straight
// from a URL) and base64url are tolerated.
//
// # Wrap-vs-native judgement
//
// Native. The transform is encoding/base64 + compress/flate + an encoding/xml
// token scan — all standard library. There is nothing to wrap; a SAML toolkit
// (crewjam/saml, russellhaering/gosaml2) is a heavy dependency aimed at being
// an SP/IdP, not at decoding an untrusted blob. Consistent with internal/jwtsig
// and internal/paseto owning their token parsing in-tree.
//
// # Verifiable / no confidently-wrong output
//
// The base64 + DEFLATE decode is anchored to an independently-produced
// HTTP-Redirect vector (Python zlib raw-DEFLATE — the same standard DEFLATE real
// IdPs/SPs emit) that must inflate to its exact source XML, plus a HTTP-POST
// (plain base64) vector. The field extraction is a namespace-agnostic
// local-name token scan over the decoded XML, and the **raw XML is always
// surfaced as the source of truth** — a field that is absent is simply empty,
// never guessed. A value that is neither inflatable nor raw XML is rejected.
//
// # Covered / deferred
//
// Covered: binding detection, XML decode, and extraction of the message type +
// Issuer / Destination / ID / IssueInstant / InResponseTo / NameID / StatusCode
// / Conditions / Audience(s) + a signature-element count. Deferred: XML-DSig
// signature *verification* (canonicalization + certificate trust is a large,
// separate problem) — this reports whether a Signature element is present, the
// attack-surface signal, not whether it validates.
package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// Result is the decoded view of a SAML message.
type Result struct {
	Binding     string `json:"binding"`
	MessageType string `json:"message_type"` // root element local name
	XML         string `json:"xml"`

	ID           string `json:"id,omitempty"`
	Version      string `json:"version,omitempty"`
	IssueInstant string `json:"issue_instant,omitempty"`
	Destination  string `json:"destination,omitempty"`
	InResponseTo string `json:"in_response_to,omitempty"`
	Issuer       string `json:"issuer,omitempty"`
	NameID       string `json:"name_id,omitempty"`

	StatusCode             string   `json:"status_code,omitempty"`
	ConditionsNotBefore    string   `json:"conditions_not_before,omitempty"`
	ConditionsNotOnOrAfter string   `json:"conditions_not_on_or_after,omitempty"`
	Audiences              []string `json:"audiences,omitempty"`

	SignatureCount   int    `json:"signature_count"`
	SignaturePresent bool   `json:"signature_present"`
	Note             string `json:"note,omitempty"`
}

const maxXMLBytes = 8 << 20 // cap inflate / input so a hostile blob can't OOM

// Decode parses a SAML message value (a SAMLRequest / SAMLResponse from a
// redirect URL or POST body).
func Decode(in string) (*Result, error) {
	s := strings.TrimSpace(in)
	if s == "" {
		return nil, fmt.Errorf("saml: empty input")
	}
	if strings.Contains(s, "%") { // pasted straight from a URL
		if dec, err := url.QueryUnescape(s); err == nil {
			s = dec
		}
	}
	raw, err := b64decode(s)
	if err != nil {
		return nil, fmt.Errorf("saml: not valid base64: %w", err)
	}

	binding, xmlBytes, err := inflateOrRaw(raw)
	if err != nil {
		return nil, err
	}
	r := &Result{Binding: binding, XML: string(xmlBytes)}
	if err := scan(xmlBytes, r); err != nil {
		return nil, fmt.Errorf("saml: XML parse: %w", err)
	}
	r.SignaturePresent = r.SignatureCount > 0
	return r, nil
}

// b64decode tolerates standard / URL-safe base64, with or without padding.
func b64decode(s string) ([]byte, error) {
	s = strings.Join(strings.Fields(s), "") // drop any internal whitespace
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("undecodable")
}

// inflateOrRaw returns the binding and XML bytes: raw-DEFLATE if the bytes
// inflate to XML (HTTP-Redirect), else the bytes themselves if they are XML
// (HTTP-POST).
func inflateOrRaw(raw []byte) (string, []byte, error) {
	fr := flate.NewReader(bytes.NewReader(raw))
	if inflated, err := io.ReadAll(io.LimitReader(fr, maxXMLBytes)); err == nil && looksLikeXML(inflated) {
		return "HTTP-Redirect (DEFLATE)", inflated, nil
	}
	if looksLikeXML(raw) {
		return "HTTP-POST (raw)", raw, nil
	}
	return "", nil, fmt.Errorf("saml: decoded bytes are neither DEFLATE-compressed XML nor raw XML")
}

func looksLikeXML(b []byte) bool {
	t := bytes.TrimSpace(b)
	return len(t) > 0 && t[0] == '<'
}

// scan walks the decoded XML namespace-agnostically (matching element local
// names) to extract the high-signal SAML fields. The raw XML in Result.XML
// remains the source of truth; absent fields stay empty.
func scan(xmlBytes []byte, r *Result) error {
	dec := xml.NewDecoder(bytes.NewReader(xmlBytes))
	dec.Strict = false
	var rootSeen, captureIssuer, captureNameID, captureAudience bool
	var buf strings.Builder
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			local := t.Name.Local
			if !rootSeen {
				rootSeen = true
				r.MessageType = local
				r.ID = attr(t, "ID")
				r.Version = attr(t, "Version")
				r.IssueInstant = attr(t, "IssueInstant")
				r.Destination = attr(t, "Destination")
				r.InResponseTo = attr(t, "InResponseTo")
			}
			switch local {
			case "Issuer":
				captureIssuer, buf = true, strings.Builder{}
			case "NameID":
				captureNameID, buf = true, strings.Builder{}
			case "Audience":
				captureAudience, buf = true, strings.Builder{}
			case "Signature":
				if strings.Contains(t.Name.Space, "xmldsig") || t.Name.Space == "http://www.w3.org/2000/09/xmldsig#" {
					r.SignatureCount++
				}
			case "StatusCode":
				if v := attr(t, "Value"); v != "" && r.StatusCode == "" {
					r.StatusCode = v
				}
			case "Conditions":
				r.ConditionsNotBefore = attr(t, "NotBefore")
				r.ConditionsNotOnOrAfter = attr(t, "NotOnOrAfter")
			}
		case xml.CharData:
			if captureIssuer || captureNameID || captureAudience {
				buf.Write(t)
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "Issuer":
				if captureIssuer && r.Issuer == "" {
					r.Issuer = strings.TrimSpace(buf.String())
				}
				captureIssuer = false
			case "NameID":
				if captureNameID && r.NameID == "" {
					r.NameID = strings.TrimSpace(buf.String())
				}
				captureNameID = false
			case "Audience":
				if captureAudience {
					if a := strings.TrimSpace(buf.String()); a != "" {
						r.Audiences = append(r.Audiences, a)
					}
				}
				captureAudience = false
			}
		}
	}
	return nil
}

func attr(e xml.StartElement, local string) string {
	for _, a := range e.Attr {
		if a.Name.Local == local {
			return a.Value
		}
	}
	return ""
}
