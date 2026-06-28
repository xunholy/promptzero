// SPDX-License-Identifier: AGPL-3.0-or-later

package x509decode

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

// OCSPInfo is the decoded view of an OCSP response (RFC 6960) — the
// query-based revocation answer (good / revoked / unknown) for a single
// certificate, the per-certificate counterpart to a CRL's list.
type OCSPInfo struct {
	Status             string `json:"status"` // good | revoked | unknown | server_failed | unknown(N)
	SerialNumberHex    string `json:"serial_number_hex,omitempty"`
	ProducedAt         string `json:"produced_at,omitempty"`
	ThisUpdate         string `json:"this_update,omitempty"`
	NextUpdate         string `json:"next_update,omitempty"`
	Expired            bool   `json:"expired"` // NextUpdate is in the past
	RevokedAt          string `json:"revoked_at,omitempty"`
	RevocationReason   string `json:"revocation_reason,omitempty"` // only when revoked
	SignatureAlgorithm string `json:"signature_algorithm,omitempty"`

	// Responder identity: exactly one of a DN (byName) or a key hash (byKey),
	// or the embedded responder certificate's subject when present.
	ResponderName       string `json:"responder_name,omitempty"`
	ResponderKeyHashHex string `json:"responder_key_hash_hex,omitempty"`

	Note string `json:"note"`
}

// DecodeOCSP parses an OCSP response from base64 (the usual HTTP/captured
// form) or hex-encoded DER. The signature is NOT verified — that needs the
// issuer certificate an operator inspecting a captured response won't have —
// so the result carries an explicit not-verified note. Responses with an
// unsuccessful outer status (malformed / internalError / tryLater /
// unauthorized) surface as the parse error from x/crypto/ocsp.
func DecodeOCSP(input string) (*OCSPInfo, error) {
	der, err := decodeOCSPInput(input)
	if err != nil {
		return nil, err
	}
	// issuer = nil: parse the fields without signature verification.
	resp, err := ocsp.ParseResponse(der, nil)
	if err != nil {
		return nil, fmt.Errorf("x509decode: parse OCSP response: %w", err)
	}

	info := &OCSPInfo{
		Status:             ocspStatusName(resp.Status),
		SignatureAlgorithm: resp.SignatureAlgorithm.String(),
		Note:               "signature NOT verified (no issuer certificate supplied); fields shown as-is",
	}
	if resp.SerialNumber != nil {
		info.SerialNumberHex = strings.ToUpper(hex.EncodeToString(resp.SerialNumber.Bytes()))
	}
	if !resp.ProducedAt.IsZero() {
		info.ProducedAt = resp.ProducedAt.UTC().Format(time.RFC3339)
	}
	if !resp.ThisUpdate.IsZero() {
		info.ThisUpdate = resp.ThisUpdate.UTC().Format(time.RFC3339)
	}
	if !resp.NextUpdate.IsZero() {
		info.NextUpdate = resp.NextUpdate.UTC().Format(time.RFC3339)
		info.Expired = time.Now().After(resp.NextUpdate)
	}
	if resp.Status == ocsp.Revoked {
		if !resp.RevokedAt.IsZero() {
			info.RevokedAt = resp.RevokedAt.UTC().Format(time.RFC3339)
		}
		info.RevocationReason = ocspReasonName(resp.RevocationReason)
	}

	switch {
	case resp.Certificate != nil:
		info.ResponderName = resp.Certificate.Subject.String()
	case len(resp.RawResponderName) > 0:
		var rdn pkix.RDNSequence
		if _, e := asn1.Unmarshal(resp.RawResponderName, &rdn); e == nil {
			var n pkix.Name
			n.FillFromRDNSequence(&rdn)
			info.ResponderName = n.String()
		}
	case len(resp.ResponderKeyHash) > 0:
		info.ResponderKeyHashHex = strings.ToUpper(hex.EncodeToString(resp.ResponderKeyHash))
	}
	return info, nil
}

// ocspStatusName maps an OCSP certificate status to a stable lowercase name.
func ocspStatusName(s int) string {
	switch s {
	case ocsp.Good:
		return "good"
	case ocsp.Revoked:
		return "revoked"
	case ocsp.Unknown:
		return "unknown"
	case ocsp.ServerFailed:
		return "server_failed"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

// ocspReasonName maps an RFC 5280 revocation reason code to its name.
func ocspReasonName(r int) string {
	switch r {
	case ocsp.Unspecified:
		return "unspecified"
	case ocsp.KeyCompromise:
		return "keyCompromise"
	case ocsp.CACompromise:
		return "cACompromise"
	case ocsp.AffiliationChanged:
		return "affiliationChanged"
	case ocsp.Superseded:
		return "superseded"
	case ocsp.CessationOfOperation:
		return "cessationOfOperation"
	case ocsp.CertificateHold:
		return "certificateHold"
	case ocsp.RemoveFromCRL:
		return "removeFromCRL"
	case ocsp.PrivilegeWithdrawn:
		return "privilegeWithdrawn"
	case ocsp.AACompromise:
		return "aACompromise"
	default:
		return fmt.Sprintf("unknown(%d)", r)
	}
}

// decodeOCSPInput resolves base64 (std/url, padded or raw) or hex-encoded DER
// to raw bytes. OCSP responses are binary; they are most often pasted as
// base64 (the HTTP transfer form) or hex, never PEM.
func decodeOCSPInput(input string) ([]byte, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return nil, fmt.Errorf("x509decode: empty input")
	}
	if len(s)%2 == 0 && isHexString(s) {
		return hex.DecodeString(s)
	}
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || r == ' ' {
			return -1
		}
		return r
	}, s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(clean); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("x509decode: OCSP input is neither hex nor base64")
}

// isHexString reports whether s is non-empty and entirely hex digits.
func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}
