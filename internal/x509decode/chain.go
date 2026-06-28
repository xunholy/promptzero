// SPDX-License-Identifier: AGPL-3.0-or-later

package x509decode

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// ChainCert is the per-certificate summary in a verified chain.
type ChainCert struct {
	Position   int    `json:"position"` // 0 = leaf
	SubjectDN  string `json:"subject_dn"`
	IssuerDN   string `json:"issuer_dn"`
	SelfIssued bool   `json:"self_issued"` // subject == issuer
	IsCA       bool   `json:"is_ca"`
	NotAfter   string `json:"not_after"`
	Expired    bool   `json:"expired"`
}

// ChainLink reports whether certificate i is validly signed by certificate
// i+1 (the candidate parent immediately above it in the supplied order).
type ChainLink struct {
	ChildPosition  int    `json:"child_position"`
	ParentPosition int    `json:"parent_position"`
	ChildSubject   string `json:"child_subject"`
	ParentSubject  string `json:"parent_subject"`
	Valid          bool   `json:"valid"`
	Error          string `json:"error,omitempty"`
}

// ChainResult is the decoded + linkage-verified view of a certificate chain.
type ChainResult struct {
	Source string      `json:"source"` // PEM | DER
	Count  int         `json:"count"`
	Certs  []ChainCert `json:"certs"`
	Links  []ChainLink `json:"links,omitempty"`

	// Ordered is true when every adjacent link verifies, i.e. the certs are
	// in leaf -> ... -> root order and each is signed by the next.
	Ordered bool `json:"ordered"`
	// ReachesSelfSignedRoot is true when the last certificate is self-issued
	// and its own signature verifies (a trust-anchor root is present at the
	// end of the chain).
	ReachesSelfSignedRoot bool `json:"reaches_self_signed_root"`
	// AnyExpired flags whether any certificate in the chain is past its
	// NotAfter — a common cause of "chain looks right but is rejected".
	AnyExpired bool `json:"any_expired"`

	Note string `json:"note"`
}

// VerifyChain parses every certificate in a PEM bundle (or a single hex-DER
// certificate) and checks the signature linkage between adjacent certificates
// in the order supplied: each certificate must be signed by the next one up.
// It reports ordering, whether a self-signed root terminates the chain, and
// per-certificate expiry — the information an operator needs to diagnose the
// usual "the chain is present but not trusted" failures (wrong order, missing
// intermediate, expired link).
//
// Linkage uses crypto/x509's CheckSignatureFrom, which verifies the
// cryptographic signature AND that the parent is a CA permitted to sign
// certificates. It does NOT perform full RFC 5280 path validation (name
// constraints, policies, or trust against a root store) — expiry is reported
// per certificate but is not folded into link validity.
func VerifyChain(input string) (*ChainResult, error) {
	certs, source, err := parseChainCerts(input)
	if err != nil {
		return nil, err
	}
	now := time.Now()

	res := &ChainResult{Source: source, Count: len(certs), Ordered: true}
	for i, c := range certs {
		expired := now.After(c.NotAfter)
		if expired {
			res.AnyExpired = true
		}
		res.Certs = append(res.Certs, ChainCert{
			Position:   i,
			SubjectDN:  c.Subject.String(),
			IssuerDN:   c.Issuer.String(),
			SelfIssued: c.Subject.String() == c.Issuer.String(),
			IsCA:       c.IsCA,
			NotAfter:   c.NotAfter.UTC().Format(time.RFC3339),
			Expired:    expired,
		})
	}

	for i := 0; i+1 < len(certs); i++ {
		child, parent := certs[i], certs[i+1]
		link := ChainLink{
			ChildPosition:  i,
			ParentPosition: i + 1,
			ChildSubject:   child.Subject.String(),
			ParentSubject:  parent.Subject.String(),
		}
		if err := child.CheckSignatureFrom(parent); err != nil {
			link.Valid = false
			link.Error = err.Error()
			res.Ordered = false
		} else {
			link.Valid = true
		}
		res.Links = append(res.Links, link)
	}

	// A self-signed root terminates the chain when the last cert is
	// self-issued and verifies its own signature.
	if last := certs[len(certs)-1]; last.Subject.String() == last.Issuer.String() {
		res.ReachesSelfSignedRoot = last.CheckSignatureFrom(last) == nil
	}

	switch {
	case len(certs) == 1:
		res.Note = "single certificate — no chain links to verify"
	case res.Ordered && res.ReachesSelfSignedRoot:
		res.Note = "chain is correctly ordered and terminates in a self-signed root"
	case res.Ordered:
		res.Note = "chain links verify in order but no self-signed root is present (intermediate-only bundle)"
	default:
		res.Note = "chain does NOT link up in the supplied order — check ordering / a missing intermediate"
	}
	return res, nil
}

// parseChainCerts extracts every certificate from a PEM bundle, or a single
// certificate from hex-DER input.
func parseChainCerts(input string) ([]*x509.Certificate, string, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return nil, "", fmt.Errorf("x509decode: empty input")
	}
	if strings.Contains(s, "-----BEGIN") {
		var certs []*x509.Certificate
		rest := []byte(s)
		for {
			block, remaining := pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				c, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return nil, "", fmt.Errorf("x509decode: parse certificate %d: %w", len(certs), err)
				}
				certs = append(certs, c)
			}
			rest = remaining
		}
		if len(certs) == 0 {
			return nil, "", fmt.Errorf("x509decode: no CERTIFICATE block in PEM input")
		}
		return certs, "PEM", nil
	}
	b, err := parseHex(s)
	if err != nil {
		return nil, "", err
	}
	// A hex blob may itself be a concatenation of DER certificates.
	certs, err := x509.ParseCertificates(b)
	if err != nil {
		return nil, "", fmt.Errorf("x509decode: parse DER: %w", err)
	}
	if len(certs) == 0 {
		return nil, "", fmt.Errorf("x509decode: no certificate in DER input")
	}
	return certs, "DER", nil
}
