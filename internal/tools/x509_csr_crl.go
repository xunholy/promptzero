// SPDX-License-Identifier: AGPL-3.0-or-later

// x509_csr_crl.go registers csr_decode and crl_decode, completing the X.509
// PKI decoder family (certificate + request + revocation) alongside
// x509_certificate_decode. Both delegate to internal/x509decode.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/x509decode"
)

func init() { //nolint:gochecknoinits
	Register(csrDecodeSpec)
	Register(crlDecodeSpec)
	Register(ocspDecodeSpec)
}

var csrDecodeSpec = Spec{
	Name: "csr_decode",
	Description: "Decode a **PKCS#10 (pkcs10) certificate signing request** (RFC 2986) — the enrollment request a " +
		"client or device submits to a CA — from PEM (`-----BEGIN CERTIFICATE REQUEST-----`) or hex-encoded " +
		"DER. The request counterpart to `x509_certificate_decode`. Surfaces the requested subject DN, the " +
		"public key (algorithm + size), the signature algorithm, and the requested SANs (DNS / IP / email / " +
		"URI). Crucially it **verifies the CSR's self-signature** against its own public key — proof the " +
		"requester holds the matching private key; a `signature_valid:false` on a real enrollment request is a " +
		"red flag for a tampered or forged request. Offline, read-only. Low risk.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"input":{"type":"string","description":"CSR as PEM ('-----BEGIN CERTIFICATE REQUEST-----') or hex-encoded DER"}
		},
		"required":["input"]
	}`),
	Required:  []string{"input"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   csrDecodeHandler,
}

func csrDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "input")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("csr_decode: 'input' is required")
	}
	res, err := x509decode.DecodeCSR(raw)
	if err != nil {
		return "", fmt.Errorf("csr_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}

var crlDecodeSpec = Spec{
	Name: "crl_decode",
	Description: "Decode an **X.509 Certificate Revocation List** (RFC 5280) from PEM " +
		"(`-----BEGIN X509 CRL-----`) or hex-encoded DER. The revocation counterpart to " +
		"`x509_certificate_decode`. Surfaces the issuer DN, this/next update timestamps (with an `expired` " +
		"flag when the CRL is stale), the CRL number, the signature algorithm, the authority key id, the exact " +
		"count of revoked certificates, and the revoked serial numbers (hex). The serial list is capped — the " +
		"count is always exact, but a huge (or hostile) CRL can't flood output. Offline, read-only. Low risk.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"input":{"type":"string","description":"CRL as PEM ('-----BEGIN X509 CRL-----') or hex-encoded DER"}
		},
		"required":["input"]
	}`),
	Required:  []string{"input"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   crlDecodeHandler,
}

func crlDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "input")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("crl_decode: 'input' is required")
	}
	res, err := x509decode.DecodeCRL(raw)
	if err != nil {
		return "", fmt.Errorf("crl_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}

var ocspDecodeSpec = Spec{
	Name: "ocsp_decode",
	Description: "Decode an **OCSP response** (RFC 6960) — the query-based certificate revocation status (the " +
		"per-certificate counterpart to `crl_decode`'s list). Input is base64 (the usual HTTP / captured form) " +
		"or hex-encoded DER. Surfaces the cert **status** (good / revoked / unknown), the serial number, the " +
		"produced/this/next-update timestamps (with an `expired` flag when the response is stale), and — when " +
		"revoked — the revocation time and reason (keyCompromise, cACompromise, superseded, …), plus the " +
		"responder identity and signature algorithm.\n\n" +
		"Does NOT verify the responder signature (that needs the issuer certificate) — the output says so. " +
		"Offline, read-only. Low risk.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"input":{"type":"string","description":"OCSP response as base64 or hex-encoded DER"}
		},
		"required":["input"]
	}`),
	Required:  []string{"input"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ocspDecodeHandler,
}

func ocspDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "input")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ocsp_decode: 'input' is required")
	}
	res, err := x509decode.DecodeOCSP(raw)
	if err != nil {
		return "", fmt.Errorf("ocsp_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
