// x509_certificate.go — host-side X.509 certificate dissector
// Spec, delegating to the internal/x509decode package for the
// walker proper.

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
	Register(x509CertificateDecodeSpec)
}

var x509CertificateDecodeSpec = Spec{
	Name: "x509_certificate_decode",
	Description: "Decode an X.509 v3 certificate (PEM or DER) into a structured view — the " +
		"natural complement to tls_handshake_decode (whose Certificate handshake message " +
		"is surfaced as raw hex). Operators paste a PEM blob (or hex-encoded DER bytes) " +
		"and inspect every field without dragging out `openssl x509 -text` or pulling the " +
		"cert into a separate inspection tool. Per RFC 5280 + supporting RFCs. Decodes:\n\n" +
		"- **PEM and DER input auto-detection**: input starting with " +
		"'-----BEGIN CERTIFICATE-----' is decoded as PEM (with base64 unwrap and chain " +
		"support — the first cert is decoded; subsequent certs are counted); everything " +
		"else is treated as hex-encoded DER.\n" +
		"- **Subject + Issuer Distinguished Name**: full openssl-style DN string + " +
		"per-RDN breakdown (CommonName, Country, Organization, OrganizationalUnit, " +
		"Locality, Province, StreetAddress, PostalCode, SerialNumber).\n" +
		"- **Serial number**: both decimal and uppercase hex (the form printed by every " +
		"certificate UI).\n" +
		"- **Validity window**: NotBefore + NotAfter as RFC 3339 timestamps + a " +
		"days_remaining count for quick expiration triage (negative when expired) + an " +
		"expired flag.\n" +
		"- **Public key algorithm + size**: RSA modulus bits (1024/2048/3072/4096), " +
		"ECDSA curve name (P-256/P-384/P-521), Ed25519, DSA modulus.\n" +
		"- **Signature algorithm**: SHA1-RSA, SHA256-RSA, SHA256-ECDSA, SHA256-RSA-PSS, " +
		"Ed25519, etc.\n" +
		"- **X.509 version**: v1, v2, v3.\n" +
		"- **Extensions**:\n" +
		"  - **Subject Alternative Names** (DNS, IP, email, URI).\n" +
		"  - **Key Usage** (digitalSignature, contentCommitment, keyEncipherment, " +
		"dataEncipherment, keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly).\n" +
		"  - **Extended Key Usage** (serverAuth, clientAuth, codeSigning, " +
		"emailProtection, OCSPSigning, timeStamping, IPSec roles, Microsoft / " +
		"Netscape gated crypto, etc.).\n" +
		"  - **Basic Constraints** (CA flag + path length).\n" +
		"  - **Authority Information Access** (OCSP responder URLs + CA Issuer URLs).\n" +
		"  - **CRL Distribution Points** (URLs).\n" +
		"  - **Subject Key Identifier** (SKI, colon-hex).\n" +
		"  - **Authority Key Identifier** (AKI, colon-hex).\n" +
		"  - **Certificate Policy OIDs**.\n" +
		"- **Fingerprints**: SHA-1 + SHA-256 in canonical openssl/GUI colon-separated " +
		"form (the form used for SPKI pinning, CT log lookups, and at-a-glance cert " +
		"identification).\n" +
		"- **Self-signed detection**: SubjectDN == IssuerDN flag.\n" +
		"- **JA4X fingerprint** (FoxIO): the certificate member of the JA4+ threat-intel family — " +
		"`hash12(issuer RDN OIDs)_hash12(subject RDN OIDs)_hash12(extension OIDs)`, each the " +
		"comma-joined hex of the OID DER content-octets in certificate order. Fingerprints the " +
		"cert-generation stack (malware C2 / phishing infrastructure reuses it across deployments); " +
		"pairs with JA4 (client) + JA4S (server). Verified byte-for-byte against FoxIO snapshot RDN " +
		"hashes.\n\n" +
		"Pure offline parser — operators paste a PEM blob (from a certificate file, " +
		"`openssl s_client` output, a TLS handshake capture, or a CT log entry) and " +
		"inspect every field. Pairs with tls_handshake_decode for the complete " +
		"TLS-traffic-analysis stack: the handshake decoder identifies the connection " +
		"envelope + SNI + JA3, this Spec handles the cert chain bodies.\n\n" +
		"Out of scope (deferred to future iterations): chain validation (signature " +
		"verification + trust-store traversal + revocation checks — pure decoding " +
		"only), Certificate Transparency SCT decoding (SCT list extension is " +
		"recognised but body is raw hex), CSR (Certificate Signing Request) parsing, " +
		"CRL (Certificate Revocation List) parsing — each is a separate ASN.1 " +
		"structure warranting its own Spec.\n\n" +
		"Source: docs/catalog/gap-analysis.md (network-protocol decode space — natural " +
		"complement to tls_handshake_decode for full TLS-traffic-analysis coverage). " +
		"Wrap-vs-native: native via Go stdlib crypto/x509 + encoding/pem (which handle " +
		"the recursive ASN.1 DER walk); this Spec renders the parsed fields into the " +
		"same JSON shape every other native-fit decoder uses.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"input":{"type":"string","description":"X.509 certificate as PEM (starting with '-----BEGIN CERTIFICATE-----') or hex-encoded DER bytes. PEM chains supported — the first certificate in the chain is decoded and the total chain length is reported."}
		},
		"required":["input"]
	}`),
	Required:  []string{"input"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   x509CertificateDecodeHandler,
}

func x509CertificateDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "input")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("x509_certificate_decode: 'input' is required")
	}
	res, err := x509decode.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("x509_certificate_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
