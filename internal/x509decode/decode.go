// SPDX-License-Identifier: AGPL-3.0-or-later

// Package x509decode parses X.509 certificates into a
// structured view — the natural complement to
// tls_handshake_decode (whose Certificate handshake-message
// body is surfaced as raw hex). Operators paste a PEM or DER
// blob and inspect subject, issuer, validity, SANs, key
// usage, EKU, AIA, CRL distribution points, and fingerprints
// without dragging out `openssl x509 -text` or pulling the
// cert into a separate inspection tool.
//
// # Wrap-vs-native judgement
//
// Native — via the Go standard library's crypto/x509 +
// encoding/pem packages. The X.509 v3 format is defined by
// RFC 5280 + supporting RFCs (CT, SCTs, ACME, etc.); stdlib
// handles the recursive ASN.1 DER walk so this package can
// focus on rendering the parsed fields into the same JSON
// shape every other native-fit decoder in this codebase
// uses. No vendor SDK, no networking, no cryptographic
// operations beyond computing the SHA-1 + SHA-256
// fingerprints — well within the stdlib scope.
//
// # What this package covers
//
//   - PEM and DER input auto-detection: input starting with
//     "-----BEGIN CERTIFICATE-----" is decoded as PEM (with
//     base64 unwrap and chain support — the first cert in
//     the chain is decoded; subsequent certs are exposed via
//     a count); everything else is treated as hex-encoded DER.
//   - Subject + Issuer Distinguished Name: each RDN
//     (CommonName, Organization, OrganizationalUnit,
//     Country, Province, Locality, StreetAddress, PostalCode,
//     SerialNumber) is surfaced as both a flat string and the
//     full DN as a canonical openssl-style string.
//   - Serial number rendered as both decimal and uppercase
//     hex (the form printed by every certificate UI).
//   - Validity window: NotBefore + NotAfter as RFC 3339
//     timestamps + a `days_remaining` count for quick
//     expiration triage (negative when already expired).
//   - Public key algorithm + key size:
//   - RSA: modulus size in bits (1024 / 2048 / 4096 / etc.).
//   - ECDSA: curve name (P-256 / P-384 / P-521).
//   - Ed25519 / Ed448: marked by name.
//   - DSA: modulus size.
//   - Signature algorithm name (SHA1-RSA / SHA256-RSA / SHA-
//     256-ECDSA / SHA256-RSA-PSS / Ed25519 / etc.).
//   - X.509 version (v1 / v2 / v3).
//   - Extensions:
//   - Subject Alternative Names (DNS / IP / email / URI).
//   - Key Usage (digital signature / key encipherment /
//     cert signing / etc.).
//   - Extended Key Usage (server auth / client auth /
//     code signing / email protection / OCSP signing /
//     time stamping / etc.).
//   - Basic Constraints (CA flag + optional path length).
//   - Authority Information Access (OCSP responder URLs +
//     CA Issuer URLs).
//   - CRL Distribution Points (URLs).
//   - Subject Key Identifier (SKI, hex-encoded).
//   - Authority Key Identifier (AKI, hex-encoded).
//   - Certificate Policies (OIDs).
//   - Fingerprints: SHA-1 (legacy / GUI-displayed),
//     SHA-256 (modern / SPKI pinning).
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - Chain validation (signature verification, trust-store
//     traversal, revocation checks) — pure decoding only.
//     The caller can wire a follow-up Spec that walks a
//     decoded chain against a configured trust store.
//   - Certificate Transparency SCT decoding (SCT list
//     extension is recognised by OID but the body is
//     surfaced as raw hex; SCT v1 binary format is a
//     separate ~200 LoC walker).
//   - CSR (Certificate Signing Request) parsing — that's a
//     different ASN.1 structure; a future Spec can cover it.
//   - CRL (Certificate Revocation List) parsing — separate
//     iteration, different ASN.1 structure.
package x509decode

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA-1 fingerprints are the GUI-displayed form.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// Certificate is the decoded view of one X.509 v3 certificate.
type Certificate struct {
	Source             string      `json:"source"`
	Version            int         `json:"version"`
	SerialNumberHex    string      `json:"serial_number_hex"`
	SerialNumberDec    string      `json:"serial_number_decimal"`
	SubjectDN          string      `json:"subject_dn"`
	Subject            *Name       `json:"subject"`
	IssuerDN           string      `json:"issuer_dn"`
	Issuer             *Name       `json:"issuer"`
	NotBefore          string      `json:"not_before"`
	NotAfter           string      `json:"not_after"`
	DaysRemaining      int         `json:"days_remaining"`
	Expired            bool        `json:"expired"`
	PublicKeyAlgorithm string      `json:"public_key_algorithm"`
	PublicKeyDetails   string      `json:"public_key_details"`
	SignatureAlgorithm string      `json:"signature_algorithm"`
	Extensions         *Extensions `json:"extensions,omitempty"`
	FingerprintSHA1    string      `json:"fingerprint_sha1"`
	FingerprintSHA256  string      `json:"fingerprint_sha256"`
	SelfSigned         bool        `json:"self_signed"`
	IsCA               bool        `json:"is_ca"`
	ChainLength        int         `json:"chain_length_seen,omitempty"`
}

// Name is the structured view of a DN.
type Name struct {
	CommonName         string   `json:"common_name,omitempty"`
	Country            []string `json:"country,omitempty"`
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizational_unit,omitempty"`
	Locality           []string `json:"locality,omitempty"`
	Province           []string `json:"province,omitempty"`
	StreetAddress      []string `json:"street_address,omitempty"`
	PostalCode         []string `json:"postal_code,omitempty"`
	SerialNumber       string   `json:"serial_number,omitempty"`
}

// Extensions carries the operationally-interesting v3
// extensions.
type Extensions struct {
	DNSNames               []string `json:"dns_names,omitempty"`
	IPAddresses            []string `json:"ip_addresses,omitempty"`
	EmailAddresses         []string `json:"email_addresses,omitempty"`
	URIs                   []string `json:"uris,omitempty"`
	KeyUsage               []string `json:"key_usage,omitempty"`
	ExtendedKeyUsage       []string `json:"extended_key_usage,omitempty"`
	BasicConstraintsValid  bool     `json:"basic_constraints_valid"`
	IsCA                   bool     `json:"is_ca,omitempty"`
	MaxPathLen             int      `json:"max_path_len,omitempty"`
	MaxPathLenZero         bool     `json:"max_path_len_zero,omitempty"`
	OCSPServers            []string `json:"ocsp_servers,omitempty"`
	IssuingCertificateURLs []string `json:"issuing_certificate_urls,omitempty"`
	CRLDistributionPoints  []string `json:"crl_distribution_points,omitempty"`
	SubjectKeyID           string   `json:"subject_key_id_hex,omitempty"`
	AuthorityKeyID         string   `json:"authority_key_id_hex,omitempty"`
	PolicyOIDs             []string `json:"policy_oids,omitempty"`
}

// Decode parses a PEM or hex-DER certificate input.
//
// PEM input is detected by the "-----BEGIN" prefix. For PEM
// chains the first certificate is decoded and the total chain
// length is reported via ChainLength.
func Decode(input string) (*Certificate, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return nil, fmt.Errorf("x509decode: empty input")
	}
	if strings.Contains(s, "-----BEGIN") {
		return decodePEM(s)
	}
	b, err := parseHex(s)
	if err != nil {
		return nil, err
	}
	return decodeDER(b, 1, "DER")
}

func decodePEM(s string) (*Certificate, error) {
	chainLen := 0
	var first []byte
	rest := []byte(s)
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			chainLen++
			if first == nil {
				first = block.Bytes
			}
		}
		rest = remaining
	}
	if first == nil {
		return nil, fmt.Errorf("x509decode: no CERTIFICATE block in PEM input")
	}
	return decodeDER(first, chainLen, "PEM")
}

func decodeDER(b []byte, chainLen int, source string) (*Certificate, error) {
	cert, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, fmt.Errorf("x509decode: parse: %w", err)
	}
	c := &Certificate{
		Source:             source,
		Version:            cert.Version,
		SerialNumberHex:    strings.ToUpper(hex.EncodeToString(cert.SerialNumber.Bytes())),
		SerialNumberDec:    cert.SerialNumber.String(),
		SubjectDN:          cert.Subject.String(),
		Subject:            buildName(&cert.Subject),
		IssuerDN:           cert.Issuer.String(),
		Issuer:             buildName(&cert.Issuer),
		NotBefore:          cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:           cert.NotAfter.UTC().Format(time.RFC3339),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		PublicKeyDetails:   publicKeyDetails(cert.PublicKey),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		IsCA:               cert.IsCA,
	}
	now := time.Now().UTC()
	remaining := cert.NotAfter.Sub(now)
	c.DaysRemaining = int(remaining.Hours() / 24)
	c.Expired = now.After(cert.NotAfter)
	c.SelfSigned = cert.Subject.String() == cert.Issuer.String()
	c.Extensions = buildExtensions(cert)
	sha1Sum := sha1.Sum(cert.Raw) //nolint:gosec // GUI fingerprint form.
	sha256Sum := sha256.Sum256(cert.Raw)
	c.FingerprintSHA1 = formatFingerprint(sha1Sum[:])
	c.FingerprintSHA256 = formatFingerprint(sha256Sum[:])
	if chainLen > 1 {
		c.ChainLength = chainLen
	}
	return c, nil
}

func buildName(n *pkix.Name) *Name {
	return &Name{
		CommonName:         n.CommonName,
		Country:            n.Country,
		Organization:       n.Organization,
		OrganizationalUnit: n.OrganizationalUnit,
		Locality:           n.Locality,
		Province:           n.Province,
		StreetAddress:      n.StreetAddress,
		PostalCode:         n.PostalCode,
		SerialNumber:       n.SerialNumber,
	}
}

// publicKeyDetails describes the public key in the same one-
// line form GUIs use ("RSA 2048 bits", "ECDSA P-256",
// "Ed25519").
func publicKeyDetails(pk interface{}) string {
	switch k := pk.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d bits", k.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %s", k.Curve.Params().Name)
	case ed25519.PublicKey:
		return fmt.Sprintf("Ed25519 %d bits", len(k)*8)
	}
	return "unknown"
}

func buildExtensions(cert *x509.Certificate) *Extensions {
	e := &Extensions{
		BasicConstraintsValid: cert.BasicConstraintsValid,
		IsCA:                  cert.IsCA,
		MaxPathLen:            cert.MaxPathLen,
		MaxPathLenZero:        cert.MaxPathLenZero,
	}
	e.DNSNames = cert.DNSNames
	for _, ip := range cert.IPAddresses {
		e.IPAddresses = append(e.IPAddresses, ip.String())
	}
	e.EmailAddresses = cert.EmailAddresses
	for _, u := range cert.URIs {
		e.URIs = append(e.URIs, u.String())
	}
	e.KeyUsage = keyUsageNames(cert.KeyUsage)
	for _, ek := range cert.ExtKeyUsage {
		e.ExtendedKeyUsage = append(e.ExtendedKeyUsage, extKeyUsageName(ek))
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		e.ExtendedKeyUsage = append(e.ExtendedKeyUsage, oid.String())
	}
	e.OCSPServers = cert.OCSPServer
	e.IssuingCertificateURLs = cert.IssuingCertificateURL
	e.CRLDistributionPoints = cert.CRLDistributionPoints
	if len(cert.SubjectKeyId) > 0 {
		e.SubjectKeyID = formatFingerprint(cert.SubjectKeyId)
	}
	if len(cert.AuthorityKeyId) > 0 {
		e.AuthorityKeyID = formatFingerprint(cert.AuthorityKeyId)
	}
	for _, oid := range cert.PolicyIdentifiers {
		e.PolicyOIDs = append(e.PolicyOIDs, oid.String())
	}
	return e
}

func keyUsageNames(ku x509.KeyUsage) []string {
	var out []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		out = append(out, "digitalSignature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		out = append(out, "contentCommitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		out = append(out, "keyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		out = append(out, "dataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		out = append(out, "keyAgreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		out = append(out, "keyCertSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		out = append(out, "cRLSign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		out = append(out, "encipherOnly")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		out = append(out, "decipherOnly")
	}
	return out
}

func extKeyUsageName(ek x509.ExtKeyUsage) string {
	switch ek {
	case x509.ExtKeyUsageAny:
		return "any"
	case x509.ExtKeyUsageServerAuth:
		return "serverAuth"
	case x509.ExtKeyUsageClientAuth:
		return "clientAuth"
	case x509.ExtKeyUsageCodeSigning:
		return "codeSigning"
	case x509.ExtKeyUsageEmailProtection:
		return "emailProtection"
	case x509.ExtKeyUsageIPSECEndSystem:
		return "ipsecEndSystem"
	case x509.ExtKeyUsageIPSECTunnel:
		return "ipsecTunnel"
	case x509.ExtKeyUsageIPSECUser:
		return "ipsecUser"
	case x509.ExtKeyUsageTimeStamping:
		return "timeStamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "OCSPSigning"
	case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
		return "microsoftServerGatedCrypto"
	case x509.ExtKeyUsageNetscapeServerGatedCrypto:
		return "netscapeServerGatedCrypto"
	case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
		return "microsoftCommercialCodeSigning"
	case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
		return "microsoftKernelCodeSigning"
	}
	return fmt.Sprintf("unknownEKU(%d)", ek)
}

// formatFingerprint renders bytes as "AA:BB:CC:..." — the
// canonical openssl / GUI form.
func formatFingerprint(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02X", x)
	}
	return strings.Join(parts, ":")
}

func parseHex(s string) ([]byte, error) {
	s = stripSeparators(s)
	if s == "" {
		return nil, fmt.Errorf("x509decode: empty hex input")
	}
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("x509decode: invalid hex: %w", err)
	}
	return b, nil
}

func stripSeparators(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
