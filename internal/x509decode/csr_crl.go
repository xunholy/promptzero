// SPDX-License-Identifier: AGPL-3.0-or-later

package x509decode

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// CSRInfo is the decoded view of a PKCS#10 certificate signing request
// (RFC 2986) — the enrollment request a client/device submits to a CA.
type CSRInfo struct {
	Source             string `json:"source"` // PEM | DER
	SubjectDN          string `json:"subject_dn"`
	Subject            *Name  `json:"subject"`
	PublicKeyAlgorithm string `json:"public_key_algorithm"`
	PublicKeyDetails   string `json:"public_key_details"`
	SignatureAlgorithm string `json:"signature_algorithm"`

	// Requested subject-alternative names.
	DNSNames       []string `json:"dns_names,omitempty"`
	IPAddresses    []string `json:"ip_addresses,omitempty"`
	EmailAddresses []string `json:"email_addresses,omitempty"`
	URIs           []string `json:"uris,omitempty"`

	// SignatureValid reports whether the CSR's self-signature verifies
	// against its own embedded public key — proof the requester possesses
	// the matching private key. A false here on a real enrollment request is
	// a red flag (tampered or forged request).
	SignatureValid bool   `json:"signature_valid"`
	SignatureError string `json:"signature_error,omitempty"`

	FingerprintSHA256 string `json:"fingerprint_sha256"` // of the DER
}

// CRLInfo is the decoded view of an X.509 Certificate Revocation List
// (RFC 5280).
type CRLInfo struct {
	Source             string `json:"source"` // PEM | DER
	IssuerDN           string `json:"issuer_dn"`
	Issuer             *Name  `json:"issuer"`
	ThisUpdate         string `json:"this_update"`
	NextUpdate         string `json:"next_update,omitempty"`
	Expired            bool   `json:"expired"` // NextUpdate is in the past
	CRLNumber          string `json:"crl_number,omitempty"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	AuthorityKeyID     string `json:"authority_key_id_hex,omitempty"`

	RevokedCount     int      `json:"revoked_count"`
	RevokedSerials   []string `json:"revoked_serials,omitempty"` // hex, capped
	RevokedTruncated bool     `json:"revoked_truncated,omitempty"`
}

// maxCRLSerials caps how many revoked serials are listed. A CRL can carry
// millions of entries; the count is always exact, the list is bounded so a
// huge (or hostile) CRL can't flood the agent's context / the audit log.
const maxCRLSerials = 1000

// DecodeCSR parses a PKCS#10 certificate signing request from PEM
// ("CERTIFICATE REQUEST") or hex-DER input and verifies its self-signature.
func DecodeCSR(input string) (*CSRInfo, error) {
	der, source, err := decodeX509Input(input, "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST")
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("x509decode: parse CSR: %w", err)
	}

	sum := sha256.Sum256(der)
	info := &CSRInfo{
		Source:             source,
		SubjectDN:          csr.Subject.String(),
		Subject:            buildName(&csr.Subject),
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm.String(),
		PublicKeyDetails:   publicKeyDetails(csr.PublicKey),
		SignatureAlgorithm: csr.SignatureAlgorithm.String(),
		DNSNames:           csr.DNSNames,
		EmailAddresses:     csr.EmailAddresses,
		FingerprintSHA256:  formatFingerprint(sum[:]),
	}
	for _, ip := range csr.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}
	for _, u := range csr.URIs {
		info.URIs = append(info.URIs, u.String())
	}
	if err := csr.CheckSignature(); err != nil {
		info.SignatureValid = false
		info.SignatureError = err.Error()
	} else {
		info.SignatureValid = true
	}
	return info, nil
}

// DecodeCRL parses an X.509 CRL from PEM ("X509 CRL") or hex-DER input.
func DecodeCRL(input string) (*CRLInfo, error) {
	der, source, err := decodeX509Input(input, "X509 CRL")
	if err != nil {
		return nil, err
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("x509decode: parse CRL: %w", err)
	}

	info := &CRLInfo{
		Source:             source,
		IssuerDN:           crl.Issuer.String(),
		Issuer:             buildName(&crl.Issuer),
		ThisUpdate:         crl.ThisUpdate.UTC().Format(time.RFC3339),
		SignatureAlgorithm: crl.SignatureAlgorithm.String(),
		RevokedCount:       len(crl.RevokedCertificateEntries),
	}
	if !crl.NextUpdate.IsZero() {
		info.NextUpdate = crl.NextUpdate.UTC().Format(time.RFC3339)
		info.Expired = time.Now().After(crl.NextUpdate)
	}
	if crl.Number != nil {
		info.CRLNumber = crl.Number.String()
	}
	if len(crl.AuthorityKeyId) > 0 {
		info.AuthorityKeyID = strings.ToUpper(hex.EncodeToString(crl.AuthorityKeyId))
	}
	for i, e := range crl.RevokedCertificateEntries {
		if i >= maxCRLSerials {
			info.RevokedTruncated = true
			break
		}
		info.RevokedSerials = append(info.RevokedSerials, strings.ToUpper(hex.EncodeToString(e.SerialNumber.Bytes())))
	}
	return info, nil
}

// decodeX509Input resolves PEM (matching any of pemTypes) or hex-DER input to
// raw DER bytes plus a source label. Shared by the CSR and CRL decoders;
// mirrors the certificate decoder's input handling.
func decodeX509Input(input string, pemTypes ...string) (der []byte, source string, err error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return nil, "", fmt.Errorf("x509decode: empty input")
	}
	if strings.Contains(s, "-----BEGIN") {
		rest := []byte(s)
		for {
			block, remaining := pem.Decode(rest)
			if block == nil {
				break
			}
			for _, t := range pemTypes {
				if block.Type == t {
					return block.Bytes, "PEM", nil
				}
			}
			rest = remaining
		}
		return nil, "", fmt.Errorf("x509decode: no %s block in PEM input", strings.Join(pemTypes, " / "))
	}
	b, perr := parseHex(s)
	if perr != nil {
		return nil, "", perr
	}
	return b, "DER", nil
}
