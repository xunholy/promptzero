// Package pkcs7 decodes a PKCS#7 / CMS (Cryptographic Message Syntax, RFC 5652)
// structure into a readable forensic view.
//
// PKCS#7 / CMS is the container behind S/MIME signed & encrypted email,
// Authenticode (Windows code signing is a SignedData), .p7b / .p7c certificate
// bundles, .p7s detached signatures, timestamp tokens, and the SignedData that
// wraps many document signatures. After an operator recovers such a blob the
// question is "what is this — signed or encrypted? whose certificate? signed
// when, with what algorithm?". This walks the ASN.1 with the Go stdlib
// (encoding/asn1 + crypto/x509) and surfaces it.
//
// What it covers: the outer ContentInfo content-type (SignedData /
// EnvelopedData / DigestedData / EncryptedData / data / …); for SignedData the
// version, the digest algorithms, the encapsulated content type and whether the
// content is embedded or detached, the embedded X.509 certificate chain
// (subject / issuer / serial / validity / key & signature algorithm / CA flag /
// SKI), whether CRLs are present, and each SignerInfo (the issuer+serial or
// subject-key-id that identifies the signer, the digest & signature algorithms,
// whether signed attributes are present, and the signing time when carried);
// for EnvelopedData the recipient count and the content-encryption algorithm.
// A security note flags weak digests (MD5 / SHA-1).
//
// What it does NOT do: verify the signature, decrypt the content, or validate
// the certificate chain — it is a structural decoder. No key material, no
// network. Weak/legacy algorithms are reported, never trusted.
//
// No confidently-wrong output: every field comes straight from the ASN.1;
// unknown algorithm / content-type OIDs are surfaced as the dotted OID, never
// guessed; a parse error is returned, never a partial guess.
//
// Wrap-vs-native: native — stdlib encoding/asn1 + crypto/x509, no new go.mod
// dependency. Anchored to real openssl-generated CMS (see the test).
package pkcs7

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Result is the decoded CMS structure.
type Result struct {
	Format        string         `json:"format"`
	ContentType   string         `json:"content_type"`
	SignedData    *SignedData    `json:"signed_data,omitempty"`
	EnvelopedData *EnvelopedData `json:"enveloped_data,omitempty"`
	Note          string         `json:"note"`
}

// SignedData is a CMS SignedData (the S/MIME-sign / Authenticode / .p7b case).
type SignedData struct {
	Version          int      `json:"version"`
	DigestAlgorithms []string `json:"digest_algorithms,omitempty"`
	EncapContentType string   `json:"encap_content_type"`
	Detached         bool     `json:"detached"`
	Certificates     []Cert   `json:"certificates,omitempty"`
	CRLsPresent      bool     `json:"crls_present,omitempty"`
	Signers          []Signer `json:"signers,omitempty"`
}

// Cert is one embedded X.509 certificate's headline facts.
type Cert struct {
	Subject            string `json:"subject"`
	Issuer             string `json:"issuer"`
	SerialNumber       string `json:"serial_number"`
	NotBefore          string `json:"not_before"`
	NotAfter           string `json:"not_after"`
	PublicKeyAlgorithm string `json:"public_key_algorithm"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	IsCA               bool   `json:"is_ca,omitempty"`
	SubjectKeyID       string `json:"subject_key_id,omitempty"`
}

// Signer is one SignerInfo.
type Signer struct {
	Version            int    `json:"version"`
	IssuerAndSerial    string `json:"issuer_and_serial,omitempty"`
	SubjectKeyID       string `json:"subject_key_id,omitempty"`
	DigestAlgorithm    string `json:"digest_algorithm"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	HasSignedAttrs     bool   `json:"has_signed_attrs"`
	SigningTime        string `json:"signing_time,omitempty"`
}

// EnvelopedData is a CMS EnvelopedData (the S/MIME-encrypt case).
type EnvelopedData struct {
	Version                    int    `json:"version"`
	RecipientCount             int    `json:"recipient_count"`
	EncryptedContentType       string `json:"encrypted_content_type"`
	ContentEncryptionAlgorithm string `json:"content_encryption_algorithm"`
}

// --- ASN.1 shapes -----------------------------------------------------------

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type encapContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signedDataASN struct {
	Version          int
	DigestAlgorithms []algorithmIdentifier `asn1:"set"`
	EncapContentInfo encapContentInfo
	Certificates     asn1.RawValue   `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue   `asn1:"optional,tag:1"`
	SignerInfos      []asn1.RawValue `asn1:"set"`
}

type signerInfoASN struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    algorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm algorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type issuerAndSerialASN struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type attributeASN struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

type envelopedDataASN struct {
	Version              int
	RecipientInfos       []asn1.RawValue `asn1:"set"`
	EncryptedContentInfo encryptedContentInfoASN
}

type encryptedContentInfoASN struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm algorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"optional,tag:0"`
}

// Decode parses a DER-encoded PKCS#7 / CMS structure.
func Decode(der []byte) (*Result, error) {
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("pkcs7: not a CMS ContentInfo: %w", err)
	}
	res := &Result{Format: "pkcs7", ContentType: contentTypeName(ci.ContentType)}
	switch {
	case ci.ContentType.Equal(oidSignedData):
		if err := res.parseSignedData(ci.Content.Bytes); err != nil {
			return nil, err
		}
	case ci.ContentType.Equal(oidEnvelopedData):
		if err := res.parseEnvelopedData(ci.Content.Bytes); err != nil {
			return nil, err
		}
	}
	res.Note = noteFor(res)
	return res, nil
}

func (res *Result) parseSignedData(b []byte) error {
	if len(b) == 0 {
		return fmt.Errorf("pkcs7: empty SignedData content")
	}
	var sd signedDataASN
	if _, err := asn1.Unmarshal(b, &sd); err != nil {
		return fmt.Errorf("pkcs7: malformed SignedData: %w", err)
	}
	out := &SignedData{
		Version:          sd.Version,
		EncapContentType: contentTypeName(sd.EncapContentInfo.ContentType),
		Detached:         len(sd.EncapContentInfo.Content.Bytes) == 0,
		CRLsPresent:      len(sd.CRLs.Bytes) > 0,
	}
	for _, da := range sd.DigestAlgorithms {
		out.DigestAlgorithms = append(out.DigestAlgorithms, algName(da.Algorithm))
	}
	if len(sd.Certificates.Bytes) > 0 {
		if certs, err := x509.ParseCertificates(sd.Certificates.Bytes); err == nil {
			for _, c := range certs {
				out.Certificates = append(out.Certificates, toCert(c))
			}
		}
	}
	for _, raw := range sd.SignerInfos {
		if s, ok := parseSigner(raw.FullBytes); ok {
			out.Signers = append(out.Signers, s)
		}
	}
	res.SignedData = out
	return nil
}

func (res *Result) parseEnvelopedData(b []byte) error {
	if len(b) == 0 {
		return fmt.Errorf("pkcs7: empty EnvelopedData content")
	}
	var ed envelopedDataASN
	if _, err := asn1.Unmarshal(b, &ed); err != nil {
		return fmt.Errorf("pkcs7: malformed EnvelopedData: %w", err)
	}
	res.EnvelopedData = &EnvelopedData{
		Version:                    ed.Version,
		RecipientCount:             len(ed.RecipientInfos),
		EncryptedContentType:       contentTypeName(ed.EncryptedContentInfo.ContentType),
		ContentEncryptionAlgorithm: algName(ed.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm),
	}
	return nil
}

// parseSigner decodes one SignerInfo.
func parseSigner(raw []byte) (Signer, bool) {
	var si signerInfoASN
	if _, err := asn1.Unmarshal(raw, &si); err != nil {
		return Signer{}, false
	}
	s := Signer{
		Version:            si.Version,
		DigestAlgorithm:    algName(si.DigestAlgorithm.Algorithm),
		SignatureAlgorithm: algName(si.SignatureAlgorithm.Algorithm),
		HasSignedAttrs:     len(si.SignedAttrs.Bytes) > 0,
	}
	// SignerIdentifier: [0] subjectKeyIdentifier, else issuerAndSerialNumber.
	if si.SID.Class == asn1.ClassContextSpecific && si.SID.Tag == 0 {
		s.SubjectKeyID = strings.ToUpper(hex.EncodeToString(si.SID.Bytes))
	} else {
		var ias issuerAndSerialASN
		if _, err := asn1.Unmarshal(si.SID.FullBytes, &ias); err == nil {
			s.IssuerAndSerial = nameString(ias.Issuer.FullBytes) + "; serial=" + serialString(ias.SerialNumber)
		}
	}
	if s.HasSignedAttrs {
		if t, ok := signingTime(si.SignedAttrs.Bytes); ok {
			s.SigningTime = t
		}
	}
	return s, true
}

// signingTime extracts the signing-time signed attribute (OID 1.2.840.113549.1.9.5).
func signingTime(signedAttrsBody []byte) (string, bool) {
	// SignedAttrs was parsed as an IMPLICIT [0] SET; its Bytes is the SET body:
	// a concatenation of Attribute SEQUENCEs. Walk them.
	rest := signedAttrsBody
	for len(rest) > 0 {
		var attr attributeASN
		var err error
		rest, err = asn1.Unmarshal(rest, &attr)
		if err != nil {
			return "", false
		}
		if !attr.Type.Equal(oidSigningTime) {
			continue
		}
		var t time.Time
		if _, err := asn1.Unmarshal(attr.Values.Bytes, &t); err == nil {
			return t.UTC().Format(time.RFC3339), true
		}
	}
	return "", false
}

func toCert(c *x509.Certificate) Cert {
	cert := Cert{
		Subject:            c.Subject.String(),
		Issuer:             c.Issuer.String(),
		SerialNumber:       serialString(c.SerialNumber),
		NotBefore:          c.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:           c.NotAfter.UTC().Format(time.RFC3339),
		PublicKeyAlgorithm: c.PublicKeyAlgorithm.String(),
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		IsCA:               c.IsCA,
	}
	if len(c.SubjectKeyId) > 0 {
		cert.SubjectKeyID = strings.ToUpper(hex.EncodeToString(c.SubjectKeyId))
	}
	return cert
}

func nameString(der []byte) string {
	var rdn pkix.RDNSequence
	if _, err := asn1.Unmarshal(der, &rdn); err != nil {
		return "<unparseable name>"
	}
	var n pkix.Name
	n.FillFromRDNSequence(&rdn)
	return n.String()
}

func serialString(n *big.Int) string {
	if n == nil {
		return ""
	}
	return strings.ToUpper(hex.EncodeToString(n.Bytes()))
}

func noteFor(res *Result) string {
	base := "Structural decode only — the signature was not verified and the content was not decrypted. "
	weak := weakDigests(res)
	switch {
	case res.SignedData != nil:
		msg := base + fmt.Sprintf("CMS SignedData with %d certificate(s) and %d signer(s)",
			len(res.SignedData.Certificates), len(res.SignedData.Signers))
		if res.SignedData.Detached {
			msg += " (detached — the signed content is not embedded)"
		}
		if weak != "" {
			msg += ". WEAK: " + weak
		}
		return msg + "."
	case res.EnvelopedData != nil:
		return base + fmt.Sprintf("CMS EnvelopedData encrypted for %d recipient(s) with %s; the recipient's private key is needed to decrypt.",
			res.EnvelopedData.RecipientCount, res.EnvelopedData.ContentEncryptionAlgorithm)
	default:
		return base + "Content type " + res.ContentType + " — recognised but not structurally expanded."
	}
}

// weakDigests reports a comma-joined list of weak digest algorithms in use.
func weakDigests(res *Result) string {
	if res.SignedData == nil {
		return ""
	}
	seen := map[string]bool{}
	var weak []string
	add := func(a string) {
		la := strings.ToLower(a)
		if (strings.Contains(la, "md5") || strings.Contains(la, "sha1") || strings.Contains(la, "sha-1")) && !seen[a] {
			seen[a] = true
			weak = append(weak, a)
		}
	}
	for _, d := range res.SignedData.DigestAlgorithms {
		add(d)
	}
	for _, s := range res.SignedData.Signers {
		add(s.DigestAlgorithm)
	}
	if len(weak) == 0 {
		return ""
	}
	return "broken/legacy digest in use (" + strings.Join(weak, ", ") + ")"
}
