// Package pkcs12 decodes a PKCS#12 / PFX keystore (.p12 / .pfx) for forensic
// triage and cracking.
//
// PKCS#12 is the modern, ubiquitous keystore: it is keytool's default since
// Java 9, the format Windows exports TLS client/server identities into, and the
// container for mobile provisioning. A looted .p12 holds a private key and its
// certificate chain, all protected by one password. That password guards a
// PBKDF integrity MAC over the container (the pfx2john crack target); recovering
// it then decrypts the key, yielding the identity. This parses the PFX offline
// and reports the version, the MAC parameters (the crack target), each top-level
// safe (plaintext vs password-encrypted), the certificate identities found in
// plaintext bags (via crypto/x509), and whether any private key is stored
// *unshrouded* (no per-key encryption — a finding in its own right).
//
// No confidently-wrong output: the file is recognised only as a well-formed PFX
// (version + a pkcs7-data authSafe); the ASN.1 is parsed with stdlib
// encoding/asn1 (which errors rather than panics on malformed input); a
// certificate that fails to parse is recorded with its error, never asserted
// valid; password-encrypted safes are reported as encrypted, never guessed; and
// it does not crack, decrypt, or recover any key or password.
//
// Wrap-vs-native: native — a bounded encoding/asn1 walk of the documented
// PKCS#12 structure (RFC 7292) plus stdlib crypto/x509 for the certificate
// identities; no new go.mod dependency. Anchored to real openssl-generated .p12
// files (see the package test).
package pkcs12

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// PKCS#12 / PKCS#7 / PKCS#9 object identifiers (RFC 7292, RFC 2315).
var (
	oidDataContent          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidEncryptedDataContent = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidCertBag              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidKeyBag               = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}
	oidShroudedKeyBag       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidX509Certificate      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
)

// pbeAlgName maps a PKCS#12 / PKCS#5 content-encryption OID to a readable name,
// falling back to the dotted OID so an unknown algorithm is shown, not hidden.
func pbeAlgName(oid asn1.ObjectIdentifier) string {
	switch oid.String() {
	case "1.2.840.113549.1.5.13":
		return "PBES2"
	case "1.2.840.113549.1.12.1.3":
		return "pbeWithSHA1And3-KeyTripleDES-CBC"
	case "1.2.840.113549.1.12.1.6":
		return "pbeWithSHA1And40BitRC2-CBC"
	case "1.2.840.113549.1.5.3":
		return "pbeWithMD5AndDES-CBC"
	default:
		return oid.String()
	}
}

// macAlgName maps a digest OID to a human name; empty for an unknown OID.
func macAlgName(oid asn1.ObjectIdentifier) string {
	switch oid.String() {
	case "1.3.14.3.2.26":
		return "SHA-1"
	case "2.16.840.1.101.3.4.2.4":
		return "SHA-224"
	case "2.16.840.1.101.3.4.2.1":
		return "SHA-256"
	case "2.16.840.1.101.3.4.2.2":
		return "SHA-384"
	case "2.16.840.1.101.3.4.2.3":
		return "SHA-512"
	default:
		return ""
	}
}

// --- ASN.1 models (RFC 7292) ---

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

type macData struct {
	Mac        digestInfo
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

type pfx struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData `asn1:"optional"`
}

type safeBag struct {
	ID         asn1.ObjectIdentifier
	Value      asn1.RawValue `asn1:"explicit,tag:0"`
	Attributes asn1.RawValue `asn1:"set,optional"`
}

type certBag struct {
	ID   asn1.ObjectIdentifier
	Data asn1.RawValue `asn1:"explicit,tag:0"`
}

type encryptedData struct {
	Version              int
	EncryptedContentInfo struct {
		ContentType                asn1.ObjectIdentifier
		ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
		EncryptedContent           asn1.RawValue `asn1:"optional,tag:0"`
	}
}

// --- result ---

// Cert is one certificate recovered from a plaintext bag.
type Cert struct {
	Subject    string `json:"subject,omitempty"`
	Issuer     string `json:"issuer,omitempty"`
	NotAfter   string `json:"not_after,omitempty"`
	SelfSigned bool   `json:"self_signed,omitempty"`
	Bytes      int    `json:"bytes"`
	ParseError string `json:"parse_error,omitempty"`
}

// Safe is one top-level AuthenticatedSafe ContentInfo.
type Safe struct {
	// Type is "data" (plaintext bags) or "encrypted-data" (password-encrypted).
	Type      string `json:"type"`
	Encrypted bool   `json:"encrypted"`
	// Algorithm names the content-encryption algorithm of an encrypted-data safe.
	Algorithm string `json:"algorithm,omitempty"`
	// Bags is the number of safe bags read from a plaintext safe.
	Bags int `json:"bags,omitempty"`
}

// Result is the decoded PKCS#12 container.
type Result struct {
	Format        string `json:"format"`
	Version       int    `json:"version"`
	MacPresent    bool   `json:"mac_present"`
	MacAlgorithm  string `json:"mac_algorithm,omitempty"`
	MacSaltBytes  int    `json:"mac_salt_bytes,omitempty"`
	MacIterations int    `json:"mac_iterations,omitempty"`

	Safes         []Safe `json:"safes"`
	Certificates  []Cert `json:"certificates,omitempty"`
	PlaintextKeys int    `json:"plaintext_keys"`
	ShroudedKeys  int    `json:"shrouded_keys"`

	JohnTool string `json:"john_tool"`
	Note     string `json:"note"`
}

// Decode parses a DER-encoded PKCS#12 / PFX container.
func Decode(der []byte) (*Result, error) {
	var p pfx
	rest, err := asn1.Unmarshal(der, &p)
	if err != nil {
		return nil, fmt.Errorf("pkcs12: not a PFX (ASN.1 parse failed): %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("pkcs12: %d trailing bytes after PFX", len(rest))
	}
	if !p.AuthSafe.ContentType.Equal(oidDataContent) {
		return nil, fmt.Errorf("pkcs12: authSafe is not pkcs7-data (got %v)", p.AuthSafe.ContentType)
	}

	res := &Result{Format: "pkcs12", Version: p.Version, JohnTool: "pfx2john"}

	// MAC integrity block (the crack target). It is optional in the spec but
	// present on every password-protected keystore.
	if name := macAlgName(p.MacData.Mac.Algorithm.Algorithm); name != "" || len(p.MacData.MacSalt) > 0 {
		res.MacPresent = true
		res.MacAlgorithm = name
		res.MacSaltBytes = len(p.MacData.MacSalt)
		res.MacIterations = p.MacData.Iterations
	}

	// authSafe content is an OCTET STRING wrapping the AuthenticatedSafe; the
	// explicit-tag unwrap leaves its raw content bytes here.
	var authSafe []byte
	if _, err := asn1.Unmarshal(p.AuthSafe.Content.Bytes, &authSafe); err != nil {
		return nil, fmt.Errorf("pkcs12: malformed authSafe octet string: %w", err)
	}
	var safes []contentInfo
	if _, err := asn1.Unmarshal(authSafe, &safes); err != nil {
		return nil, fmt.Errorf("pkcs12: malformed AuthenticatedSafe: %w", err)
	}

	for _, ci := range safes {
		res.applySafe(ci)
	}
	res.Note = noteFor(res)
	return res, nil
}

// applySafe classifies one top-level safe and, when it is plaintext, walks its
// bags for certificates and keys.
func (res *Result) applySafe(ci contentInfo) {
	switch {
	case ci.ContentType.Equal(oidDataContent):
		safe := Safe{Type: "data"}
		var inner []byte
		if _, err := asn1.Unmarshal(ci.Content.Bytes, &inner); err == nil {
			var bags []safeBag
			if _, err := asn1.Unmarshal(inner, &bags); err == nil {
				safe.Bags = len(bags)
				for _, b := range bags {
					res.applyBag(b)
				}
			}
		}
		res.Safes = append(res.Safes, safe)

	case ci.ContentType.Equal(oidEncryptedDataContent):
		safe := Safe{Type: "encrypted-data", Encrypted: true}
		var ed encryptedData
		if _, err := asn1.Unmarshal(ci.Content.Bytes, &ed); err == nil {
			safe.Algorithm = pbeAlgName(ed.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm)
		}
		res.Safes = append(res.Safes, safe)

	default:
		res.Safes = append(res.Safes, Safe{Type: ci.ContentType.String()})
	}
}

// applyBag handles one safe bag from a plaintext safe.
func (res *Result) applyBag(b safeBag) {
	switch {
	case b.ID.Equal(oidCertBag):
		if c, ok := parseCertBag(b.Value.Bytes); ok {
			res.Certificates = append(res.Certificates, c)
		}
	case b.ID.Equal(oidKeyBag):
		res.PlaintextKeys++
	case b.ID.Equal(oidShroudedKeyBag):
		res.ShroudedKeys++
	}
}

// parseCertBag extracts an X.509 certificate identity from a certBag value.
func parseCertBag(der []byte) (Cert, bool) {
	var cb certBag
	if _, err := asn1.Unmarshal(der, &cb); err != nil {
		return Cert{}, false
	}
	if !cb.ID.Equal(oidX509Certificate) {
		return Cert{}, false
	}
	var raw []byte
	if _, err := asn1.Unmarshal(cb.Data.Bytes, &raw); err != nil {
		return Cert{}, false
	}
	c := Cert{Bytes: len(raw)}
	if parsed, err := x509.ParseCertificate(raw); err != nil {
		c.ParseError = err.Error()
	} else {
		c.Subject = parsed.Subject.String()
		c.Issuer = parsed.Issuer.String()
		c.NotAfter = parsed.NotAfter.UTC().Format("2006-01-02T15:04:05Z")
		c.SelfSigned = parsed.Subject.String() == parsed.Issuer.String()
	}
	return c, true
}

func noteFor(res *Result) string {
	base := "Forensic triage only — no key or password is cracked, decrypted, or recovered. "
	if res.PlaintextKeys > 0 {
		return base + fmt.Sprintf("WARNING: %d private key(s) are stored UNSHROUDED (no per-key encryption) — "+
			"recoverable from the container without the password. The integrity MAC is still the pfx2john crack "+
			"target. Offline; no network, no device.", res.PlaintextKeys)
	}
	if res.MacPresent {
		return base + "The integrity MAC is a PBKDF digest keyed by the store password (pfx2john); recovering it " +
			"then decrypts the shrouded key and encrypted bags, yielding the identity. Offline; no network, no device."
	}
	return base + "No integrity MAC present. Offline; no network, no device."
}
