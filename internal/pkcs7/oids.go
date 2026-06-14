package pkcs7

import (
	"encoding/asn1"
	"fmt"
)

// PKCS#7 / CMS content-type OIDs (RFC 5652 §3, §4; RFC 2315).
var (
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidSignedAndEnv  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 4}
	oidDigestedData  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 5}
	oidEncryptedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}

	// signing-time signed attribute (RFC 5652 §11.3).
	oidSigningTime = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)

// contentTypeName maps a content-type OID to a friendly name + the dotted OID.
func contentTypeName(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(oidData):
		return "data (1.2.840.113549.1.7.1)"
	case oid.Equal(oidSignedData):
		return "signedData (1.2.840.113549.1.7.2)"
	case oid.Equal(oidEnvelopedData):
		return "envelopedData (1.2.840.113549.1.7.3)"
	case oid.Equal(oidSignedAndEnv):
		return "signedAndEnvelopedData (1.2.840.113549.1.7.4)"
	case oid.Equal(oidDigestedData):
		return "digestedData (1.2.840.113549.1.7.5)"
	case oid.Equal(oidEncryptedData):
		return "encryptedData (1.2.840.113549.1.7.6)"
	case len(oid) == 0:
		return "(none)"
	default:
		return oid.String()
	}
}

// algNames maps the common algorithm OIDs (string form) to friendly names.
var algNames = map[string]string{ //nolint:gochecknoglobals
	// Digests.
	"1.2.840.113549.2.5":      "MD5",
	"1.3.14.3.2.26":           "SHA-1",
	"2.16.840.1.101.3.4.2.1":  "SHA-256",
	"2.16.840.1.101.3.4.2.2":  "SHA-384",
	"2.16.840.1.101.3.4.2.3":  "SHA-512",
	"2.16.840.1.101.3.4.2.4":  "SHA-224",
	"2.16.840.1.101.3.4.2.7":  "SHA3-256",
	"2.16.840.1.101.3.4.2.9":  "SHA3-384",
	"2.16.840.1.101.3.4.2.10": "SHA3-512",
	// Signature / public-key.
	"1.2.840.113549.1.1.1":  "RSA",
	"1.2.840.113549.1.1.5":  "SHA1-RSA",
	"1.2.840.113549.1.1.11": "SHA256-RSA",
	"1.2.840.113549.1.1.12": "SHA384-RSA",
	"1.2.840.113549.1.1.13": "SHA512-RSA",
	"1.2.840.113549.1.1.10": "RSA-PSS",
	"1.2.840.113549.1.1.4":  "MD5-RSA",
	"1.2.840.10040.4.1":     "DSA",
	"1.2.840.10040.4.3":     "SHA1-DSA",
	"1.2.840.10045.2.1":     "EC",
	"1.2.840.10045.4.1":     "SHA1-ECDSA",
	"1.2.840.10045.4.3.2":   "SHA256-ECDSA",
	"1.2.840.10045.4.3.3":   "SHA384-ECDSA",
	"1.2.840.10045.4.3.4":   "SHA512-ECDSA",
	"1.3.101.112":           "Ed25519",
	// Content encryption.
	"1.2.840.113549.3.7":      "3DES-CBC",
	"2.16.840.1.101.3.4.1.2":  "AES-128-CBC",
	"2.16.840.1.101.3.4.1.22": "AES-192-CBC",
	"2.16.840.1.101.3.4.1.42": "AES-256-CBC",
	"2.16.840.1.101.3.4.1.6":  "AES-128-GCM",
	"2.16.840.1.101.3.4.1.46": "AES-256-GCM",
	"1.2.840.113549.3.2":      "RC2-CBC",
}

// algName maps an algorithm OID to a friendly name, falling back to the OID.
func algName(oid asn1.ObjectIdentifier) string {
	if len(oid) == 0 {
		return "(none)"
	}
	if n, ok := algNames[oid.String()]; ok {
		return fmt.Sprintf("%s (%s)", n, oid.String())
	}
	return oid.String()
}
