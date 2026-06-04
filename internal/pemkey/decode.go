// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pemkey parses a PEM private key file (the openssl-style
// "-----BEGIN [RSA|EC|ENCRYPTED] PRIVATE KEY-----" / PKCS#1 / SEC1 / PKCS#8
// formats) for triage. A stolen .pem / .key file is top pentest loot (TLS server
// keys, client-cert keys, API keys), and the first questions mirror the OpenSSH
// and PuTTY key tools (see internal/sshkey, internal/puttykey): is it
// **encrypted** (so the passphrase must be cracked before use)? what **key
// algorithm + size** (an RSA-1024 / weak key is worth flagging)? for an
// unencrypted key, what **public-key SHA-256** (to correlate the key with a
// known certificate / endpoint)? and for an encrypted key, what **cipher + KDF**
// (the crack cost)? Pure offline transform; no network or device.
//
// # Wrap-vs-native judgement
//
// Native (own code + Go stdlib; no third-party dep, no shell-out). The
// unencrypted-key DER is parsed with crypto/x509 (ParsePKCS1PrivateKey /
// ParseECPrivateKey / ParsePKCS8PrivateKey) and crypto/x509.MarshalPKIXPublicKey
// — these are stdlib ASN.1/DER routines for exactly these standard key
// structures; hand-rolling RSA/EC DER parsing would reinvent stdlib poorly and
// risk a confidently-wrong decode. The part stdlib will NOT do without the
// passphrase — reading the cipher + KDF parameters out of an encrypted key — is
// hand-rolled here: the traditional Proc-Type/DEK-Info headers are a plain-text
// read, and the PKCS#8 EncryptedPrivateKeyInfo (PBES2 → PBKDF2 / scrypt + an
// encryption scheme) is walked with encoding/asn1. No PEM/PKCS library is added
// to go.mod. Consistent with the other in-tree key/loot parsers.
//
// # Verifiable / no confidently-wrong output
//
// Anchored to openssl: for a generated EC P-256, Ed25519 and RSA-1024 key the
// algorithm / curve / bits + the public-key SHA-256 reproduce
// `openssl pkey -pubout -outform DER | sha256sum` exactly; for an encrypted key
// the cipher / KDF / salt / iteration (PBKDF2) or N,r,p (scrypt) / IV-length
// reproduce `openssl asn1parse` exactly. Every recognised OID is vector-checked;
// an unrecognised algorithm/cipher/KDF/PRF OID is surfaced as its dotted string
// with "(unrecognized)" rather than guessed. The key type/size of an encrypted
// key live in the ciphertext and are reported as unavailable, never guessed. A
// non-PEM blob, or DER that fails to parse, is rejected. An OpenSSH-format key is
// redirected to ssh_privkey_decode.
package pemkey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
)

// Result is the triage view of a PEM private key file.
type Result struct {
	Format    string `json:"format"`   // pem-pkcs1 / pem-sec1 / pem-pkcs8 / pem-traditional-encrypted / pem-pkcs8-encrypted
	PEMType   string `json:"pem_type"` // the BEGIN label
	Algorithm string `json:"algorithm,omitempty"`
	Bits      int    `json:"bits,omitempty"`
	Curve     string `json:"curve,omitempty"`
	Encrypted bool   `json:"encrypted"`

	Cipher        string `json:"cipher,omitempty"`
	IVLen         int    `json:"iv_len,omitempty"`
	KDF           string `json:"kdf,omitempty"`
	KDFPRF        string `json:"kdf_prf,omitempty"`
	KDFSaltLen    int    `json:"kdf_salt_len,omitempty"`
	KDFIterations int    `json:"kdf_iterations,omitempty"`
	ScryptN       int    `json:"scrypt_n,omitempty"`
	ScryptR       int    `json:"scrypt_r,omitempty"`
	ScryptP       int    `json:"scrypt_p,omitempty"`

	PublicSHA256 string `json:"public_sha256,omitempty"` // SHA-256 of the SubjectPublicKeyInfo DER (unencrypted only)
	Note         string `json:"note,omitempty"`
}

// OIDs (RFC 8018 PBES2 / RFC 7914 scrypt / NIST AES).
var (
	oidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidScrypt = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}
)

var prfNames = map[string]string{
	"1.2.840.113549.2.7":  "hmacWithSHA1",
	"1.2.840.113549.2.8":  "hmacWithSHA224",
	"1.2.840.113549.2.9":  "hmacWithSHA256",
	"1.2.840.113549.2.10": "hmacWithSHA384",
	"1.2.840.113549.2.11": "hmacWithSHA512",
}

var cipherNames = map[string]string{
	"2.16.840.1.101.3.4.1.2":  "aes-128-cbc",
	"2.16.840.1.101.3.4.1.22": "aes-192-cbc",
	"2.16.840.1.101.3.4.1.42": "aes-256-cbc",
	"2.16.840.1.101.3.4.1.6":  "aes-128-gcm",
	"2.16.840.1.101.3.4.1.26": "aes-192-gcm",
	"2.16.840.1.101.3.4.1.46": "aes-256-gcm",
	"1.2.840.113549.3.7":      "des-ede3-cbc",
	"1.3.14.3.2.7":            "des-cbc",
}

// Decode parses a PEM private key file.
func Decode(in string) (*Result, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(in)))
	if block == nil {
		return nil, fmt.Errorf("pemkey: no PEM block found")
	}
	r := &Result{PEMType: block.Type}

	switch {
	case block.Type == "OPENSSH PRIVATE KEY":
		return nil, fmt.Errorf("pemkey: this is an OpenSSH-format key — use ssh_privkey_decode")

	case isEncryptedHeader(block.Headers):
		return decodeTraditionalEncrypted(r, block)

	case block.Type == "ENCRYPTED PRIVATE KEY":
		return decodePKCS8Encrypted(r, block)

	default:
		return decodeUnencrypted(r, block)
	}
}

func isEncryptedHeader(h map[string]string) bool {
	return strings.Contains(strings.ToUpper(h["Proc-Type"]), "ENCRYPTED") || h["DEK-Info"] != ""
}

// decodeTraditionalEncrypted reads a legacy Proc-Type/DEK-Info encrypted PEM
// (RSA/EC/DSA PRIVATE KEY). The algorithm is the block label; the key size lives
// in the ciphertext and is not shown.
func decodeTraditionalEncrypted(r *Result, block *pem.Block) (*Result, error) {
	r.Format = "pem-traditional-encrypted"
	r.Encrypted = true
	r.Algorithm = algoFromLabel(block.Type)
	r.KDF = "EVP_BytesToKey(MD5)" // openssl's legacy traditional-PEM KDF
	dek := block.Headers["DEK-Info"]
	cipher, ivHex, found := strings.Cut(dek, ",")
	r.Cipher = strings.TrimSpace(cipher)
	if found {
		if iv, err := hex.DecodeString(strings.TrimSpace(ivHex)); err == nil {
			r.IVLen = len(iv)
		}
	}
	r.Note = fmt.Sprintf("encrypted (traditional PEM, %s, legacy MD5-based KDF) — crack the passphrase with "+
		"`openssl` / pem2john + John the Ripper before use. The key size is inside the encrypted DER, not shown.", r.Cipher)
	return r, nil
}

type encryptedPrivateKeyInfo struct {
	Algo      pkix.AlgorithmIdentifier
	Encrypted []byte
}

type pbes2Params struct {
	KeyDerivationFunc pkix.AlgorithmIdentifier
	EncryptionScheme  pkix.AlgorithmIdentifier
}

type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
	KeyLength      int                      `asn1:"optional"`
	PRF            pkix.AlgorithmIdentifier `asn1:"optional"`
}

type scryptParams struct {
	Salt      []byte
	CostN     int
	BlockR    int
	ParallelP int
	KeyLength int `asn1:"optional"`
}

// decodePKCS8Encrypted walks a PKCS#8 EncryptedPrivateKeyInfo (PBES2 → PBKDF2 /
// scrypt + an encryption scheme). The inner key type is encrypted, so only the
// cipher + KDF parameters are recoverable.
func decodePKCS8Encrypted(r *Result, block *pem.Block) (*Result, error) {
	r.Format = "pem-pkcs8-encrypted"
	r.Encrypted = true

	var epki encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(block.Bytes, &epki); err != nil {
		return nil, fmt.Errorf("pemkey: malformed EncryptedPrivateKeyInfo: %w", err)
	}
	if !epki.Algo.Algorithm.Equal(oidPBES2) {
		r.KDF = "PBES1 / " + epki.Algo.Algorithm.String() + " (unrecognized)"
		r.Note = "encrypted (PKCS#8, non-PBES2 scheme) — crack the passphrase with `openssl` / pem2john before use. Scheme parameters not decoded."
		return r, nil
	}
	var p pbes2Params
	if _, err := asn1.Unmarshal(epki.Algo.Parameters.FullBytes, &p); err != nil {
		return nil, fmt.Errorf("pemkey: malformed PBES2 parameters: %w", err)
	}

	// Encryption scheme: cipher OID + IV (an OCTET STRING for the CBC ciphers).
	r.Cipher = lookup(cipherNames, p.EncryptionScheme.Algorithm)
	var iv []byte
	if _, err := asn1.Unmarshal(p.EncryptionScheme.Parameters.FullBytes, &iv); err == nil {
		r.IVLen = len(iv)
	}

	// Key-derivation function.
	switch {
	case p.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2):
		r.KDF = "PBKDF2"
		var kp pbkdf2Params
		if _, err := asn1.Unmarshal(p.KeyDerivationFunc.Parameters.FullBytes, &kp); err != nil {
			return nil, fmt.Errorf("pemkey: malformed PBKDF2 parameters: %w", err)
		}
		r.KDFSaltLen = len(kp.Salt)
		r.KDFIterations = kp.IterationCount
		if len(kp.PRF.Algorithm) > 0 {
			r.KDFPRF = lookup(prfNames, kp.PRF.Algorithm)
		} else {
			r.KDFPRF = "hmacWithSHA1" // PBKDF2 default when the PRF is omitted (RFC 8018)
		}
	case p.KeyDerivationFunc.Algorithm.Equal(oidScrypt):
		r.KDF = "scrypt"
		var sp scryptParams
		if _, err := asn1.Unmarshal(p.KeyDerivationFunc.Parameters.FullBytes, &sp); err != nil {
			return nil, fmt.Errorf("pemkey: malformed scrypt parameters: %w", err)
		}
		r.KDFSaltLen = len(sp.Salt)
		r.ScryptN, r.ScryptR, r.ScryptP = sp.CostN, sp.BlockR, sp.ParallelP
	default:
		r.KDF = p.KeyDerivationFunc.Algorithm.String() + " (unrecognized)"
	}

	r.Note = fmt.Sprintf("encrypted (PKCS#8 PBES2, %s / %s) — crack the passphrase with `openssl` / pem2john + "+
		"John the Ripper before use. The key type + size are inside the encrypted DER, not shown.", r.Cipher, r.KDF)
	return r, nil
}

// decodeUnencrypted parses a cleartext key with crypto/x509 and reports its
// algorithm / size + the SHA-256 of its public SubjectPublicKeyInfo DER.
func decodeUnencrypted(r *Result, block *pem.Block) (*Result, error) {
	var (
		priv any
		err  error
	)
	switch block.Type {
	case "RSA PRIVATE KEY":
		r.Format = "pem-pkcs1"
		priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		r.Format = "pem-sec1"
		priv, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		r.Format = "pem-pkcs8"
		priv, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("pemkey: unsupported PEM block type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("pemkey: %s: %w", block.Type, err)
	}

	switch k := priv.(type) {
	case *rsa.PrivateKey:
		r.Algorithm, r.Bits = "RSA", k.N.BitLen()
	case *ecdsa.PrivateKey:
		r.Algorithm, r.Curve, r.Bits = "ECDSA", k.Curve.Params().Name, k.Curve.Params().BitSize
	case ed25519.PrivateKey:
		r.Algorithm, r.Bits = "Ed25519", 256
	default:
		r.Algorithm = fmt.Sprintf("%T", priv)
	}
	if pub := publicOf(priv); pub != nil {
		if der, e := x509.MarshalPKIXPublicKey(pub); e == nil {
			sum := sha256.Sum256(der)
			r.PublicSHA256 = hex.EncodeToString(sum[:])
		}
	}
	if r.Bits > 0 && r.Bits < 2048 && r.Algorithm == "RSA" {
		r.Note = fmt.Sprintf("unencrypted, directly usable — WARNING: RSA-%d is below the 2048-bit minimum (weak).", r.Bits)
	} else {
		r.Note = "unencrypted — the private key is directly usable (no cracking needed)."
	}
	return r, nil
}

func publicOf(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public()
	default:
		return nil
	}
}

func algoFromLabel(t string) string {
	switch {
	case strings.HasPrefix(t, "RSA"):
		return "RSA"
	case strings.HasPrefix(t, "EC"):
		return "ECDSA"
	case strings.HasPrefix(t, "DSA"):
		return "DSA"
	default:
		return ""
	}
}

func lookup(m map[string]string, oid asn1.ObjectIdentifier) string {
	if n, ok := m[oid.String()]; ok {
		return n
	}
	return oid.String() + " (unrecognized)"
}
