// Package jks decodes a Java KeyStore (JKS) for forensic triage and cracking.
//
// A `.jks` (or `.keystore`) file is classic enterprise loot: Java app servers
// (Tomcat, JBoss, custom services) keep their TLS server keys and code-signing
// keys in one, protected by a store password. The store password is a slow but
// crackable SHA-1-keyed digest (hashcat -m 15500, keystore2john), and the
// private keys inside grant the server's own identity. This parses the JKS
// container offline and reports the version, every entry (alias, type, creation
// time), the embedded certificate identities (parsed with crypto/x509 — whose
// TLS/signing identity each key is), and the matching crack mode.
//
// No confidently-wrong output: the file is recognised only by its 0xFEEDFEED
// magic and a known version (1 or 2); every field read is bounds-checked against
// the buffer, and a structural deviation (truncation, an over-long length, a
// missing 20-byte trailer) is reported as an error rather than guessed; a
// certificate that fails to parse is recorded per-entry with its error, never
// asserted valid. It does not crack, decrypt, or recover any key or password.
//
// Wrap-vs-native: native — a bounds-checked binary reader over the documented
// Sun JKS layout (sun.security.provider.JavaKeyStore.engineLoad) plus stdlib
// crypto/x509 for the certificate identities; no new go.mod dependency. Anchored
// to a real keytool-generated keystore (see the package test).
package jks

import (
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"time"
)

// magic is the JKS file magic, 0xFEEDFEED.
const magic = 0xFEEDFEED

// JKS entry tags.
const (
	tagPrivateKey  = 1
	tagTrustedCert = 2
)

// maxEntries caps the declared entry count: a JKS with more than this is almost
// certainly malformed/hostile, and the bound stops a huge count from driving a
// large slice allocation before the per-entry reads fail.
const maxEntries = 1 << 20

// Cert is one certificate from an entry's chain.
type Cert struct {
	Type    string `json:"type"`
	Bytes   int    `json:"bytes"`
	Subject string `json:"subject,omitempty"`
	Issuer  string `json:"issuer,omitempty"`
	// NotAfter is the certificate expiry (RFC3339 UTC), when parseable.
	NotAfter   string `json:"not_after,omitempty"`
	SelfSigned bool   `json:"self_signed,omitempty"`
	// ParseError is set when crypto/x509 could not parse the certificate; the
	// raw byte length is still reported, but no identity is asserted.
	ParseError string `json:"parse_error,omitempty"`
}

// Entry is one keystore entry.
type Entry struct {
	Alias string `json:"alias"`
	// Type is "private-key" or "trusted-cert".
	Type string `json:"type"`
	// Created is the entry creation time (RFC3339 UTC).
	Created string `json:"created,omitempty"`
	// EncryptedKeyBytes is the size of the EncryptedPrivateKeyInfo for a
	// private-key entry (0 for a trusted-cert entry).
	EncryptedKeyBytes int    `json:"encrypted_key_bytes,omitempty"`
	CertChain         []Cert `json:"cert_chain,omitempty"`
}

// Result is the decoded keystore.
type Result struct {
	Format       string  `json:"format"`
	Version      int     `json:"version"`
	EntryCount   int     `json:"entry_count"`
	PrivateKeys  int     `json:"private_keys"`
	TrustedCerts int     `json:"trusted_certs"`
	Entries      []Entry `json:"entries"`

	HashcatMode int    `json:"hashcat_mode"`
	JohnTool    string `json:"john_tool"`
	Note        string `json:"note"`
}

// reader is a bounds-checked big-endian cursor over the keystore bytes.
type reader struct {
	b   []byte
	pos int
}

func (r *reader) remaining() int { return len(r.b) - r.pos }

func (r *reader) u16() (int, error) {
	if r.remaining() < 2 {
		return 0, fmt.Errorf("jks: truncated (want 2 bytes at %d)", r.pos)
	}
	v := binary.BigEndian.Uint16(r.b[r.pos:])
	r.pos += 2
	return int(v), nil
}

func (r *reader) u32() (int64, error) {
	if r.remaining() < 4 {
		return 0, fmt.Errorf("jks: truncated (want 4 bytes at %d)", r.pos)
	}
	v := binary.BigEndian.Uint32(r.b[r.pos:])
	r.pos += 4
	return int64(v), nil
}

func (r *reader) i64() (int64, error) {
	if r.remaining() < 8 {
		return 0, fmt.Errorf("jks: truncated (want 8 bytes at %d)", r.pos)
	}
	v := binary.BigEndian.Uint64(r.b[r.pos:])
	r.pos += 8
	return int64(v), nil
}

// bytesN reads n bytes, refusing an n that exceeds what remains (so an over-long
// length field can never drive an out-of-range slice or a huge copy).
func (r *reader) bytesN(n int64) ([]byte, error) {
	if n < 0 || n > int64(r.remaining()) {
		return nil, fmt.Errorf("jks: length %d exceeds %d remaining bytes", n, r.remaining())
	}
	out := r.b[r.pos : r.pos+int(n)]
	r.pos += int(n)
	return out, nil
}

// utf reads a Java DataOutput UTF string (2-byte length + bytes). Aliases and
// cert-type tags are ASCII in practice; the bytes are stored verbatim.
func (r *reader) utf() (string, error) {
	n, err := r.u16()
	if err != nil {
		return "", err
	}
	b, err := r.bytesN(int64(n))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Decode parses a JKS keystore.
func Decode(data []byte) (*Result, error) {
	r := &reader{b: data}

	m, err := r.u32()
	if err != nil || m != magic {
		return nil, fmt.Errorf("jks: not a Java KeyStore (missing 0xFEEDFEED magic)")
	}
	version, err := r.u32()
	if err != nil {
		return nil, err
	}
	if version != 1 && version != 2 {
		return nil, fmt.Errorf("jks: unsupported version %d (want 1 or 2)", version)
	}
	count, err := r.u32()
	if err != nil {
		return nil, err
	}
	if count < 0 || count > maxEntries {
		return nil, fmt.Errorf("jks: implausible entry count %d", count)
	}

	res := &Result{
		Format:      "jks",
		Version:     int(version),
		EntryCount:  int(count),
		HashcatMode: 15500,
		JohnTool:    "keystore2john",
	}

	for i := int64(0); i < count; i++ {
		e, err := decodeEntry(r, int(version))
		if err != nil {
			return nil, fmt.Errorf("jks: entry %d: %w", i, err)
		}
		switch e.Type {
		case "private-key":
			res.PrivateKeys++
		case "trusted-cert":
			res.TrustedCerts++
		}
		res.Entries = append(res.Entries, *e)
	}

	// The container ends with a 20-byte SHA-1 integrity digest; exactly that much
	// must remain, or the structure did not parse cleanly.
	if r.remaining() != 20 {
		return nil, fmt.Errorf("jks: expected 20-byte trailer digest, found %d trailing bytes", r.remaining())
	}

	res.Note = noteFor(res)
	return res, nil
}

func decodeEntry(r *reader, version int) (*Entry, error) {
	tag, err := r.u32()
	if err != nil {
		return nil, err
	}
	alias, err := r.utf()
	if err != nil {
		return nil, err
	}
	dateMS, err := r.i64()
	if err != nil {
		return nil, err
	}
	e := &Entry{Alias: alias, Created: time.UnixMilli(dateMS).UTC().Format(time.RFC3339)}

	switch tag {
	case tagPrivateKey:
		e.Type = "private-key"
		keyLen, err := r.u32()
		if err != nil {
			return nil, err
		}
		if _, err := r.bytesN(keyLen); err != nil {
			return nil, fmt.Errorf("encrypted key: %w", err)
		}
		e.EncryptedKeyBytes = int(keyLen)
		chainLen, err := r.u32()
		if err != nil {
			return nil, err
		}
		// Each cert consumes at least a length field; bound the chain by the
		// bytes left so a bogus chainLen cannot spin a huge loop.
		if chainLen < 0 || chainLen > int64(r.remaining()) {
			return nil, fmt.Errorf("implausible cert-chain length %d", chainLen)
		}
		for c := int64(0); c < chainLen; c++ {
			cert, err := decodeCert(r, version)
			if err != nil {
				return nil, fmt.Errorf("chain cert %d: %w", c, err)
			}
			e.CertChain = append(e.CertChain, *cert)
		}
	case tagTrustedCert:
		e.Type = "trusted-cert"
		cert, err := decodeCert(r, version)
		if err != nil {
			return nil, err
		}
		e.CertChain = append(e.CertChain, *cert)
	default:
		return nil, fmt.Errorf("unknown entry tag %d", tag)
	}
	return e, nil
}

// decodeCert reads one certificate. In JKS version 2 each certificate is
// preceded by a UTF type tag ("X.509"); version 1 omits it (type is implicitly
// X.509).
func decodeCert(r *reader, version int) (*Cert, error) {
	cert := &Cert{Type: "X.509"}
	if version == 2 {
		t, err := r.utf()
		if err != nil {
			return nil, err
		}
		cert.Type = t
	}
	certLen, err := r.u32()
	if err != nil {
		return nil, err
	}
	raw, err := r.bytesN(certLen)
	if err != nil {
		return nil, fmt.Errorf("cert body: %w", err)
	}
	cert.Bytes = int(certLen)

	// Surface the certificate identity when it parses; record the error and move
	// on when it does not — never assert an identity we could not parse.
	if parsed, perr := x509.ParseCertificate(raw); perr != nil {
		cert.ParseError = perr.Error()
	} else {
		cert.Subject = parsed.Subject.String()
		cert.Issuer = parsed.Issuer.String()
		cert.NotAfter = parsed.NotAfter.UTC().Format(time.RFC3339)
		cert.SelfSigned = parsed.Subject.String() == parsed.Issuer.String()
	}
	return cert, nil
}

func noteFor(res *Result) string {
	base := "Forensic triage only — no key or password is cracked, decrypted, or recovered. "
	if res.PrivateKeys > 0 {
		return base + "The store password is a SHA-1-keyed digest crackable with hashcat -m 15500 " +
			"(keystore2john); a recovered password then decrypts the private keys, granting the server's own " +
			"TLS/signing identity. Offline; no network, no device."
	}
	return base + "This keystore holds only trusted certificates (no private keys), so there is no -m 15500 " +
		"private-key target — the certificate identities are surfaced for inventory. Offline; no network, no device."
}
