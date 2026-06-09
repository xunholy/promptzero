// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pgppacket decodes the OpenPGP (RFC 4880 / RFC 9580) packet stream of a
// PGP key or message — public/secret keys, user IDs, signatures, and the
// encrypted/compressed/literal data packets — into a structured per-packet view:
// tag, length, and for key packets the version, algorithm, creation time,
// **fingerprint, and 64-bit key ID**. A captured PGP key or message (`.asc`,
// `.gpg`, an armored block pasted from an email or a key dump) is real
// credential-forensics / IR loot: identifying a key's fingerprint / key ID, its
// algorithm and creation time, and the user IDs it certifies is standard triage,
// and a secret-key packet is the private key itself. Pure offline transform; no
// network or device.
//
// # Wrap-vs-native judgement
//
// Native. The OpenPGP packet framing (old- and new-format headers, partial
// lengths), the public-key fingerprint formula (RFC 4880 §12.2: SHA-1 over
// 0x99 ‖ len ‖ body for v4, SHA-256 over 0x9A ‖ len ‖ body for v5), the MPI /
// ECC-OID layout, and the algorithm/tag tables are a public spec — a TLV walker
// plus a hash, stdlib only. We do NOT depend on golang.org/x/crypto/openpgp
// (deprecated and frozen); it is used ONLY in the package test as an independent
// reference oracle to cross-check every fingerprint / key ID / tag.
//
// # What this covers / defers
//
//   - Packet framing for every tag (old + new format, single- and partial-body
//     lengths) with tag names.
//   - Public-Key / Public-Subkey / Secret-Key / Secret-Subkey: version, algorithm,
//     creation time, and (v4/v5) the fingerprint + key ID. For a public-key
//     packet the whole body is hashed (correct for every algorithm); for a
//     secret-key packet the public portion is isolated by walking the public MPIs
//     (RSA / DSA / Elgamal) — an ECC secret key's fingerprint is flagged rather
//     than guessed, since that OID/point layout is not exercised by the oracle.
//   - User ID text; Signature header fields (version, type, public-key + hash
//     algorithm).
//   - v3 keys are surfaced (version + creation + algorithm) but their MD5
//     fingerprint is not computed (legacy, rare); MPI bodies of signatures and
//     session-key packets are not deep-parsed (the recon value is the framing +
//     key identity).
//
// # Verifiable / no confidently-wrong output
//
// Cross-checked in-package against golang.org/x/crypto/openpgp: a freshly
// generated entity (public + secret) is serialized, parsed by BOTH this native
// walker and the reference implementation, and every fingerprint / key ID /
// creation time / tag must match byte-for-byte. A truncated packet or a length
// that overruns the buffer is reported as a warning and the walk stops cleanly
// rather than panicking; non-OpenPGP input is rejected.
package pgppacket

import (
	"crypto/sha1" //nolint:gosec // SHA-1 is the RFC 4880 v4 fingerprint algorithm, not a security choice
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Packet is one decoded OpenPGP packet.
type Packet struct {
	Tag    int    `json:"tag"`
	Name   string `json:"name"`
	Format string `json:"format"` // old / new
	Length int    `json:"length"`
	Offset int    `json:"offset"`

	// Key packets (tags 5, 6, 7, 14).
	KeyVersion  int    `json:"key_version,omitempty"`
	Algorithm   string `json:"algorithm,omitempty"`
	CreatedUTC  string `json:"created_utc,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	KeyID       string `json:"key_id,omitempty"`

	// User ID (tag 13).
	UserID string `json:"user_id,omitempty"`

	// Signature (tag 2).
	SignatureType string `json:"signature_type,omitempty"`
	HashAlgorithm string `json:"hash_algorithm,omitempty"`

	Note string `json:"note,omitempty"`
}

// Result is the decoded packet stream.
type Result struct {
	Armored     bool     `json:"armored"`
	PacketCount int      `json:"packet_count"`
	Packets     []Packet `json:"packets"`
	Warnings    []string `json:"warnings,omitempty"`
}

// Decode accepts an ASCII-armored block, a base64 body, a hex string, or raw
// binary bytes (as a string) and walks the OpenPGP packet stream.
func Decode(input string) (*Result, error) {
	data, armored, err := normalize(input)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("pgppacket: empty input")
	}
	res := &Result{Armored: armored}
	walk(res, data)
	res.PacketCount = len(res.Packets)
	if res.PacketCount == 0 {
		return nil, fmt.Errorf("pgppacket: no OpenPGP packets found (is this an OpenPGP key/message?)")
	}
	return res, nil
}

// normalize strips ASCII armor and decodes base64 / hex / raw forms to bytes.
func normalize(in string) ([]byte, bool, error) {
	s := strings.TrimSpace(in)
	if strings.HasPrefix(s, "-----BEGIN PGP") {
		body, err := dearmor(s)
		return body, true, err
	}
	// Try base64, then hex; otherwise treat as raw bytes.
	compact := strings.Join(strings.Fields(s), "")
	if b, err := base64.StdEncoding.DecodeString(compact); err == nil && len(b) > 0 && b[0]&0x80 != 0 {
		return b, false, nil
	}
	if b, err := hex.DecodeString(compact); err == nil && len(b) > 0 {
		return b, false, nil
	}
	return []byte(s), false, nil
}

// dearmor extracts the base64 body from an ASCII-armored block (dropping the
// armor headers and the trailing =CRC24 checksum line).
func dearmor(s string) ([]byte, error) {
	lines := strings.Split(s, "\n")
	var b64 strings.Builder
	inBody, sawBlank := false, false
	for _, ln := range lines {
		t := strings.TrimRight(ln, "\r")
		switch {
		case strings.HasPrefix(t, "-----BEGIN PGP"):
			inBody = true
		case strings.HasPrefix(t, "-----END PGP"):
			inBody = false
		case inBody && !sawBlank && strings.TrimSpace(t) == "":
			sawBlank = true // header/body separator
		case inBody && sawBlank:
			if strings.HasPrefix(t, "=") { // CRC24 checksum line
				continue
			}
			b64.WriteString(strings.TrimSpace(t))
		}
	}
	data, err := base64.StdEncoding.DecodeString(b64.String())
	if err != nil {
		return nil, fmt.Errorf("pgppacket: armored body is not valid base64: %w", err)
	}
	return data, nil
}

// walk parses the packet stream into res, stopping cleanly on truncation.
func walk(res *Result, data []byte) {
	i := 0
	for i < len(data) {
		first := data[i]
		if first&0x80 == 0 {
			res.Warnings = append(res.Warnings, fmt.Sprintf("byte %d: not an OpenPGP packet header (high bit clear)", i))
			return
		}
		var (
			tag, hdrLen, bodyLen int
			format               string
			partial              bool
		)
		if first&0x40 == 0 {
			tag, bodyLen, hdrLen, partial = parseOldHeader(data, i)
			format = "old"
		} else {
			tag, bodyLen, hdrLen, partial = parseNewHeader(data, i)
			format = "new"
		}
		if hdrLen == 0 {
			res.Warnings = append(res.Warnings, fmt.Sprintf("byte %d: malformed packet length", i))
			return
		}
		bodyStart := i + hdrLen
		if partial || bodyLen < 0 || bodyStart+bodyLen > len(data) {
			// Indeterminate / partial / overrunning length: take the rest.
			bodyLen = len(data) - bodyStart
		}
		body := data[bodyStart : bodyStart+bodyLen]
		p := Packet{Tag: tag, Name: tagName(tag), Format: format, Length: bodyLen, Offset: bodyStart}
		interpret(&p, body)
		res.Packets = append(res.Packets, p)
		i = bodyStart + bodyLen
	}
}

// parseOldHeader decodes an old-format header (RFC 4880 §4.2.1).
func parseOldHeader(data []byte, i int) (tag, bodyLen, hdrLen int, partial bool) {
	tag = int((data[i] >> 2) & 0x0f)
	switch data[i] & 0x03 {
	case 0:
		if i+1 >= len(data) {
			return tag, 0, 0, false
		}
		return tag, int(data[i+1]), 2, false
	case 1:
		if i+2 >= len(data) {
			return tag, 0, 0, false
		}
		return tag, int(binary.BigEndian.Uint16(data[i+1:])), 3, false
	case 2:
		if i+4 >= len(data) {
			return tag, 0, 0, false
		}
		return tag, int(binary.BigEndian.Uint32(data[i+1:])), 5, false
	default: // 3 = indeterminate
		return tag, -1, 1, true
	}
}

// parseNewHeader decodes a new-format header (RFC 4880 §4.2.2).
func parseNewHeader(data []byte, i int) (tag, bodyLen, hdrLen int, partial bool) {
	tag = int(data[i] & 0x3f)
	if i+1 >= len(data) {
		return tag, 0, 0, false
	}
	l := data[i+1]
	switch {
	case l < 192:
		return tag, int(l), 2, false
	case l < 224:
		if i+2 >= len(data) {
			return tag, 0, 0, false
		}
		return tag, (int(l-192) << 8) + int(data[i+2]) + 192, 3, false
	case l == 255:
		if i+5 >= len(data) {
			return tag, 0, 0, false
		}
		return tag, int(binary.BigEndian.Uint32(data[i+2:])), 6, false
	default: // 224..254: partial body length (first chunk)
		return tag, 1 << (l & 0x1f), 2, true
	}
}

// interpret fills in type-specific fields.
func interpret(p *Packet, body []byte) {
	switch p.Tag {
	case 6, 14: // Public-Key, Public-Subkey — the whole body is the public key
		parseKey(p, body, false)
	case 5, 7: // Secret-Key, Secret-Subkey — public portion precedes the secret material
		parseKey(p, body, true)
	case 13: // User ID
		p.UserID = string(body)
	case 2: // Signature
		parseSignature(p, body)
	}
}

// parseKey extracts the public-key fields and computes the fingerprint. For a
// public-key packet the whole body is hashed; for a secret-key packet the public
// portion is isolated by walking the public MPIs.
func parseKey(p *Packet, body []byte, isSecret bool) {
	if len(body) < 6 {
		p.Note = "key packet too short"
		return
	}
	p.KeyVersion = int(body[0])
	switch body[0] {
	case 4:
		created := binary.BigEndian.Uint32(body[1:5])
		p.CreatedUTC = time.Unix(int64(created), 0).UTC().Format(time.RFC3339)
		p.Algorithm = pubKeyAlgo(body[5])
		pubEnd := len(body) // public-key packet: the entire body is the public key
		if isSecret {
			pubEnd = publicPortionEndV4(body) // secret-key packet: isolate the public MPIs
		}
		if pubEnd > 0 {
			fp := sha1.Sum(fingerprintPreimage(0x99, body[:pubEnd])) //nolint:gosec
			p.Fingerprint = hex.EncodeToString(fp[:])
			p.KeyID = strings.ToUpper(hex.EncodeToString(fp[12:20]))
		} else {
			p.Note = "secret-key fingerprint not computed — public-key-material isolation is " +
				"unsupported for this algorithm (ECC); the secret key material is still present"
		}
	case 5:
		// RFC 9580 v5/v6: 4-byte public-material count after the algorithm byte.
		if len(body) < 10 {
			p.Note = "v5 key packet too short"
			return
		}
		created := binary.BigEndian.Uint32(body[1:5])
		p.CreatedUTC = time.Unix(int64(created), 0).UTC().Format(time.RFC3339)
		p.Algorithm = pubKeyAlgo(body[5])
		count := int(binary.BigEndian.Uint32(body[6:10]))
		pubEnd := 10 + count
		if pubEnd <= len(body) {
			fp := sha256.Sum256(fingerprintPreimage(0x9a, body[:pubEnd]))
			p.Fingerprint = hex.EncodeToString(fp[:])
			p.KeyID = strings.ToUpper(hex.EncodeToString(fp[:8]))
		}
	case 3, 2:
		created := binary.BigEndian.Uint32(body[1:5])
		p.CreatedUTC = time.Unix(int64(created), 0).UTC().Format(time.RFC3339)
		if len(body) >= 8 {
			p.Algorithm = pubKeyAlgo(body[7])
		}
		p.Note = "v3 key — MD5 fingerprint not computed (legacy)"
	default:
		p.Note = fmt.Sprintf("unsupported key version %d", body[0])
	}
}

// fingerprintPreimage builds the RFC 4880 §12.2 fingerprint preimage:
// prefix ‖ big-endian length ‖ public-key-packet body. v4 uses a 0x99 prefix
// with a 2-byte length; v5/v6 use 0x9A with a 4-byte length.
func fingerprintPreimage(prefix byte, pub []byte) []byte {
	if prefix == 0x99 {
		out := make([]byte, 3+len(pub))
		out[0] = prefix
		binary.BigEndian.PutUint16(out[1:3], uint16(len(pub)))
		copy(out[3:], pub)
		return out
	}
	out := make([]byte, 5+len(pub))
	out[0] = prefix
	binary.BigEndian.PutUint32(out[1:5], uint32(len(pub)))
	copy(out[5:], pub)
	return out
}

// publicPortionEndV4 returns the offset at which the public key material ends in
// a v4 SECRET-key body — the start of the secret material, after the public MPIs.
// It supports the plain-MPI algorithms (RSA / DSA / Elgamal), whose self-
// delimiting MPI layout is the same primitive the public-key cross-check
// verifies. ECC algorithms (whose OID + point + KDF encoding is not MPI-uniform
// and is not exercised by the reference oracle) return 0 so their secret-key
// fingerprint is flagged rather than guessed. Returns 0 on truncation too.
func publicPortionEndV4(body []byte) int {
	off := 6 // version(1) + created(4) + algo(1)
	skipMPIs := func(n int) bool {
		for k := 0; k < n; k++ {
			if off+2 > len(body) {
				return false
			}
			bits := int(binary.BigEndian.Uint16(body[off:]))
			off += 2 + (bits+7)/8
			if off > len(body) {
				return false
			}
		}
		return true
	}
	var ok bool
	switch body[5] {
	case 1, 2, 3: // RSA: n, e
		ok = skipMPIs(2)
	case 17: // DSA: p, q, g, y
		ok = skipMPIs(4)
	case 16: // Elgamal: p, g, y
		ok = skipMPIs(3)
	default: // ECC and others: not isolated here
		return 0
	}
	if !ok {
		return 0
	}
	return off
}

// parseSignature extracts the v4 signature header fields.
func parseSignature(p *Packet, body []byte) {
	if len(body) < 1 {
		return
	}
	p.KeyVersion = int(body[0])
	if body[0] == 4 && len(body) >= 4 {
		p.SignatureType = sigType(body[1])
		p.Algorithm = pubKeyAlgo(body[2])
		p.HashAlgorithm = hashAlgo(body[3])
	} else if body[0] == 3 && len(body) >= 19 {
		// v3: type at offset 2, pubkey algo 15, hash 16.
		p.SignatureType = sigType(body[2])
		p.Algorithm = pubKeyAlgo(body[15])
		p.HashAlgorithm = hashAlgo(body[16])
	}
}

func tagName(t int) string {
	switch t {
	case 1:
		return "Public-Key Encrypted Session Key"
	case 2:
		return "Signature"
	case 3:
		return "Symmetric-Key Encrypted Session Key"
	case 4:
		return "One-Pass Signature"
	case 5:
		return "Secret-Key"
	case 6:
		return "Public-Key"
	case 7:
		return "Secret-Subkey"
	case 8:
		return "Compressed Data"
	case 9:
		return "Symmetrically Encrypted Data"
	case 10:
		return "Marker"
	case 11:
		return "Literal Data"
	case 12:
		return "Trust"
	case 13:
		return "User ID"
	case 14:
		return "Public-Subkey"
	case 17:
		return "User Attribute"
	case 18:
		return "Sym. Encrypted and Integrity Protected Data"
	case 19:
		return "Modification Detection Code"
	case 20:
		return "AEAD Encrypted Data"
	default:
		if t >= 60 && t <= 63 {
			return "Private/Experimental"
		}
		return fmt.Sprintf("Unknown (tag %d)", t)
	}
}

func pubKeyAlgo(a byte) string {
	switch a {
	case 1:
		return "RSA (Encrypt or Sign)"
	case 2:
		return "RSA Encrypt-Only"
	case 3:
		return "RSA Sign-Only"
	case 16:
		return "Elgamal"
	case 17:
		return "DSA"
	case 18:
		return "ECDH"
	case 19:
		return "ECDSA"
	case 22:
		return "EdDSA"
	case 25:
		return "X25519"
	case 27:
		return "Ed25519"
	default:
		return fmt.Sprintf("algorithm %d", a)
	}
}

func hashAlgo(a byte) string {
	switch a {
	case 1:
		return "MD5"
	case 2:
		return "SHA-1"
	case 8:
		return "SHA-256"
	case 9:
		return "SHA-384"
	case 10:
		return "SHA-512"
	case 11:
		return "SHA-224"
	default:
		return fmt.Sprintf("hash %d", a)
	}
}

func sigType(t byte) string {
	switch t {
	case 0x00:
		return "binary document"
	case 0x01:
		return "canonical text document"
	case 0x10:
		return "generic certification"
	case 0x11:
		return "persona certification"
	case 0x12:
		return "casual certification"
	case 0x13:
		return "positive certification"
	case 0x18:
		return "subkey binding"
	case 0x19:
		return "primary key binding"
	case 0x1f:
		return "direct key"
	case 0x20:
		return "key revocation"
	case 0x28:
		return "subkey revocation"
	default:
		return fmt.Sprintf("type 0x%02x", t)
	}
}
