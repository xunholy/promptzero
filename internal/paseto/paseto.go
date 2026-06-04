// SPDX-License-Identifier: AGPL-3.0-or-later

// Package paseto decodes (and, for the Ed25519 public variants, verifies) PASETO
// tokens — "Platform-Agnostic Security Tokens", the modern signed/encrypted
// token format positioned as the safer alternative to JWT (no algorithm
// confusion, versioned crypto). It is the PASETO counterpart of jwt_decode for
// the web-token decode stack: an operator pastes a token captured from an
// Authorization header / cookie / API body and gets its structure and — for the
// public (signed, not encrypted) variants — the cleartext claims, without a
// PASETO library. Pure offline transform; no network or device.
//
// A PASETO token is `version.purpose.payload[.footer]` (base64url, unpadded):
//
//   - **public** (signed, NOT encrypted): the payload is the cleartext message
//     followed by a signature, so the claims are recoverable without any key
//     (exactly like jwt_decode reads a JWT body). Signature sizes: v2/v4
//     Ed25519 = 64 bytes, v3 ECDSA P-384 = 96 bytes, v1 RSA-PSS = 256 bytes.
//   - **local** (encrypted): the payload is nonce ‖ ciphertext ‖ tag; without
//     the symmetric key only the structure is visible, so it is surfaced as
//     length + hex with a note (no claims are recoverable).
//
// # Wrap-vs-native judgement
//
// Native. Decoding is base64url + a length split; Ed25519 verification is
// crypto/ed25519 over the PASETO Pre-Authentication Encoding (PAE) — both
// standard library. Adding github.com/o1c-dev/paseto or aidantwoods/go-paseto as
// a runtime dependency to read untrusted tokens is unwarranted, consistent with
// internal/jwtsig and the other in-tree token/crypto packages.
//
// # Verifiable / no confidently-wrong output
//
// Strongest verification class — anchored to the official PASETO test vectors
// (github.com/paseto-standard/test-vectors): v4.public 4-S-1 decodes to its
// exact cleartext claims and Verify returns true with its published public key
// (and false for a tampered token); 4-S-2's footer decodes; the v4.local 4-E-1
// payload is surfaced encrypted, never guessed. A malformed token (wrong part
// count, bad base64url, payload shorter than the signature) is rejected with an
// error.
//
// # Covered / deferred
//
// Covered: structural decode of all four versions (v1–v4) × both purposes, the
// public cleartext message, and Ed25519 signature verification for the v2/v4
// public variants. Deferred: v1 (RSA-PSS) and v3 (ECDSA P-384) signature
// verification (different algorithms; v4 is the current recommendation) and
// local decryption (requires the symmetric key and is out of scope for a decode
// tool).
package paseto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Result is the decoded view of a PASETO token.
type Result struct {
	Version string `json:"version"`
	Purpose string `json:"purpose"`

	// Public (signed) tokens — cleartext message + signature.
	Message      string `json:"message,omitempty"`
	MessageHex   string `json:"message_hex,omitempty"` // set when message is not valid UTF-8
	SignatureHex string `json:"signature_hex,omitempty"`

	// Local (encrypted) tokens — opaque payload.
	EncryptedHex   string `json:"encrypted_payload_hex,omitempty"`
	EncryptedBytes int    `json:"encrypted_payload_bytes,omitempty"`

	Footer    string `json:"footer,omitempty"`
	FooterHex string `json:"footer_hex,omitempty"` // set when footer is not valid UTF-8
	HasFooter bool   `json:"has_footer"`
	Note      string `json:"note,omitempty"`
}

// publicSigSize is the signature length appended to a public token's message,
// by version. 0 marks a version whose public form is not split here.
var publicSigSize = map[string]int{ //nolint:gochecknoglobals // immutable table
	"v1": 256, // RSA-PSS 2048
	"v2": 64,  // Ed25519
	"v3": 96,  // ECDSA P-384 (raw r‖s)
	"v4": 64,  // Ed25519
}

// Decode parses a PASETO token's structure. For public tokens it recovers the
// cleartext message + signature; for local tokens it surfaces the encrypted
// payload (no key, no claims).
func Decode(token string) (*Result, error) {
	version, purpose, payload, footer, err := split(token)
	if err != nil {
		return nil, err
	}
	r := &Result{Version: version, Purpose: purpose}
	if len(footer) > 0 {
		r.HasFooter = true
		setText(footer, &r.Footer, &r.FooterHex)
	}

	switch purpose {
	case "public":
		sigSize, ok := publicSigSize[version]
		if !ok {
			return nil, fmt.Errorf("paseto: unknown version %q", version)
		}
		if len(payload) < sigSize {
			return nil, fmt.Errorf("paseto: %s.public payload (%d bytes) shorter than the %d-byte signature",
				version, len(payload), sigSize)
		}
		msg := payload[:len(payload)-sigSize]
		sig := payload[len(payload)-sigSize:]
		setText(msg, &r.Message, &r.MessageHex)
		r.SignatureHex = hex.EncodeToString(sig)
	case "local":
		r.EncryptedBytes = len(payload)
		r.EncryptedHex = hex.EncodeToString(payload)
		r.Note = fmt.Sprintf("%s.local is encrypted (nonce ‖ ciphertext ‖ tag); decryption requires the symmetric key", version)
	default:
		return nil, fmt.Errorf("paseto: unknown purpose %q (want local or public)", purpose)
	}
	return r, nil
}

// Verify checks an Ed25519 public-token signature (v2 / v4 only) against the
// given hex-encoded 32-byte public key. implicit is the optional implicit
// assertion (v3/v4; pass "" if none). It returns whether the signature is
// valid. Decoding the claims does not require this — Verify is the
// authenticity check.
func Verify(token, publicKeyHex, implicit string) (bool, error) {
	version, purpose, payload, footer, err := split(token)
	if err != nil {
		return false, err
	}
	if purpose != "public" {
		return false, fmt.Errorf("paseto: Verify applies to public tokens, not %s.%s", version, purpose)
	}
	if version != "v2" && version != "v4" {
		return false, fmt.Errorf("paseto: signature verification is supported for v2/v4 (Ed25519), not %s", version)
	}
	key, err := hex.DecodeString(strings.TrimSpace(publicKeyHex))
	if err != nil {
		return false, fmt.Errorf("paseto: public key is not valid hex: %w", err)
	}
	if len(key) != ed25519.PublicKeySize {
		return false, fmt.Errorf("paseto: Ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(key))
	}
	if len(payload) < ed25519.SignatureSize {
		return false, fmt.Errorf("paseto: payload shorter than a signature")
	}
	msg := payload[:len(payload)-ed25519.SignatureSize]
	sig := payload[len(payload)-ed25519.SignatureSize:]
	header := version + ".public."
	m2 := pae([][]byte{[]byte(header), msg, footer, []byte(implicit)})
	return ed25519.Verify(key, m2, sig), nil
}

// split breaks a token into version, purpose, raw payload bytes and raw footer
// bytes, validating the part count and base64url.
func split(token string) (version, purpose string, payload, footer []byte, err error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 && len(parts) != 4 {
		return "", "", nil, nil, fmt.Errorf("paseto: token must have 3 or 4 dot-separated parts, got %d", len(parts))
	}
	version, purpose = parts[0], parts[1]
	if _, ok := publicSigSize[version]; !ok {
		return "", "", nil, nil, fmt.Errorf("paseto: unknown version %q (want v1..v4)", version)
	}
	payload, err = b64.DecodeString(parts[2])
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("paseto: payload is not valid base64url: %w", err)
	}
	if len(parts) == 4 {
		footer, err = b64.DecodeString(parts[3])
		if err != nil {
			return "", "", nil, nil, fmt.Errorf("paseto: footer is not valid base64url: %w", err)
		}
	}
	return version, purpose, payload, footer, nil
}

// pae is the PASETO Pre-Authentication Encoding: LE64(count) followed by, for
// each piece, LE64(len) ‖ piece. The top bit of each LE64 is cleared per spec.
func pae(pieces [][]byte) []byte {
	out := le64(uint64(len(pieces)))
	for _, p := range pieces {
		out = append(out, le64(uint64(len(p)))...)
		out = append(out, p...)
	}
	return out
}

func le64(n uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], n&0x7fffffffffffffff)
	return b[:]
}

var b64 = base64.RawURLEncoding //nolint:gochecknoglobals // immutable codec

// setText renders raw as UTF-8 text when valid, otherwise as hex into hexOut.
func setText(raw []byte, textOut, hexOut *string) {
	if utf8.Valid(raw) {
		*textOut = string(raw)
	} else {
		*hexOut = hex.EncodeToString(raw)
	}
}
