// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sshkey parses an OpenSSH private key file (the
// "-----BEGIN OPENSSH PRIVATE KEY-----" / openssh-key-v1 format) for triage. A
// stolen private key (id_ed25519 / id_rsa) is top pentest loot, and the first
// questions are: is it **encrypted** (so it must be cracked — ssh2john →
// hashcat -m 22921 — before use, or used directly if not)? what **key type**?
// what **SHA256 fingerprint** (to correlate the key with an authorized_keys
// entry / a known target identity)? and what **comment** (often user@host)?
// This answers all of those from the key's public portion (always readable,
// even for an encrypted key). Pure offline transform; no network or device.
//
// # Wrap-vs-native judgement
//
// Native. The format is a documented, self-delimited binary blob inside PEM
// base64 (PROTOCOL.key): a "openssh-key-v1\0" magic, then SSH-wire
// length-prefixed strings — ciphername, kdfname, kdfoptions, key count, the
// public-key blob(s), and the (possibly encrypted) private section. It is a
// base64-decode + a length-prefixed walk + a SHA-256; there is nothing to wrap,
// and pulling in golang.org/x/crypto/ssh (which refuses to even parse an
// encrypted key without the passphrase) defeats the triage purpose. Consistent
// with the other in-tree parsers.
//
// # Verifiable / no confidently-wrong output
//
// The cipher / kdf / key-type / fingerprint are anchored to `ssh-keygen`: for a
// generated ed25519 and rsa key (encrypted and not), the parser reproduces
// ssh-keygen -l's exact SHA256 fingerprint + type + encrypted state + the
// comment. A non-openssh-key-v1 blob, or a truncated/over-long length field, is
// rejected. The comment of an encrypted key lives in the encrypted section and
// is correctly reported as unavailable rather than guessed.
package sshkey

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
)

// Result is the triage view of an OpenSSH private key file.
type Result struct {
	Format     string    `json:"format"`
	Cipher     string    `json:"cipher"`
	Encrypted  bool      `json:"encrypted"`
	KDF        string    `json:"kdf"`
	KDFRounds  int       `json:"kdf_rounds,omitempty"`
	KDFSaltLen int       `json:"kdf_salt_len,omitempty"`
	NumKeys    int       `json:"num_keys"`
	Keys       []*PubKey `json:"keys"`
	Comment    string    `json:"comment,omitempty"`
	Note       string    `json:"note,omitempty"`
}

// PubKey is one public key carried in the file.
type PubKey struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"` // SHA256:... (as `ssh-keygen -l` prints)
}

const magic = "openssh-key-v1\x00"

// Decode parses an OpenSSH private key (the full PEM, or just its base64 body).
func Decode(in string) (*Result, error) {
	b64 := stripArmor(in)
	if b64 == "" {
		return nil, fmt.Errorf("sshkey: empty input")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("sshkey: body is not valid base64: %w", err)
		}
	}
	if len(raw) < len(magic) || string(raw[:len(magic)]) != magic {
		return nil, fmt.Errorf("sshkey: not an openssh-key-v1 private key (bad magic)")
	}
	c := &cursor{b: raw, pos: len(magic)}

	cipher, err := c.str()
	if err != nil {
		return nil, fmt.Errorf("sshkey: ciphername: %w", err)
	}
	kdf, err := c.str()
	if err != nil {
		return nil, fmt.Errorf("sshkey: kdfname: %w", err)
	}
	kdfOpts, err := c.str()
	if err != nil {
		return nil, fmt.Errorf("sshkey: kdfoptions: %w", err)
	}
	numKeys, err := c.u32()
	if err != nil {
		return nil, fmt.Errorf("sshkey: key count: %w", err)
	}
	if numKeys == 0 || numKeys > 256 {
		return nil, fmt.Errorf("sshkey: implausible key count %d", numKeys)
	}

	r := &Result{
		Format: "openssh-key-v1", Cipher: string(cipher), KDF: string(kdf),
		Encrypted: string(cipher) != "none", NumKeys: int(numKeys),
	}
	if string(kdf) == "bcrypt" {
		if salt, rounds, ok := parseBcryptKDF(kdfOpts); ok {
			r.KDFSaltLen = len(salt)
			r.KDFRounds = rounds
		}
	}
	for i := uint32(0); i < numKeys; i++ {
		blob, err := c.str()
		if err != nil {
			return nil, fmt.Errorf("sshkey: public key %d: %w", i, err)
		}
		r.Keys = append(r.Keys, pubKey(blob))
	}
	priv, err := c.str()
	if err != nil {
		return nil, fmt.Errorf("sshkey: private section: %w", err)
	}

	if r.Encrypted {
		r.Note = fmt.Sprintf("encrypted (%s / %s) — crack the passphrase with ssh2john + hashcat -m 22921 before use; the comment is in the encrypted section", r.Cipher, r.KDF)
	} else {
		r.Comment = extractComment(priv)
		r.Note = "unencrypted — the private key is directly usable (no cracking needed)"
	}
	return r, nil
}

// pubKey parses a public-key blob: its first SSH string is the key type; the
// SHA256 fingerprint is base64(sha256(blob)) without padding, as ssh-keygen -l
// prints it.
func pubKey(blob []byte) *PubKey {
	pk := &PubKey{Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sha256Sum(blob))}
	bc := &cursor{b: blob}
	if t, err := bc.str(); err == nil {
		pk.Type = string(t)
	}
	return pk
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// parseBcryptKDF decodes a bcrypt kdfoptions string: string salt + uint32 rounds.
func parseBcryptKDF(opts []byte) (salt []byte, rounds int, ok bool) {
	c := &cursor{b: opts}
	s, err := c.str()
	if err != nil {
		return nil, 0, false
	}
	rds, err := c.u32()
	if err != nil {
		return nil, 0, false
	}
	return s, int(rds), true
}

// extractComment pulls the comment from an UNENCRYPTED private section. The
// section is check1(4) ‖ check2(4), then per key the type + private fields +
// comment (all SSH strings), then index padding (1,2,3,…). Walking the
// length-prefixed fields, the last one before the padding is the comment.
func extractComment(priv []byte) string {
	if len(priv) < 8 {
		return ""
	}
	c := &cursor{b: priv, pos: 8} // skip check1/check2
	last := ""
	for c.remaining() >= 4 {
		f, err := c.str()
		if err != nil {
			break
		}
		last = string(f)
		if isPadding(priv[c.pos:]) {
			return last
		}
	}
	return last
}

// isPadding reports whether b is the OpenSSH index padding (byte i == i+1), or
// empty.
func isPadding(b []byte) bool {
	for i, v := range b {
		if v != byte((i+1)&0xff) {
			return false
		}
	}
	return true
}

// stripArmor removes the PEM header/footer lines and whitespace, returning the
// base64 body.
func stripArmor(s string) string {
	var sb strings.Builder
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		sb.WriteString(line)
	}
	return sb.String()
}

// cursor is a bounds-checked SSH-wire reader (big-endian, uint32-length strings).
type cursor struct {
	b   []byte
	pos int
}

func (c *cursor) remaining() int { return len(c.b) - c.pos }

func (c *cursor) u32() (uint32, error) {
	if c.pos+4 > len(c.b) {
		return 0, fmt.Errorf("truncated (need 4 bytes at offset %d)", c.pos)
	}
	v := binary.BigEndian.Uint32(c.b[c.pos:])
	c.pos += 4
	return v, nil
}

// str reads a uint32-length-prefixed byte string.
func (c *cursor) str() ([]byte, error) {
	n, err := c.u32()
	if err != nil {
		return nil, err
	}
	if int(n) < 0 || c.pos+int(n) > len(c.b) {
		return nil, fmt.Errorf("string length %d overruns buffer at offset %d", n, c.pos)
	}
	s := c.b[c.pos : c.pos+int(n)]
	c.pos += int(n)
	return s, nil
}
