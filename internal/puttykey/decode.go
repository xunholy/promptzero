// SPDX-License-Identifier: AGPL-3.0-or-later

// Package puttykey parses a PuTTY private key file (the ".ppk" /
// "PuTTY-User-Key-File-N" format) for triage. A saved PuTTY / WinSCP / FileZilla
// key is the Windows counterpart to a stolen id_ed25519 — top pentest loot — and
// the first questions are the same as for an OpenSSH key (see internal/sshkey):
// is it **encrypted** (so the passphrase must be cracked — putty2john + John the
// Ripper — before use)? what **key type**? what **SHA256 fingerprint** (to
// correlate the key with an authorized_keys entry / a known target identity)?
// and what **comment**? Unlike OpenSSH, a PPK's comment is a cleartext header so
// it is readable even for an encrypted key. Pure offline transform; no network
// or device.
//
// # Wrap-vs-native judgement
//
// Native. The .ppk format is a simple line-based text container (RFC-822-style
// "Key: value" headers wrapping two base64 blocks), documented in the PuTTY
// manual appendix. The public block is base64 of the **same SSH-wire public
// blob** that goes in an authorized_keys line, so the type + fingerprint are a
// base64-decode + a length-prefixed read + a SHA-256 — there is nothing to wrap.
// Pulling in a third-party PPK library (none is in go.mod) would add a runtime
// dep for what is a few dozen lines of text parsing. Consistent with the other
// in-tree key/loot parsers.
//
// # Verifiable / no confidently-wrong output
//
// The key-type + fingerprint are cross-validated against `ssh-keygen`: a PPK's
// Public-Lines base64 is byte-for-byte the same SSH-wire blob as the matching
// OpenSSH .pub, so SHA256(blob) reproduces `ssh-keygen -l`'s exact SHA256
// fingerprint (confirmed for a generated ed25519 and rsa key). The header fields
// (version, Encryption, Comment, Key-Derivation, Argon2-*, Private-MAC) are
// plain-text reads against the documented PuTTY AppendixC format — no transform
// that could be confidently wrong. The Private-Lines section (PuTTY's own
// private-key layout) and the Private-MAC are surfaced/raw, not decoded or
// verified: MAC verification needs the passphrase-derived key, and a wrong
// "valid/invalid" verdict would be worse than none. A blob that does not begin
// with the PuTTY-User-Key-File- magic, or whose public block is missing /
// undecodable, is rejected.
package puttykey

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Result is the triage view of a PuTTY .ppk private key file.
type Result struct {
	Format            string `json:"format"`     // always "ppk"
	Version           int    `json:"version"`    // 1, 2, or 3
	Algorithm         string `json:"algorithm"`  // from the header line, e.g. ssh-ed25519
	Encryption        string `json:"encryption"` // none / aes256-cbc
	Encrypted         bool   `json:"encrypted"`
	KeyType           string `json:"key_type"`    // from the public blob (should match algorithm)
	Fingerprint       string `json:"fingerprint"` // SHA256:... (as `ssh-keygen -l` prints)
	Comment           string `json:"comment,omitempty"`
	KeyDerivation     string `json:"key_derivation,omitempty"` // Argon2id / Argon2i / Argon2d (v3 encrypted)
	Argon2Memory      int    `json:"argon2_memory_kb,omitempty"`
	Argon2Passes      int    `json:"argon2_passes,omitempty"`
	Argon2Parallelism int    `json:"argon2_parallelism,omitempty"`
	Argon2SaltLen     int    `json:"argon2_salt_len,omitempty"`
	PrivateMAC        string `json:"private_mac,omitempty"`
	Note              string `json:"note,omitempty"`
}

const magicPrefix = "PuTTY-User-Key-File-"

// Decode parses a PuTTY .ppk private key file.
func Decode(in string) (*Result, error) {
	lines := splitLines(in)
	// Find the first non-empty line — it must be the magic header.
	start := 0
	for start < len(lines) && strings.TrimSpace(lines[start]) == "" {
		start++
	}
	if start >= len(lines) {
		return nil, fmt.Errorf("puttykey: empty input")
	}
	k0, v0, ok := splitHeader(lines[start])
	if !ok || !strings.HasPrefix(k0, magicPrefix) {
		return nil, fmt.Errorf("puttykey: not a PuTTY key file (missing %sN header)", magicPrefix)
	}
	ver, err := strconv.Atoi(strings.TrimPrefix(k0, magicPrefix))
	if err != nil || ver < 1 || ver > 3 {
		return nil, fmt.Errorf("puttykey: unsupported PPK version %q", strings.TrimPrefix(k0, magicPrefix))
	}

	r := &Result{Format: "ppk", Version: ver, Algorithm: strings.TrimSpace(v0)}

	var pubB64 strings.Builder
	for i := start + 1; i < len(lines); i++ {
		line := lines[i]
		if strings.TrimSpace(line) == "" {
			continue
		}
		key, val, ok := splitHeader(line)
		if !ok {
			// A non-header, non-blob stray line: ignore rather than crash.
			continue
		}
		switch key {
		case "Encryption":
			r.Encryption = val
		case "Comment":
			r.Comment = val
		case "Key-Derivation":
			r.KeyDerivation = val
		case "Argon2-Memory":
			r.Argon2Memory = atoiSafe(val)
		case "Argon2-Passes":
			r.Argon2Passes = atoiSafe(val)
		case "Argon2-Parallelism":
			r.Argon2Parallelism = atoiSafe(val)
		case "Argon2-Salt":
			if b, ok := hexLen(val); ok {
				r.Argon2SaltLen = b
			}
		case "Private-MAC":
			r.PrivateMAC = strings.TrimSpace(val)
		case "Public-Lines":
			body, next, err := readBlock(lines, i, val)
			if err != nil {
				return nil, fmt.Errorf("puttykey: public block: %w", err)
			}
			pubB64.WriteString(body)
			i = next
		case "Private-Lines":
			// The private section is PuTTY's own layout (and is encrypted when a
			// passphrase is set). We do not decode it — skip its lines.
			_, next, err := readBlock(lines, i, val)
			if err != nil {
				return nil, fmt.Errorf("puttykey: private block: %w", err)
			}
			i = next
		}
	}

	if pubB64.Len() == 0 {
		return nil, fmt.Errorf("puttykey: no Public-Lines block")
	}
	blob, err := base64.StdEncoding.DecodeString(pubB64.String())
	if err != nil {
		return nil, fmt.Errorf("puttykey: public block is not valid base64: %w", err)
	}
	r.KeyType = firstSSHString(blob)
	r.Fingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(sha256Sum(blob))

	r.Encrypted = r.Encryption != "" && r.Encryption != "none"
	if r.Encrypted {
		kdf := r.KeyDerivation
		if kdf == "" {
			kdf = "PPK-v2 HMAC-SHA-1 derived" // v2 has no Key-Derivation header
		}
		r.Note = fmt.Sprintf("encrypted (%s / %s) — crack the passphrase with putty2john + John the Ripper before use. "+
			"The comment + public key are cleartext headers (already shown); the Private-Lines section is encrypted.",
			r.Encryption, kdf)
	} else {
		r.Note = "unencrypted — the Private-Lines section is in cleartext, so the private key is directly usable (no cracking needed)."
	}
	return r, nil
}

// readBlock reads the N base64 lines following a "Foo-Lines: N" header at index
// hdr. It returns the joined base64 body and the index of the last consumed
// line (so the caller's loop advances past the block).
func readBlock(lines []string, hdr int, count string) (body string, last int, err error) {
	n, e := strconv.Atoi(strings.TrimSpace(count))
	if e != nil || n < 0 || n > 100000 {
		return "", hdr, fmt.Errorf("bad line count %q", count)
	}
	if hdr+n >= len(lines) {
		return "", hdr, fmt.Errorf("declares %d lines but only %d follow", n, len(lines)-hdr-1)
	}
	var sb strings.Builder
	for j := 1; j <= n; j++ {
		sb.WriteString(strings.TrimSpace(lines[hdr+j]))
	}
	return sb.String(), hdr + n, nil
}

// firstSSHString reads the first SSH-wire string (uint32 length + bytes) from a
// public-key blob — its key type, e.g. "ssh-ed25519".
func firstSSHString(blob []byte) string {
	if len(blob) < 4 {
		return ""
	}
	n := binary.BigEndian.Uint32(blob)
	if int(n) < 0 || 4+int(n) > len(blob) {
		return ""
	}
	return string(blob[4 : 4+int(n)])
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// splitHeader splits a "Key: value" line. The value keeps internal spaces but is
// trimmed of the leading space after the colon.
func splitHeader(line string) (key, val string, ok bool) {
	idx := strings.IndexByte(line, ':')
	if idx < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:idx])
	val = strings.TrimPrefix(line[idx+1:], " ")
	val = strings.TrimRight(val, "\r")
	return key, val, key != ""
}

// splitLines splits on \n and strips trailing \r (CRLF tolerance).
func splitLines(s string) []string {
	out := strings.Split(s, "\n")
	for i := range out {
		out[i] = strings.TrimRight(out[i], "\r")
	}
	return out
}

func atoiSafe(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}

// hexLen returns the byte length of a hex string, ok=false if it is not valid hex.
func hexLen(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return 0, false
	}
	return len(b), true
}
