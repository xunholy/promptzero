// Package rcloneconfig extracts cloud-remote credentials from an rclone
// configuration file (rclone.conf).
//
// rclone is the ubiquitous "rsync for cloud storage" tool, and its config is
// common loot on a backup / sync / CI host: each [remote] section holds the
// credentials for an S3 bucket, a Google Drive, an SFTP server, a WebDAV share,
// and so on. The high-value, uniquely recoverable part is rclone's "obscured"
// passwords: rclone does not store these in plaintext, but it does not encrypt
// them with a user secret either — it "obscures" them with AES-256-CTR under a
// single hardcoded key (rclone fs/config/obscure/obscure.go), explicitly NOT a
// security measure (per rclone's own docs). They are therefore fully reversible
// offline. This reveals them, and surfaces the plaintext secrets (S3 keys, OAuth
// tokens) the config holds verbatim.
//
// No confidently-wrong output: a password field is revealed only when its value
// is a valid rclone-obscure blob (RawURL-base64 of IV+ciphertext, ≥ one AES
// block) that decodes to printable UTF-8; a value that does not decode, or
// decodes to non-printable bytes, is reported as plaintext / unrevealable with
// the raw value surfaced — never a garbage "password". Input that is not an
// rclone config (no [section] with config keys) is rejected.
//
// Wrap-vs-native: native — an INI scanner plus the exact rclone Reveal transform
// (crypto/aes + crypto/cipher, stdlib only, no new go.mod dependency). The key
// and algorithm are taken verbatim from rclone fs/config/obscure/obscure.go and
// anchored to rclone's own published reveal vectors (see the package test).
package rcloneconfig

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf8"
)

// cryptKey is rclone's hardcoded AES-256 obscure key, copied verbatim from
// rclone fs/config/obscure/obscure.go. It is a fixed constant in every rclone
// build — "obscuring" is obfuscation, not encryption, so the same key reveals
// every obscured password on every host.
var cryptKey = []byte{ //nolint:gochecknoglobals
	0x9c, 0x93, 0x5b, 0x48, 0x73, 0x0a, 0x55, 0x4d,
	0x6b, 0xfd, 0x7c, 0x63, 0xc8, 0x86, 0xa9, 0x2b,
	0xd3, 0x90, 0x19, 0x8e, 0xb8, 0x12, 0x8a, 0xfb,
	0xf4, 0xde, 0x16, 0x2b, 0x8b, 0x95, 0xf6, 0x38,
}

// Reveal reverses rclone's Obscure: it RawURL-base64-decodes the input into a
// 16-byte IV followed by AES-256-CTR ciphertext, then decrypts under the
// hardcoded key. It mirrors rclone's obscure.Reveal exactly, including the
// "input too short" guard. It does not judge whether the plaintext is sensible
// (that is the caller's job) — only that the structure is a valid obscure blob.
func Reveal(obscured string) (string, error) {
	ct, err := base64.RawURLEncoding.DecodeString(obscured)
	if err != nil {
		return "", fmt.Errorf("rcloneconfig: not a valid obscure blob (base64): %w", err)
	}
	if len(ct) < aes.BlockSize {
		return "", fmt.Errorf("rcloneconfig: obscure blob too short (%d < %d bytes)", len(ct), aes.BlockSize)
	}
	block, err := aes.NewCipher(cryptKey)
	if err != nil {
		return "", fmt.Errorf("rcloneconfig: aes: %w", err)
	}
	iv := ct[:aes.BlockSize]
	buf := ct[aes.BlockSize:]
	out := make([]byte, len(buf))
	cipher.NewCTR(block, iv).XORKeyStream(out, buf)
	return string(out), nil
}

// Kind classifies a recovered credential field.
const (
	// KindRevealedPassword is an rclone-obscured password successfully revealed
	// to printable plaintext (the operator can use it directly).
	KindRevealedPassword = "revealed-password"
	// KindPlaintextSecret is a field stored in the clear in the config (S3 keys,
	// OAuth tokens, …) or a password field that is not actually obscured.
	KindPlaintextSecret = "plaintext-secret"
	// KindObscuredUnrevealable is a known password field whose value decodes to
	// non-printable bytes — surfaced raw, with no plaintext claimed.
	KindObscuredUnrevealable = "obscured-unrevealable"
)

// Cred is one recovered credential from a remote.
type Cred struct {
	Field string `json:"field"`
	Kind  string `json:"kind"`
	// Value is the usable credential: the revealed plaintext for a
	// revealed-password, or the verbatim value for a plaintext-secret. Empty for
	// an obscured-unrevealable field (see Obscured).
	Value string `json:"value,omitempty"`
	// Obscured is the raw rclone-obscure blob, set when the field is an obscured
	// password (whether or not the reveal produced printable plaintext).
	Obscured string `json:"obscured,omitempty"`
	Note     string `json:"note,omitempty"`
}

// Remote is one [section] of the rclone config.
type Remote struct {
	Name        string `json:"name"`
	Type        string `json:"type,omitempty"`
	Credentials []Cred `json:"credentials,omitempty"`
}

// Result is the decoded rclone config.
type Result struct {
	Format        string   `json:"format"`
	Remotes       []Remote `json:"remotes"`
	HasCredential bool     `json:"has_credential"`
	Note          string   `json:"note"`
}

// obscuredFields are the rclone backend keys declared IsPassword (obscured with
// the hardcoded key): the SFTP/FTP/WebDAV/SMB `pass`, and the crypt `password` /
// `password2`. These are the values Reveal applies to.
var obscuredFields = map[string]bool{ //nolint:gochecknoglobals
	"pass":      true,
	"password":  true,
	"password2": true,
}

// plaintextSecretFields are config keys whose values are sensitive but stored in
// the clear (no obscure) — surfaced verbatim as loot.
var plaintextSecretFields = map[string]bool{ //nolint:gochecknoglobals
	"access_key_id":     true,
	"secret_access_key": true,
	"token":             true,
	"client_id":         true,
	"client_secret":     true,
	"sas_url":           true,
	"key":               true,
	"account":           true,
}

// Decode parses an rclone config and recovers each remote's credentials.
func Decode(input string) (*Result, error) {
	res := &Result{Format: "rclone-config"}

	var cur *Remote
	sawKey := false
	for _, raw := range strings.Split(input, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.TrimSpace(line[1 : len(line)-1])
			res.Remotes = append(res.Remotes, Remote{Name: name})
			cur = &res.Remotes[len(res.Remotes)-1]
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 || cur == nil {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if key == "" {
			continue
		}
		sawKey = true

		switch {
		case key == "type":
			cur.Type = val
		case obscuredFields[key]:
			cur.Credentials = append(cur.Credentials, classifyObscured(key, val))
			res.HasCredential = true
		case plaintextSecretFields[key] && val != "":
			cur.Credentials = append(cur.Credentials, Cred{Field: key, Kind: KindPlaintextSecret, Value: val})
			res.HasCredential = true
		}
	}

	// An rclone config is a set of [section]s with key=value bodies; reject input
	// that has no recognised structure rather than returning an empty shell.
	if len(res.Remotes) == 0 || !sawKey {
		return nil, fmt.Errorf("rcloneconfig: not an rclone config (no [section] with config keys)")
	}

	if res.HasCredential {
		res.Note = "rclone obscured passwords are reversible offline (a fixed AES key, not encryption) — " +
			"revealed values are usable directly. Plaintext secrets (S3 keys, OAuth tokens) are surfaced verbatim. " +
			"Offline; no network, no device."
	} else {
		res.Note = "Parsed as an rclone config, but no obscured-password or known plaintext-secret fields were found."
	}
	return res, nil
}

// classifyObscured reveals an obscured-password field, downgrading honestly when
// the value is not a usable obscure blob (so a hand-edited plaintext password,
// or a non-printable decode, is never presented as a recovered password).
func classifyObscured(field, val string) Cred {
	plain, err := Reveal(val)
	switch {
	case err != nil:
		// Not a valid obscure blob — most likely a plaintext password.
		return Cred{
			Field: field, Kind: KindPlaintextSecret, Value: val,
			Note: "not rclone-obscured (reveal failed) — surfaced as plaintext",
		}
	case !isPrintable(plain):
		// Decodes, but to bytes that are not a plausible password.
		return Cred{
			Field: field, Kind: KindObscuredUnrevealable, Obscured: val,
			Note: "decoded to non-printable bytes — may be plaintext rather than rclone-obscured; raw value surfaced",
		}
	default:
		return Cred{Field: field, Kind: KindRevealedPassword, Value: plain, Obscured: val}
	}
}

// isPrintable reports whether s is valid UTF-8 with no control characters
// (tab/newline included as control) — the printability bar for a revealed
// password to be trusted as such.
func isPrintable(s string) bool {
	if s == "" || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
