// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ldappw implements the RFC 2307 LDAP userPassword storage schemes
// used by OpenLDAP slapd, 389 Directory Server, Dovecot, and Atlassian Crowd:
// the {SHA}/{SSHA} family plus {MD5}/{SMD5} and the OpenLDAP pw-sha2 / Dovecot
// SHA-2 extensions ({SHA256}/{SSHA256}/{SHA384}/{SSHA384}/{SHA512}/{SSHA512}).
// It is an offline credential primitive: compute the storage string for a
// candidate password, or verify a candidate against a captured userPassword
// value (e.g. from a slapcat dump or a directory-server backup). It complements
// the credential toolkit — hash_identify recognises {SSHA}/{SHA}/{MD5} (hashcat
// modes 111 / 101 / 1001) and hash_crack attacks them, but neither could
// produce or check one. Pure offline compute from operator-supplied strings; no
// network or device.
//
// # Scheme construction
//
// Every scheme is the same shape with no key-stretching: the stored value is
//
//	{SCHEME}base64( H(password ‖ salt) ‖ salt )
//
// where H is the named digest and the salt is empty for the unsalted variants
// ({SHA}, {MD5}, {SHA256}, …) and a trailing run of random bytes for the salted
// variants ({SSHA}, {SMD5}, {SSHA256}, …). Because the digest length is fixed
// per algorithm, verification splits the decoded blob at that boundary: the
// first digestLen bytes are the stored digest, the remainder is the salt, and
// the candidate is accepted iff H(password ‖ salt) equals the stored digest
// (constant-time). The salt length is therefore recovered from the blob, not
// assumed — slapd defaults to 4 bytes, Dovecot to longer, and both verify here.
//
// # Wrap-vs-native judgement
//
// Native. These schemes are a digest (crypto/{md5,sha1,sha256,sha512}) plus
// encoding/base64 — there is nothing to wrap; the only third-party option would
// be a cgo crypt(3) binding or an LDAP client library, neither warranted for a
// pure hash-and-encode. Consistent with internal/unixcrypt, internal/nthash,
// and internal/wpa, the crypto is owned in-tree.
//
// # Verifiable / no confidently-wrong output
//
// Strongest verification class — the construction is unambiguous (a single
// digest + base64, no rounds, no scrambling), so a wrong output cannot hide.
// {SHA} compute is gated byte-for-byte against the OpenLDAP `slappasswd -h
// {SHA}` oracle; {SSHA}/{SMD5} round-trip against slappasswd-produced values
// (variable-length salt recovered from the blob); the SHA-2 variants are gated
// against the definitional digest+base64 vectors (the exact pw-sha2 / Dovecot
// construction). Out of scope: {CRYPT} (RFC 2307 delegates it to crypt(3) —
// already covered by md5crypt / sha_crypt / bcrypt) and {CLEARTEXT}.
package ldappw

import (
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // LDAP {MD5}/{SMD5} schemes are MD5 by definition.
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // LDAP {SHA}/{SSHA} schemes are SHA-1 by definition.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"strings"
)

// scheme describes one RFC 2307 / pw-sha2 userPassword scheme.
type scheme struct {
	prefix    string // canonical "{SCHEME}" tag, uppercased
	newHash   func() hash.Hash
	digestLen int
	salted    bool
}

// schemes is the supported set, keyed by uppercased prefix (without braces).
var schemes = map[string]scheme{ //nolint:gochecknoglobals // immutable lookup table
	"MD5":     {"{MD5}", md5.New, md5.Size, false},
	"SMD5":    {"{SMD5}", md5.New, md5.Size, true},
	"SHA":     {"{SHA}", sha1.New, sha1.Size, false},
	"SSHA":    {"{SSHA}", sha1.New, sha1.Size, true},
	"SHA256":  {"{SHA256}", sha256.New, sha256.Size, false},
	"SSHA256": {"{SSHA256}", sha256.New, sha256.Size, true},
	"SHA384":  {"{SHA384}", sha512.New384, sha512.Size384, false},
	"SSHA384": {"{SSHA384}", sha512.New384, sha512.Size384, true},
	"SHA512":  {"{SHA512}", sha512.New, sha512.Size, false},
	"SSHA512": {"{SSHA512}", sha512.New, sha512.Size, true},
}

// Schemes returns the canonical scheme tags this package supports, for tool
// help / enum surfaces. Order is stable (unsalted then salted, weakest first).
func Schemes() []string {
	return []string{
		"{MD5}", "{SMD5}", "{SHA}", "{SSHA}",
		"{SHA256}", "{SSHA256}", "{SHA384}", "{SSHA384}",
		"{SHA512}", "{SSHA512}",
	}
}

// normaliseScheme maps an operator-supplied scheme name ("ssha", "{SSHA}",
// "SSHA512", …) to a canonical key in the schemes table.
func normaliseScheme(s string) (scheme, string, error) {
	key := strings.ToUpper(strings.TrimSpace(s))
	key = strings.TrimPrefix(key, "{")
	key = strings.TrimSuffix(key, "}")
	sc, ok := schemes[key]
	if !ok {
		return scheme{}, "", fmt.Errorf("unsupported LDAP scheme %q (supported: %s)",
			s, strings.Join(Schemes(), " "))
	}
	return sc, key, nil
}

// Compute returns the {SCHEME}base64(...) userPassword string for the given
// password. For a salted scheme an explicit salt is used verbatim; if salt is
// empty a 4-byte random salt is generated (matching slappasswd's default). For
// an unsalted scheme a non-empty salt is rejected.
func Compute(schemeName, password, salt string) (string, error) {
	sc, _, err := normaliseScheme(schemeName)
	if err != nil {
		return "", err
	}
	saltBytes := []byte(salt)
	switch {
	case !sc.salted && len(saltBytes) > 0:
		return "", fmt.Errorf("scheme %s is unsalted; do not supply a salt", sc.prefix)
	case sc.salted && len(saltBytes) == 0:
		saltBytes, err = randomBytes(4)
		if err != nil {
			return "", err
		}
	}
	return sc.prefix + encode(sc, []byte(password), saltBytes), nil
}

// encode computes H(password ‖ salt) ‖ salt and base64-encodes it.
func encode(sc scheme, password, salt []byte) string {
	h := sc.newHash()
	h.Write(password)
	h.Write(salt)
	blob := h.Sum(nil)
	blob = append(blob, salt...)
	return base64.StdEncoding.EncodeToString(blob)
}

// Result is the outcome of verifying a candidate password against a stored
// userPassword value.
type Result struct {
	Scheme  string `json:"scheme"`
	Salted  bool   `json:"salted"`
	SaltLen int    `json:"salt_len"`
	Matched bool   `json:"matched"`
}

// Verify checks a candidate password against a stored {SCHEME}base64(...)
// userPassword value. It returns the detected scheme and whether the candidate
// matches (constant-time digest comparison).
func Verify(password, stored string) (*Result, error) {
	stored = strings.TrimSpace(stored)
	if !strings.HasPrefix(stored, "{") {
		return nil, fmt.Errorf("not an LDAP userPassword value (no {SCHEME} prefix)")
	}
	end := strings.Index(stored, "}")
	if end < 0 {
		return nil, fmt.Errorf("malformed scheme prefix (missing '}')")
	}
	sc, _, err := normaliseScheme(stored[1:end])
	if err != nil {
		return nil, err
	}
	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(stored[end+1:]))
	if err != nil {
		return nil, fmt.Errorf("scheme %s payload is not valid base64: %w", sc.prefix, err)
	}
	if len(blob) < sc.digestLen {
		return nil, fmt.Errorf("scheme %s payload too short: %d bytes, need >= %d",
			sc.prefix, len(blob), sc.digestLen)
	}
	digest, salt := blob[:sc.digestLen], blob[sc.digestLen:]
	if !sc.salted && len(salt) != 0 {
		return nil, fmt.Errorf("scheme %s is unsalted but payload carries %d trailing bytes",
			sc.prefix, len(salt))
	}
	h := sc.newHash()
	h.Write([]byte(password))
	h.Write(salt)
	want := h.Sum(nil)
	return &Result{
		Scheme:  sc.prefix,
		Salted:  sc.salted,
		SaltLen: len(salt),
		Matched: hmac.Equal(want, digest),
	}, nil
}

// Identify returns the canonical scheme tag of a stored value, or "" if it is
// not a recognised LDAP userPassword scheme.
func Identify(stored string) string {
	stored = strings.TrimSpace(stored)
	end := strings.Index(stored, "}")
	if !strings.HasPrefix(stored, "{") || end < 0 {
		return ""
	}
	sc, _, err := normaliseScheme(stored[1:end])
	if err != nil {
		return ""
	}
	return sc.prefix
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
