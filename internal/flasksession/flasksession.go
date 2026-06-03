// SPDX-License-Identifier: AGPL-3.0-or-later

// Package flasksession decodes, verifies and forges Flask session cookies (the
// itsdangerous URLSafeTimedSerializer format). It is a web-pentest primitive
// directly parallel to the JWT tooling: a Flask session cookie is signed (not
// encrypted), so its payload is readable by anyone, and an app with a weak or
// leaked SECRET_KEY can be impersonated by forging an arbitrary session — the
// classic flask-unsign attack.
//
// # Wrap-vs-native judgement
//
// Native. The format is base64url segments (payload[.compressed].timestamp.sig)
// signed with HMAC-SHA1 under a key derived as HMAC-SHA1(SECRET_KEY,
// "cookie-session"). It is a few dozen lines over crypto/hmac + crypto/sha1 +
// compress/zlib; there is nothing to wrap.
//
// # Verifiable / no confidently-wrong output
//
// The signing derivation, the timestamp epoch, and the zlib compression were
// confirmed byte-for-byte against the reference itsdangerous library (the
// authoritative implementation) — the unit tests gate decode and verify against
// itsdangerous-produced cookies. The payload is signed-not-encrypted so decode
// asserts nothing secret; verify is constant-time and reports which candidate
// SECRET_KEY (if any) validates, never guessing.
//
// # Covered / deferred
//
// Covered: decode (payload + timestamp, transparently zlib-inflating compressed
// payloads), verify against candidate SECRET_KEYs, and forge (sign an arbitrary
// payload). The TaggedJSONSerializer's type tags ({" b": …} etc.) are surfaced
// as the raw JSON they are rather than expanded.
package flasksession

import (
	"bytes"
	"compress/zlib"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // Flask/itsdangerous sign sessions with HMAC-SHA1; this is the format, not a security choice.
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// DefaultSalt is Flask's SecureCookieSessionInterface salt.
const DefaultSalt = "cookie-session"

// itsdangerousEpoch is the itsdangerous timestamp epoch (2011-01-01 UTC).
const itsdangerousEpoch int64 = 1293840000

// maxInflate caps decompressed payload size to avoid a zlib bomb.
const maxInflate = 4 << 20

// Session is a decoded Flask session cookie.
type Session struct {
	Payload     any    `json:"payload"`
	PayloadJSON string `json:"payload_json"`
	Compressed  bool   `json:"compressed"`
	UnixTime    int64  `json:"unix_time,omitempty"`
	Signature   string `json:"signature"`
}

// split separates a cookie into the signed part (payload[.]timestamp), the
// payload segment, the timestamp segment, and the signature.
func split(cookie string) (signed, payloadSeg, tsSeg, sig string, err error) {
	cookie = strings.TrimSpace(cookie)
	i2 := strings.LastIndexByte(cookie, '.')
	if i2 <= 0 {
		return "", "", "", "", fmt.Errorf("flasksession: no signature segment")
	}
	sig = cookie[i2+1:]
	signed = cookie[:i2]
	i1 := strings.LastIndexByte(signed, '.')
	if i1 < 0 {
		return "", "", "", "", fmt.Errorf("flasksession: no timestamp segment")
	}
	payloadSeg = signed[:i1]
	tsSeg = signed[i1+1:]
	if payloadSeg == "" {
		return "", "", "", "", fmt.Errorf("flasksession: empty payload segment")
	}
	return signed, payloadSeg, tsSeg, sig, nil
}

// Decode parses a Flask session cookie. It does not require the SECRET_KEY
// (the cookie is signed, not encrypted).
func Decode(cookie string) (*Session, error) {
	_, payloadSeg, tsSeg, sig, err := split(cookie)
	if err != nil {
		return nil, err
	}
	raw, compressed, err := decodePayload(payloadSeg)
	if err != nil {
		return nil, err
	}
	s := &Session{PayloadJSON: string(raw), Compressed: compressed, Signature: sig}
	if err := json.Unmarshal(raw, &s.Payload); err != nil {
		return nil, fmt.Errorf("flasksession: payload is not valid JSON: %w", err)
	}
	if ts, ok := decodeTimestamp(tsSeg); ok {
		s.UnixTime = ts
	}
	return s, nil
}

func decodePayload(seg string) ([]byte, bool, error) {
	compressed := false
	if strings.HasPrefix(seg, ".") {
		compressed = true
		seg = seg[1:]
	}
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil, compressed, fmt.Errorf("flasksession: payload is not valid base64url: %w", err)
	}
	if !compressed {
		return b, false, nil
	}
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, true, fmt.Errorf("flasksession: payload zlib header invalid: %w", err)
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, maxInflate))
	if err != nil {
		return nil, true, fmt.Errorf("flasksession: payload zlib inflate failed: %w", err)
	}
	return out, true, nil
}

func decodeTimestamp(seg string) (int64, bool) {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return 0, false
	}
	var v int64
	for _, c := range b { // big-endian, itsdangerous int_to_bytes
		v = v<<8 | int64(c)
	}
	return v + itsdangerousEpoch, true
}

// derivedKey is itsdangerous's key_derivation="hmac": HMAC-SHA1(secret, salt).
func derivedKey(secret, salt string) []byte {
	if salt == "" {
		salt = DefaultSalt
	}
	m := hmac.New(sha1.New, []byte(secret))
	m.Write([]byte(salt))
	return m.Sum(nil)
}

func sign(signed string, secret, salt string) string {
	m := hmac.New(sha1.New, derivedKey(secret, salt))
	m.Write([]byte(signed))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// Verify reports whether the cookie's signature is valid under secret/salt
// (salt "" defaults to Flask's "cookie-session").
func Verify(cookie, secret, salt string) (bool, error) {
	signed, _, _, sig, err := split(cookie)
	if err != nil {
		return false, err
	}
	want := sign(signed, secret, salt)
	return subtle.ConstantTimeCompare([]byte(want), []byte(sig)) == 1, nil
}

// Sign forges a Flask session cookie: it base64url-encodes the (compacted)
// payload JSON, appends the timestamp, and signs with secret/salt. The payload
// is not compressed (an uncompressed cookie is equally valid), so a server with
// this SECRET_KEY will accept it.
func Sign(payloadJSON, secret, salt string, unixTime int64) (string, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, []byte(payloadJSON)); err != nil {
		return "", fmt.Errorf("flasksession: payload is not valid JSON: %w", err)
	}
	payloadSeg := base64.RawURLEncoding.EncodeToString(buf.Bytes())
	tsSeg := base64.RawURLEncoding.EncodeToString(intToBytes(unixTime - itsdangerousEpoch))
	signed := payloadSeg + "." + tsSeg
	return signed + "." + sign(signed, secret, salt), nil
}

// intToBytes is itsdangerous's int_to_bytes: minimal big-endian, no leading zeros.
func intToBytes(v int64) []byte {
	if v <= 0 {
		return nil
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte(v & 0xff)}, b...)
		v >>= 8
	}
	return b
}
