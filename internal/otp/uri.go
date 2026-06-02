// SPDX-License-Identifier: AGPL-3.0-or-later

package otp

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// URIParams holds the fields parsed from a Google-Authenticator otpauth:// key
// URI — the form encoded in a 2FA-enrolment QR code and emitted by authenticator
// exports. The secret is returned base32 (as it appears in the URI); decode it
// with DecodeSecret.
type URIParams struct {
	Type       string // "totp" or "hotp"
	Secret     string // base32 secret (decode with DecodeSecret)
	Algorithm  string // SHA1 / SHA256 / SHA512 (default SHA1)
	Digits     int    // 6-8 (default 6)
	Period     int    // TOTP step seconds (default 30)
	Counter    uint64 // HOTP counter (valid only when HasCounter)
	HasCounter bool
	Issuer     string
	Account    string
}

// ParseURI parses an otpauth:// key URI per Google's Key-URI-Format
//
//	otpauth://TYPE/[ISSUER:]ACCOUNT?secret=BASE32&issuer=…&algorithm=…&digits=…&period=…&counter=…
//
// into its fields, applying the spec defaults (algorithm SHA1, digits 6, period
// 30) for absent parameters. It exists so totp_generate can consume the real
// 2FA artifact directly: the URI carries the algorithm / digits / period that
// drive the code, so feeding the raw base32 secret alone (and relying on the
// SHA1/6/30 defaults) would silently produce wrong codes whenever the enrolment
// used, say, SHA256 or 8 digits. The label's ISSUER:ACCOUNT is parsed for
// display; an explicit issuer= query parameter wins over the label prefix.
func ParseURI(raw string) (*URIParams, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("otp: invalid otpauth URI: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "otpauth") {
		return nil, fmt.Errorf("otp: not an otpauth:// URI (scheme %q)", u.Scheme)
	}
	typ := strings.ToLower(u.Host)
	if typ != "totp" && typ != "hotp" {
		return nil, fmt.Errorf("otp: otpauth type must be totp or hotp (got %q)", u.Host)
	}
	q := u.Query()
	secret := strings.TrimSpace(q.Get("secret"))
	if secret == "" {
		return nil, fmt.Errorf("otp: otpauth URI missing required 'secret' parameter")
	}

	p := &URIParams{
		Type:      typ,
		Secret:    secret,
		Algorithm: "SHA1",
		Digits:    6,
		Period:    30,
		Issuer:    strings.TrimSpace(q.Get("issuer")),
	}

	// Label: an optional "[issuer:]account" path (already percent-decoded by url).
	if label := strings.TrimPrefix(u.Path, "/"); label != "" {
		if i := strings.Index(label, ":"); i >= 0 {
			if p.Issuer == "" {
				p.Issuer = strings.TrimSpace(label[:i])
			}
			p.Account = strings.TrimSpace(label[i+1:])
		} else {
			p.Account = strings.TrimSpace(label)
		}
	}

	if a := strings.TrimSpace(q.Get("algorithm")); a != "" {
		if _, err := HashFor(a); err != nil {
			return nil, fmt.Errorf("otp: otpauth %w", err)
		}
		p.Algorithm = strings.ToUpper(a)
	}
	if d := strings.TrimSpace(q.Get("digits")); d != "" {
		n, err := strconv.Atoi(d)
		if err != nil || n < 6 || n > 8 {
			return nil, fmt.Errorf("otp: otpauth digits must be 6-8 (got %q)", d)
		}
		p.Digits = n
	}
	if pr := strings.TrimSpace(q.Get("period")); pr != "" {
		n, err := strconv.Atoi(pr)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("otp: otpauth period must be positive (got %q)", pr)
		}
		p.Period = n
	}
	if c := strings.TrimSpace(q.Get("counter")); c != "" {
		n, err := strconv.ParseUint(c, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("otp: otpauth counter must be a non-negative integer (got %q)", c)
		}
		p.Counter = n
		p.HasCounter = true
	}
	if typ == "hotp" && !p.HasCounter {
		return nil, fmt.Errorf("otp: hotp otpauth URI requires a 'counter' parameter")
	}
	return p, nil
}
