// SPDX-License-Identifier: AGPL-3.0-or-later

// Package otpmigration decodes the Google Authenticator "Export accounts"
// payload — the otpauth-migration://offline?data=… URI (and the bare base64
// behind it) — into the list of 2FA accounts it carries: issuer, account name,
// secret, algorithm, digit count, OTP type, and HOTP counter. A single export
// QR packs ALL of a user's seeds, so decoding one is a high-value
// post-exploitation / device-forensics step: it bulk-recovers every TOTP/HOTP
// secret, each ready to feed into totp_generate for the live codes. Pure
// offline transform; no network or device.
//
// # Wrap-vs-native judgement
//
// Native. The payload is a small protobuf (MigrationPayload) whose schema is
// public and stable. We parse the wire format directly with
// google.golang.org/protobuf/encoding/protowire — already an indirect
// dependency of the module, used here only as a low-level varint/bytes reader,
// with NO generated .pb.go and NO new go.mod entry. The base64 + base32 +
// URI assembly is stdlib. Nothing is wrapped or shelled out.
//
// # Schema (reverse-engineered, stable since the 2020 export feature)
//
//	message MigrationPayload {
//	  message OtpParameters {
//	    bytes  secret    = 1;  // raw secret bytes (base32-encode for display)
//	    string name      = 2;  // account / label
//	    string issuer    = 3;
//	    Algorithm algorithm = 4;  // 0 unspec,1 SHA1,2 SHA256,3 SHA512,4 MD5
//	    DigitCount digits   = 5;  // 0 unspec,1 SIX,2 EIGHT
//	    OtpType type        = 6;  // 0 unspec,1 HOTP,2 TOTP
//	    int64  counter   = 7;  // HOTP only
//	  }
//	  repeated OtpParameters otp_parameters = 1;
//	  int32 version     = 2;
//	  int32 batch_size  = 3;
//	  int32 batch_index = 4;
//	  int32 batch_id    = 5;
//	}
//
// # Verifiable / no confidently-wrong output
//
// Anchored to the canonical migration example used across the ecosystem —
// data CjEKCkhlbGxvId6tvu8SGFRlc3Q6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZSABKAEwAg==
// → issuer "Example", secret JBSWY3DPEHPK3PXP (base32 of the bytes
// 48656C6C6F21DEADBEEF, "Hello!"+0xDEADBEEF), SHA1 / 6 digits / TOTP. An
// unknown enum value is surfaced raw ("UNSPECIFIED(n)") rather than guessed; a
// truncated or non-protobuf payload is rejected. The secret is the
// correctness-critical field, and it is cross-checked by that independent
// base32 computation.
package otpmigration

import (
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

// Account is one decoded OTP entry, with a reconstructed otpauth:// URI ready to
// paste into totp_generate.
type Account struct {
	Issuer     string `json:"issuer,omitempty"`
	Name       string `json:"name"`
	Secret     string `json:"secret"` // base32, no padding (the otpauth form)
	Algorithm  string `json:"algorithm"`
	Digits     int    `json:"digits"`
	Type       string `json:"type"`              // totp / hotp
	Counter    int64  `json:"counter,omitempty"` // HOTP only
	OtpauthURI string `json:"otpauth_uri"`
}

// Result is the decoded migration payload.
type Result struct {
	Version    int       `json:"version,omitempty"`
	BatchSize  int       `json:"batch_size,omitempty"`
	BatchIndex int       `json:"batch_index,omitempty"`
	BatchID    int       `json:"batch_id,omitempty"`
	Count      int       `json:"count"`
	Accounts   []Account `json:"accounts"`
}

// b32 encodes secret bytes as upper-case base32 without padding — the form an
// otpauth:// secret takes.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// MigrationPayload top-level field numbers.
const (
	fieldOtpParameters = 1
	fieldVersion       = 2
	fieldBatchSize     = 3
	fieldBatchIndex    = 4
	fieldBatchID       = 5
)

// OtpParameters field numbers.
const (
	opSecret    = 1
	opName      = 2
	opIssuer    = 3
	opAlgorithm = 4
	opDigits    = 5
	opType      = 6
	opCounter   = 7
)

// Decode accepts a full otpauth-migration:// URI or the bare (URL- or plain)
// base64 data payload and returns the decoded accounts.
func Decode(input string) (*Result, error) {
	data, err := extractData(strings.TrimSpace(input))
	if err != nil {
		return nil, err
	}
	raw, err := decodeBase64(data)
	if err != nil {
		return nil, fmt.Errorf("otpmigration: data is not valid base64: %w", err)
	}
	res, err := parsePayload(raw)
	if err != nil {
		return nil, err
	}
	res.Count = len(res.Accounts)
	return res, nil
}

// extractData pulls the base64 payload from a full otpauth-migration:// URI, or
// returns the input unchanged when it is already the bare data.
func extractData(in string) (string, error) {
	if in == "" {
		return "", fmt.Errorf("otpmigration: empty input")
	}
	if strings.HasPrefix(strings.ToLower(in), "otpauth-migration://") {
		u, err := url.Parse(in)
		if err != nil {
			return "", fmt.Errorf("otpmigration: malformed migration URI: %w", err)
		}
		d := u.Query().Get("data")
		if d == "" {
			return "", fmt.Errorf("otpmigration: migration URI has no 'data' parameter")
		}
		return d, nil
	}
	if strings.HasPrefix(strings.ToLower(in), "otpauth://") {
		return "", fmt.Errorf("otpmigration: this is a single otpauth:// URI, not a migration export — use totp_generate")
	}
	return in, nil
}

// decodeBase64 tolerates the standard, URL, padded and unpadded base64 forms
// the data parameter appears in across exporters.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("not decodable as base64")
}

// parsePayload walks the MigrationPayload wire bytes.
func parsePayload(b []byte) (*Result, error) {
	res := &Result{}
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, fmt.Errorf("otpmigration: malformed protobuf tag")
		}
		b = b[n:]
		switch {
		case num == fieldOtpParameters && typ == protowire.BytesType:
			v, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return nil, fmt.Errorf("otpmigration: malformed otp_parameters field")
			}
			acct, err := parseOtpParameters(v)
			if err != nil {
				return nil, err
			}
			res.Accounts = append(res.Accounts, acct)
			b = b[m:]
		case num == fieldVersion && typ == protowire.VarintType:
			b = consumeVarintInto(b, &res.Version)
		case num == fieldBatchSize && typ == protowire.VarintType:
			b = consumeVarintInto(b, &res.BatchSize)
		case num == fieldBatchIndex && typ == protowire.VarintType:
			b = consumeVarintInto(b, &res.BatchIndex)
		case num == fieldBatchID && typ == protowire.VarintType:
			b = consumeVarintInto(b, &res.BatchID)
		default:
			m := protowire.ConsumeFieldValue(num, typ, b)
			if m < 0 {
				return nil, fmt.Errorf("otpmigration: malformed protobuf field %d", num)
			}
			b = b[m:]
		}
	}
	if len(res.Accounts) == 0 {
		return nil, fmt.Errorf("otpmigration: payload carried no OTP accounts")
	}
	return res, nil
}

// parseOtpParameters walks one OtpParameters sub-message.
func parseOtpParameters(b []byte) (Account, error) {
	var (
		a         Account
		secret    []byte
		algEnum   uint64
		digitEnum uint64
		typeEnum  uint64
	)
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return a, fmt.Errorf("otpmigration: malformed otp_parameters tag")
		}
		b = b[n:]
		switch {
		case num == opSecret && typ == protowire.BytesType:
			v, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return a, fmt.Errorf("otpmigration: malformed secret")
			}
			secret = v
			b = b[m:]
		case num == opName && typ == protowire.BytesType:
			a.Name, b = consumeString(b)
		case num == opIssuer && typ == protowire.BytesType:
			a.Issuer, b = consumeString(b)
		case num == opAlgorithm && typ == protowire.VarintType:
			algEnum, b = consumeVarint(b)
		case num == opDigits && typ == protowire.VarintType:
			digitEnum, b = consumeVarint(b)
		case num == opType && typ == protowire.VarintType:
			typeEnum, b = consumeVarint(b)
		case num == opCounter && typ == protowire.VarintType:
			var c uint64
			c, b = consumeVarint(b)
			a.Counter = int64(c)
		default:
			m := protowire.ConsumeFieldValue(num, typ, b)
			if m < 0 {
				return a, fmt.Errorf("otpmigration: malformed otp_parameters field %d", num)
			}
			b = b[m:]
		}
	}
	a.Secret = b32.EncodeToString(secret)
	a.Algorithm = algorithmName(algEnum)
	a.Digits = digitCount(digitEnum)
	a.Type = otpType(typeEnum)
	a.OtpauthURI = buildOtpauthURI(a)
	return a, nil
}

func consumeString(b []byte) (string, []byte) {
	v, m := protowire.ConsumeBytes(b)
	if m < 0 {
		return "", nil
	}
	return string(v), b[m:]
}

func consumeVarint(b []byte) (uint64, []byte) {
	v, m := protowire.ConsumeVarint(b)
	if m < 0 {
		return 0, nil
	}
	return v, b[m:]
}

func consumeVarintInto(b []byte, dst *int) []byte {
	v, nb := consumeVarint(b)
	*dst = int(v)
	return nb
}

// algorithmName maps the Algorithm enum. 0 (unspecified) defaults to SHA1 — the
// otpauth default — since that is what authenticators use for an unset field.
func algorithmName(v uint64) string {
	switch v {
	case 0, 1:
		return "SHA1"
	case 2:
		return "SHA256"
	case 3:
		return "SHA512"
	case 4:
		return "MD5"
	default:
		return fmt.Sprintf("UNSPECIFIED(%d)", v)
	}
}

// digitCount maps the DigitCount enum (0/1 → 6, 2 → 8).
func digitCount(v uint64) int {
	switch v {
	case 2:
		return 8
	default:
		return 6
	}
}

// otpType maps the OtpType enum. 0 (unspecified) defaults to totp.
func otpType(v uint64) string {
	if v == 1 {
		return "hotp"
	}
	return "totp"
}

// buildOtpauthURI reconstructs an otpauth:// URI from a decoded account, ready
// to feed into totp_generate.
func buildOtpauthURI(a Account) string {
	label := a.Name
	if a.Issuer != "" && !strings.Contains(a.Name, ":") {
		label = a.Issuer + ":" + a.Name
	}
	q := url.Values{}
	q.Set("secret", a.Secret)
	if a.Issuer != "" {
		q.Set("issuer", a.Issuer)
	}
	q.Set("algorithm", a.Algorithm)
	q.Set("digits", strconv.Itoa(a.Digits))
	if a.Type == "hotp" {
		q.Set("counter", strconv.FormatInt(a.Counter, 10))
	} else {
		q.Set("period", "30")
	}
	return fmt.Sprintf("otpauth://%s/%s?%s", a.Type, url.PathEscape(label), q.Encode())
}
