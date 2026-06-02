// totp_generate.go — host-side TOTP/HOTP one-time-password generator Spec,
// delegating to internal/otp.
//
// Wrap-vs-native: native — HOTP is HMAC + RFC 4226 truncation, TOTP is HOTP
// over a time step. It is an offline post-exploitation primitive: a 2FA seed
// recovered from captured loot (secrets file, config dump, otpauth:// payload)
// is turned into the live codes, complementing the credential tooling
// (hash_identify / jwt_decode / kerberos_decode). Computes from an
// operator-supplied seed; no network or device interaction.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/otp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(totpGenerateSpec)
}

var totpGenerateSpec = Spec{
	Name: "totp_generate",
	Description: "Generate an RFC 6238 TOTP (default), RFC 4226 HOTP, or Steam Guard one-time password from " +
		"a recovered 2FA seed — the offline post-exploitation step after a seed is recovered from captured " +
		"loot (a secrets file, a config dump, an otpauth:// URI / QR payload, a Steam maFile shared_secret). " +
		"Complements the credential tooling (hash_identify / jwt_decode / kerberos_decode): you have the " +
		"seed, this derives the live code.\n\n" +
		"**Steam Guard**: set mode=steam and pass the base64 shared_secret — Steam uses RFC 6238 over " +
		"HMAC-SHA1 / 30s but maps the result to its own 5-character alphabet (algorithm / digits / period " +
		"are fixed and ignored).\n\n" +
		"Fields: **secret** (base32, the Google-Authenticator form — spaces / lowercase / missing padding " +
		"tolerated), **mode** (totp default, or hotp), **algorithm** (SHA1 default / SHA256 / SHA512), " +
		"**digits** (6 default, 6-8), **period** (TOTP step seconds, 30 default), **counter** (HOTP), and — alternatively a full **otpauth:// key URI** (captured from a 2FA-enrolment " +
		"QR / authenticator export) supplied in the **secret** field, in which case the parser takes the " +
		"algorithm / digits / period / counter / mode straight from the URI and ignores those args (the " +
		"safer path: feeding only the base32 secret from a SHA256/8-digit enrolment while the defaults stay " +
		"SHA1/6 yields valid-looking but wrong codes) — and " +
		"**timestamp** (optional TOTP unix seconds — defaults to now). For TOTP the output also reports " +
		"the time-step counter and the seconds remaining in the current window.\n\n" +
		"Offline compute from an operator-supplied seed — no network, no device, transmits nothing, so it " +
		"is Low risk. Verified in-tree against the RFC 4226/6238 published test vectors. Wrap-vs-native: " +
		"native — HMAC-SHA* + the RFC dynamic-truncation, standard-library only.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"secret":{"type":"string","description":"2FA seed: base32 (default, the Google-Authenticator form — spaces / lowercase / missing padding tolerated), base64 (set encoding=base64; Steam's shared_secret is base64), OR a full otpauth:// key URI (parameters then come from the URI)."},
			"mode":{"type":"string","description":"\"totp\" (default), \"hotp\", or \"steam\" (Steam Guard 5-char code).","enum":["totp","hotp","steam"]},
			"encoding":{"type":"string","description":"Secret encoding: base32 (default) or base64. Steam mode defaults to base64.","enum":["base32","base64"]},
			"algorithm":{"type":"string","description":"HMAC hash: SHA1 (default), SHA256, SHA512. Ignored for mode=steam (always SHA1).","enum":["SHA1","SHA256","SHA512"]},
			"digits":{"type":"integer","description":"Code length 6-8 (default 6). Ignored for mode=steam (always 5)."},
			"period":{"type":"integer","description":"TOTP time-step seconds (default 30). Ignored for mode=steam (always 30)."},
			"counter":{"type":"integer","description":"HOTP counter (required for mode=hotp)."},
			"timestamp":{"type":"integer","description":"TOTP/Steam unix timestamp (default: current time)."}
		},
		"required":["secret"]
	}`),
	Required:  []string{"secret"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   totpGenerateHandler,
}

func totpGenerateHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	secretArg := strings.TrimSpace(str(p, "secret"))

	// Effective parameters. An otpauth:// URI is self-describing — it carries the
	// secret plus the algorithm / digits / period / counter that drive the code —
	// so when one is supplied those fields come from the URI and the matching tool
	// args are ignored (only 'timestamp', the TOTP evaluation moment, is still
	// honoured). This is the correctness win: pasting the raw base32 secret from a
	// SHA256/8-digit enrolment while the tool defaults to SHA1/6 yields valid-
	// looking but wrong codes; consuming the URI applies the real parameters.
	secretStr := secretArg
	algoStr := str(p, "algorithm")
	mode := strings.ToLower(strings.TrimSpace(str(p, "mode")))
	digits := intOr(p, "digits", 6)
	period := intOr(p, "period", 30)
	var uri *otp.URIParams
	if strings.HasPrefix(strings.ToLower(secretArg), "otpauth://") {
		u, err := otp.ParseURI(secretArg)
		if err != nil {
			return "", fmt.Errorf("totp_generate: %w", err)
		}
		uri = u
		secretStr = u.Secret
		algoStr = u.Algorithm
		mode = u.Type
		digits = u.Digits
		period = u.Period
	}

	if mode == "" {
		mode = "totp"
	}

	// Secret encoding: base32 (Google-Authenticator form) by default; base64 for
	// Steam's shared_secret (the maFile / loot form). otpauth:// secrets are
	// always base32. An explicit 'encoding' arg overrides everything else.
	enc := strings.ToLower(strings.TrimSpace(str(p, "encoding")))
	switch {
	case uri != nil:
		enc = "base32"
	case enc == "" && mode == "steam":
		enc = "base64"
	case enc == "":
		enc = "base32"
	}
	key, err := decodeOTPSecret(secretStr, enc)
	if err != nil {
		return "", fmt.Errorf("totp_generate: %w", err)
	}

	// Steam Guard: RFC 6238 over HMAC-SHA1 / 30s mapped to Steam's 5-character
	// alphabet. The parameters are fixed, so algorithm / digits / period / counter
	// do not apply — only 'timestamp' (the evaluation moment) is honoured.
	if mode == "steam" {
		now := int64(intOr(p, "timestamp", int(time.Now().Unix())))
		code := otp.SteamGuard(key, time.Unix(now, 0))
		out, _ := json.MarshalIndent(map[string]any{
			"mode":              "steam",
			"code":              code,
			"digits":            5,
			"period":            30,
			"algorithm":         "SHA1",
			"unix_time":         now,
			"time_step":         now / 30,
			"seconds_remaining": int64(30) - (now % 30),
		}, "", "  ")
		return string(out), nil
	}

	h, err := otp.HashFor(algoStr)
	if err != nil {
		return "", fmt.Errorf("totp_generate: %w", err)
	}
	if digits < 6 || digits > 8 {
		return "", fmt.Errorf("totp_generate: digits must be 6-8 (got %d)", digits)
	}
	switch mode {
	case "hotp":
		var counter int
		switch {
		case uri != nil && uri.HasCounter:
			counter = int(uri.Counter)
		default:
			c, ok := intArg(p["counter"])
			if !ok || c < 0 {
				return "", fmt.Errorf("totp_generate: mode=hotp requires a non-negative 'counter'")
			}
			counter = c
		}
		code := otp.HOTP(key, uint64(counter), digits, h)
		res := map[string]any{
			"mode": "hotp", "counter": counter, "code": code, "digits": digits, "algorithm": displayAlgo(algoStr),
		}
		addURIContext(res, uri)
		out, _ := json.MarshalIndent(res, "", "  ")
		return string(out), nil
	case "totp":
		if period <= 0 {
			return "", fmt.Errorf("totp_generate: period must be positive (got %d)", period)
		}
		now := int64(intOr(p, "timestamp", int(time.Now().Unix())))
		t := time.Unix(now, 0)
		code := otp.TOTP(key, t, period, digits, h)
		step := now / int64(period)
		remaining := int64(period) - (now % int64(period))
		res := map[string]any{
			"mode":              "totp",
			"code":              code,
			"digits":            digits,
			"period":            period,
			"algorithm":         displayAlgo(algoStr),
			"unix_time":         now,
			"time_step":         step,
			"seconds_remaining": remaining,
		}
		addURIContext(res, uri)
		out, _ := json.MarshalIndent(res, "", "  ")
		return string(out), nil
	default:
		return "", fmt.Errorf("totp_generate: mode %q must be \"totp\" or \"hotp\"", mode)
	}
}

// decodeOTPSecret decodes the seed using the named encoding (base32 — the
// Google-Authenticator form — or base64 — Steam's shared_secret form).
func decodeOTPSecret(secret, encoding string) ([]byte, error) {
	switch encoding {
	case "", "base32":
		return otp.DecodeSecret(secret)
	case "base64":
		return otp.DecodeSecretBase64(secret)
	default:
		return nil, fmt.Errorf("encoding must be base32 or base64 (got %q)", encoding)
	}
}

// displayAlgo normalises an empty/blank algorithm to its SHA1 default for output.
func displayAlgo(a string) string {
	if strings.TrimSpace(a) == "" {
		return "SHA1"
	}
	return strings.ToUpper(strings.TrimSpace(a))
}

// addURIContext annotates the result with the issuer/account parsed from an
// otpauth:// URI (when one was supplied) so the operator can confirm which
// account the code belongs to.
func addURIContext(res map[string]any, uri *otp.URIParams) {
	if uri == nil {
		return
	}
	res["source"] = "otpauth_uri"
	if uri.Issuer != "" {
		res["issuer"] = uri.Issuer
	}
	if uri.Account != "" {
		res["account"] = uri.Account
	}
}
