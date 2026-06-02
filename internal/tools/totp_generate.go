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
	Description: "Generate an RFC 6238 TOTP (default) or RFC 4226 HOTP one-time password from a base32 " +
		"2FA seed — the offline post-exploitation step after a seed is recovered from captured loot (a " +
		"secrets file, a config dump, an otpauth:// URI / QR payload). Complements the credential tooling " +
		"(hash_identify / jwt_decode / kerberos_decode): you have the seed, this derives the live code.\n\n" +
		"Fields: **secret** (base32, the Google-Authenticator form — spaces / lowercase / missing padding " +
		"tolerated), **mode** (totp default, or hotp), **algorithm** (SHA1 default / SHA256 / SHA512), " +
		"**digits** (6 default, 6-8), **period** (TOTP step seconds, 30 default), **counter** (HOTP), and " +
		"**timestamp** (optional TOTP unix seconds — defaults to now). For TOTP the output also reports " +
		"the time-step counter and the seconds remaining in the current window.\n\n" +
		"Offline compute from an operator-supplied seed — no network, no device, transmits nothing, so it " +
		"is Low risk. Verified in-tree against the RFC 4226/6238 published test vectors. Wrap-vs-native: " +
		"native — HMAC-SHA* + the RFC dynamic-truncation, standard-library only.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"secret":{"type":"string","description":"Base32 2FA seed (spaces / lowercase / missing padding tolerated)."},
			"mode":{"type":"string","description":"\"totp\" (default) or \"hotp\".","enum":["totp","hotp"]},
			"algorithm":{"type":"string","description":"HMAC hash: SHA1 (default), SHA256, SHA512.","enum":["SHA1","SHA256","SHA512"]},
			"digits":{"type":"integer","description":"Code length 6-8 (default 6)."},
			"period":{"type":"integer","description":"TOTP time-step seconds (default 30)."},
			"counter":{"type":"integer","description":"HOTP counter (required for mode=hotp)."},
			"timestamp":{"type":"integer","description":"TOTP unix timestamp (default: current time)."}
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
	key, err := otp.DecodeSecret(str(p, "secret"))
	if err != nil {
		return "", fmt.Errorf("totp_generate: %w", err)
	}
	h, err := otp.HashFor(str(p, "algorithm"))
	if err != nil {
		return "", fmt.Errorf("totp_generate: %w", err)
	}
	digits := intOr(p, "digits", 6)
	if digits < 6 || digits > 8 {
		return "", fmt.Errorf("totp_generate: digits must be 6-8 (got %d)", digits)
	}

	mode := strings.ToLower(strings.TrimSpace(str(p, "mode")))
	if mode == "" {
		mode = "totp"
	}
	switch mode {
	case "hotp":
		counter, ok := intArg(p["counter"])
		if !ok || counter < 0 {
			return "", fmt.Errorf("totp_generate: mode=hotp requires a non-negative 'counter'")
		}
		code := otp.HOTP(key, uint64(counter), digits, h)
		out, _ := json.MarshalIndent(map[string]any{
			"mode": "hotp", "counter": counter, "code": code, "digits": digits,
		}, "", "  ")
		return string(out), nil
	case "totp":
		period := intOr(p, "period", 30)
		if period <= 0 {
			return "", fmt.Errorf("totp_generate: period must be positive (got %d)", period)
		}
		now := int64(intOr(p, "timestamp", int(time.Now().Unix())))
		t := time.Unix(now, 0)
		code := otp.TOTP(key, t, period, digits, h)
		step := now / int64(period)
		remaining := int64(period) - (now % int64(period))
		out, _ := json.MarshalIndent(map[string]any{
			"mode":              "totp",
			"code":              code,
			"digits":            digits,
			"period":            period,
			"unix_time":         now,
			"time_step":         step,
			"seconds_remaining": remaining,
		}, "", "  ")
		return string(out), nil
	default:
		return "", fmt.Errorf("totp_generate: mode %q must be \"totp\" or \"hotp\"", mode)
	}
}
