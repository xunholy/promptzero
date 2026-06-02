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

	key, err := otp.DecodeSecret(secretStr)
	if err != nil {
		return "", fmt.Errorf("totp_generate: %w", err)
	}
	h, err := otp.HashFor(algoStr)
	if err != nil {
		return "", fmt.Errorf("totp_generate: %w", err)
	}
	if digits < 6 || digits > 8 {
		return "", fmt.Errorf("totp_generate: digits must be 6-8 (got %d)", digits)
	}

	if mode == "" {
		mode = "totp"
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
