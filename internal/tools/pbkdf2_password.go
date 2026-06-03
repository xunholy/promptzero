// pbkdf2_password.go — host-side Django / Werkzeug PBKDF2 password-hash
// verify + compute Spec, delegating to internal/webpass.
//
// Wrap-vs-native: native — PBKDF2-HMAC over crypto/sha* (the generic PBKDF2 in
// internal/wpa) plus the framework-specific framing. Django (pbkdf2_sha256$…)
// and Werkzeug/Flask (pbkdf2:sha256:…) are the user-credential format in a
// Python web-app database dump; this is the compute/verify side, complementing
// hash_crack's new django/werkzeug dictionary modes. Offline compute over
// operator-supplied strings; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/webpass"
)

func init() { //nolint:gochecknoinits
	Register(pbkdf2PasswordSpec)
}

var pbkdf2PasswordSpec = Spec{
	Name: "pbkdf2_password",
	Description: "Compute or verify a Django (pbkdf2_sha256$…) or Werkzeug/Flask (pbkdf2:sha256:…) PBKDF2 " +
		"password hash — the user-credential format in a Python web-app database dump, and a top offline-" +
		"crack target. The compute/verify side of the credential toolkit for the two dominant Python web " +
		"frameworks (hash_crack also gained django/werkzeug dictionary modes).\n\n" +
		"Provide **password** and either a full **hash** (pbkdf2_sha256$… or pbkdf2:sha256:…) to verify " +
		"against (framework auto-detected, constant-time), or — for compute mode — **scheme** (django or " +
		"werkzeug), optional **algorithm** (sha256 default / sha1 / sha512), **iterations**, and **salt**. " +
		"Output is matched true/false + the detected scheme in verify mode, or the hash string in compute " +
		"mode.\n\n" +
		"Offline compute from an operator-supplied string — no network, no device, transmits nothing, so it " +
		"is Low risk. Verified in-tree against reference Django and Werkzeug hashes. Wrap-vs-native: native " +
		"— PBKDF2-HMAC-SHA* over the standard library.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"password":{"type":"string","description":"The password to hash or verify."},
			"hash":{"type":"string","description":"A full Django/Werkzeug PBKDF2 hash to verify against (verify mode)."},
			"scheme":{"type":"string","description":"Compute-mode framework: django or werkzeug.","enum":["django","werkzeug"]},
			"algorithm":{"type":"string","description":"Compute-mode PBKDF2 hash: sha256 (default), sha1, sha512.","enum":["sha256","sha1","sha512"]},
			"iterations":{"type":"integer","description":"Compute-mode iteration count (default 600000)."},
			"salt":{"type":"string","description":"Compute-mode salt (used as raw bytes; random if omitted)."}
		},
		"required":["password"]
	}`),
	Required:  []string{"password"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   pbkdf2PasswordHandler,
}

func pbkdf2PasswordHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	password, ok := p["password"].(string)
	if !ok {
		return "", fmt.Errorf("pbkdf2_password: 'password' is required")
	}

	// Verify mode.
	if h := strings.TrimSpace(str(p, "hash")); h != "" {
		matched, err := webpass.Verify(h, password)
		if err != nil {
			return "", fmt.Errorf("pbkdf2_password: %w", err)
		}
		out, _ := json.MarshalIndent(map[string]any{
			"mode": "verify", "matched": matched, "scheme": webpass.Scheme(h),
		}, "", "  ")
		return string(out), nil
	}

	// Compute mode.
	scheme := strings.ToLower(strings.TrimSpace(str(p, "scheme")))
	if scheme == "" {
		scheme = "django"
	}
	algo := strings.ToLower(strings.TrimSpace(str(p, "algorithm")))
	if algo == "" {
		algo = "sha256"
	}
	iter := intOr(p, "iterations", 600000)
	salt := str(p, "salt")
	if salt == "" {
		s, err := randomSalt(12)
		if err != nil {
			return "", fmt.Errorf("pbkdf2_password: %w", err)
		}
		salt = s
	}
	hash, err := webpass.Compute(scheme, algo, iter, salt, password)
	if err != nil {
		return "", fmt.Errorf("pbkdf2_password: %w", err)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"mode": "compute", "scheme": scheme, "hash": hash,
	}, "", "  ")
	return string(out), nil
}
