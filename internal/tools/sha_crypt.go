// sha_crypt.go — host-side SHA-crypt (Unix $5$ sha256crypt / $6$ sha512crypt)
// compute + verify Spec, delegating to internal/unixcrypt.
//
// Wrap-vs-native: native — SHA-crypt is Ulrich Drepper's algorithm over
// crypto/sha256 + crypto/sha512. $6$ sha512crypt is the modern Linux
// /etc/shadow default, so this is the highest-frequency offline-crack target:
// compute the hash of a candidate password, or verify a candidate against a
// captured shadow hash. Complements hash_identify (which recognises these,
// hashcat 7400 / 1800) and hash_crack (which attacks them), and the md5crypt
// tool (the older $1$/$apr1$ family). Offline compute from operator-supplied
// strings; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/unixcrypt"
)

func init() { //nolint:gochecknoinits
	Register(shaCryptSpec)
}

var shaCryptSpec = Spec{
	Name: "sha_crypt",
	Description: "Compute or verify a Unix SHA-crypt password hash — $6$ sha512crypt (the modern Linux " +
		"/etc/shadow default) or $5$ sha256crypt. The compute/verify side of the credential toolkit: " +
		"hash_identify recognises these (hashcat 1800 sha512crypt / 7400 sha256crypt) and hash_crack " +
		"attacks them, while the md5crypt tool covers the older $1$/$apr1$ family. Use it to confirm a " +
		"cracked password, build a shadow entry for an authorized lab, or check a candidate against a " +
		"captured hash.\n\n" +
		"Provide **password** and either: a full **hash** ($6$… / $5$… — also accepts $1$/$apr1$) to verify " +
		"against (constant-time compared), or — for compute mode — an optional **scheme** (sha512crypt " +
		"default, or sha256crypt), optional **salt** (≤ 16 chars; random if omitted), and optional " +
		"**rounds** (1000-999999999; default 5000, emitted as rounds=N$ when set). Output is the crypt " +
		"string in compute mode, or matched true/false plus the detected scheme in verify mode.\n\n" +
		"Offline compute from an operator-supplied string — no network, no device, transmits nothing, so " +
		"it is Low risk. Verified in-tree against the OpenSSL `passwd -6` / `passwd -5` oracle (including " +
		"the rounds= form). Wrap-vs-native: native — crypto/sha256 + crypto/sha512, standard-library only.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"password":{"type":"string","description":"The password to hash or verify."},
			"hash":{"type":"string","description":"A full crypt hash ($6$/$5$/$1$/$apr1$) to verify the password against (verify mode)."},
			"scheme":{"type":"string","description":"Compute-mode scheme: sha512crypt (default, $6$) or sha256crypt ($5$).","enum":["sha512crypt","sha256crypt"]},
			"salt":{"type":"string","description":"Compute-mode salt (≤ 16 chars; random if omitted)."},
			"rounds":{"type":"integer","description":"Compute-mode iteration count (1000-999999999; default 5000)."}
		},
		"required":["password"]
	}`),
	Required:  []string{"password"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   shaCryptHandler,
}

func shaCryptHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	password, ok := p["password"].(string)
	if !ok {
		return "", fmt.Errorf("sha_crypt: 'password' is required")
	}

	// Verify mode.
	if h := strings.TrimSpace(str(p, "hash")); h != "" {
		matched, err := unixcrypt.Verify(password, h)
		if err != nil {
			return "", fmt.Errorf("sha_crypt: %w", err)
		}
		out, _ := json.MarshalIndent(map[string]any{
			"mode": "verify", "matched": matched, "scheme": unixcrypt.Scheme(h),
		}, "", "  ")
		return string(out), nil
	}

	// Compute mode.
	scheme := strings.ToLower(strings.TrimSpace(str(p, "scheme")))
	if scheme == "" {
		scheme = "sha512crypt"
	}
	salt := str(p, "salt")
	if salt == "" {
		s, err := randomSalt(16)
		if err != nil {
			return "", fmt.Errorf("sha_crypt: %w", err)
		}
		salt = s
	}
	rounds := intOr(p, "rounds", 0)

	var hash string
	switch scheme {
	case "sha512crypt", "$6$", "6":
		hash = unixcrypt.SHA512Crypt(password, salt, rounds)
		scheme = "sha512crypt"
	case "sha256crypt", "$5$", "5":
		hash = unixcrypt.SHA256Crypt(password, salt, rounds)
		scheme = "sha256crypt"
	default:
		return "", fmt.Errorf("sha_crypt: scheme %q must be \"sha512crypt\" or \"sha256crypt\"", scheme)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"mode": "compute", "scheme": scheme, "hash": hash,
	}, "", "  ")
	return string(out), nil
}
