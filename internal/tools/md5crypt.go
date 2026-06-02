// md5crypt.go — host-side MD5-crypt (Unix $1$ / Apache $apr1$) compute + verify
// Spec, delegating to internal/unixcrypt.
//
// Wrap-vs-native: native — md5crypt is Poul-Henning Kamp's MD5-scramble over
// crypto/md5. It is an offline credential primitive: compute the hash of a
// candidate password, or verify a candidate against a captured $1$/$apr1$ hash.
// The $1$ algorithm is also Cisco IOS "type 5"; $apr1$ is the Apache htpasswd
// format. Complements hash_identify (which recognises these) and hash_crack
// (which attacks them). Offline compute from operator-supplied strings; no
// network or device.

package tools

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/unixcrypt"
)

func init() { //nolint:gochecknoinits
	Register(md5cryptSpec)
}

var md5cryptSpec = Spec{
	Name: "md5crypt",
	Description: "Compute or verify a Unix md5crypt ($1$) or Apache apr1 ($apr1$) password hash — the " +
		"compute/verify side of the credential toolkit (hash_identify recognises these, hash_crack attacks " +
		"them). The same $1$ algorithm is Cisco IOS \"type 5\"; $apr1$ is the Apache htpasswd format. Use " +
		"it to confirm a cracked password, build an htpasswd / shadow entry for an authorized lab, or check " +
		"a candidate against a captured hash.\n\n" +
		"Provide **password** and either: a full **hash** ($1$… or $apr1$…) to verify against (constant-time " +
		"compared), or — for compute mode — an optional **scheme** (md5crypt default, or apr1) and optional " +
		"**salt** (≤ 8 chars; a random salt is generated if omitted). Output is the crypt string in compute " +
		"mode, or the matched true/false plus the detected scheme in verify mode.\n\n" +
		"Offline compute from an operator-supplied string — no network, no device, transmits nothing, so it " +
		"is Low risk. Verified in-tree against the OpenSSL `passwd -1` / `passwd -apr1` oracle across " +
		"several password and salt lengths. Wrap-vs-native: native — crypto/md5, standard-library only.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"password":{"type":"string","description":"The password to hash or verify."},
			"hash":{"type":"string","description":"A full $1$… / $apr1$… hash to verify the password against (verify mode)."},
			"scheme":{"type":"string","description":"Compute-mode scheme: md5crypt (default, $1$) or apr1 ($apr1$).","enum":["md5crypt","apr1"]},
			"salt":{"type":"string","description":"Compute-mode salt (≤ 8 chars; random if omitted)."}
		},
		"required":["password"]
	}`),
	Required:  []string{"password"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   md5cryptHandler,
}

func md5cryptHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	password, ok := p["password"].(string)
	if !ok {
		return "", fmt.Errorf("md5crypt: 'password' is required")
	}

	// Verify mode: a full hash was supplied.
	if h := strings.TrimSpace(str(p, "hash")); h != "" {
		matched, err := unixcrypt.Verify(password, h)
		if err != nil {
			return "", fmt.Errorf("md5crypt: %w", err)
		}
		out, _ := json.MarshalIndent(map[string]any{
			"mode": "verify", "matched": matched, "scheme": unixcrypt.Scheme(h),
		}, "", "  ")
		return string(out), nil
	}

	// Compute mode.
	scheme := strings.ToLower(strings.TrimSpace(str(p, "scheme")))
	if scheme == "" {
		scheme = "md5crypt"
	}
	salt := str(p, "salt")
	if salt == "" {
		s, err := randomSalt(8)
		if err != nil {
			return "", fmt.Errorf("md5crypt: %w", err)
		}
		salt = s
	}

	var hash string
	switch scheme {
	case "md5crypt", "$1$", "1":
		hash = unixcrypt.MD5Crypt(password, salt)
		scheme = "md5crypt"
	case "apr1", "$apr1$":
		hash = unixcrypt.APR1(password, salt)
		scheme = "apr1"
	default:
		return "", fmt.Errorf("md5crypt: scheme %q must be \"md5crypt\" or \"apr1\"", scheme)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"mode": "compute", "scheme": scheme, "hash": hash,
	}, "", "  ")
	return string(out), nil
}

// randomSalt returns n characters drawn uniformly from the crypt(3) alphabet.
func randomSalt(n int) (string, error) {
	const alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for i := range buf {
		buf[i] = alphabet[int(buf[i])%len(alphabet)]
	}
	return string(buf), nil
}
