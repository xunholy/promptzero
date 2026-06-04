// cisco_type8.go — host-side Cisco IOS type-8 password compute + verify Spec,
// delegating to internal/ciscopw.
//
// Wrap-vs-native: native — Cisco type 8 is PBKDF2-HMAC-SHA256 (80-bit salt,
// 20 000 iterations) in the Cisco base64 alphabet — the modern `enable secret`
// / `secret` algorithm. It complements hash_identify (which flags $8$ as
// hashcat 9200) and the reversible cisco_type7_decode. Offline compute from
// operator-supplied strings; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ciscopw"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ciscoType8Spec)
}

var ciscoType8Spec = Spec{
	Name: "cisco_type8",
	Description: "Compute or verify a Cisco IOS type-8 password — the modern `enable secret` / `secret` " +
		"algorithm (introduced 2013, hashcat mode 9200), PBKDF2-HMAC-SHA256 with an 80-bit salt and 20,000 " +
		"iterations in the Cisco base64 alphabet. It is the compute/verify side of the credential toolkit: " +
		"hash_identify flags `$8$…` as Cisco type 8 and hash_crack attacks it, but neither could produce or " +
		"check one (cisco_type7_decode handles the older reversible type 7). Use it to confirm a password " +
		"recovered from a router/switch config, build a `secret` entry for an authorized lab, or check a " +
		"candidate against a captured hash.\n\n" +
		"The hash is `$8$<salt>$<digest>` — 14 Cisco-base64 salt chars + the 43-char Cisco-base64 of the " +
		"32-byte PBKDF2 output. The salt fed to PBKDF2 is the ASCII of the salt string itself (a Cisco " +
		"quirk).\n\n" +
		"Provide **password** and either a full **hash** (`$8$…`) to verify against (constant-time compared), " +
		"or — for compute mode — an optional **salt** (14 Cisco-base64 chars; a random salt is generated if " +
		"omitted). Output is the hash in compute mode, or matched true/false in verify mode.\n\n" +
		"Offline compute from an operator-supplied string — no network, no device, transmits nothing, so it " +
		"is Low risk. A malformed hash (wrong prefix / salt or digest length / alphabet) is rejected, never " +
		"silently \"verified\". Type 9 ($9$, scrypt) is deferred (scrypt is not in the standard library; " +
		"hash_identify flags it for cracking). Verified in-tree against the canonical hashcat-9200 vector " +
		"(`$8$TnGX/fE4KGHOVU$pEhnEvxr…`, password 'hashcat') + a second cracked vector (password 'cisco'), " +
		"both reproduced byte-for-byte. Wrap-vs-native: native — internal/wpa.PBKDF2 + crypto/sha256.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"password":{"type":"string","description":"The password to hash or verify."},
			"hash":{"type":"string","description":"A full $8$<salt>$<digest> hash to verify the password against (verify mode)."},
			"salt":{"type":"string","description":"Compute-mode salt (14 Cisco-base64 chars; random if omitted)."}
		},
		"required":["password"]
	}`),
	Required:  []string{"password"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ciscoType8Handler,
}

func ciscoType8Handler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	password, ok := p["password"].(string)
	if !ok {
		return "", fmt.Errorf("cisco_type8: 'password' is required")
	}

	// Verify mode: a full hash was supplied.
	if h := strings.TrimSpace(str(p, "hash")); h != "" {
		matched, err := ciscopw.Type8Verify(password, h)
		if err != nil {
			return "", fmt.Errorf("cisco_type8: %w", err)
		}
		out, _ := json.MarshalIndent(map[string]any{
			"mode": "verify", "matched": matched, "scheme": "cisco-type8",
		}, "", "  ")
		return string(out), nil
	}

	// Compute mode.
	hash, err := ciscopw.Type8Compute(password, strings.TrimSpace(str(p, "salt")))
	if err != nil {
		return "", fmt.Errorf("cisco_type8: %w", err)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"mode": "compute", "scheme": "cisco-type8", "hash": hash,
	}, "", "  ")
	return string(out), nil
}
