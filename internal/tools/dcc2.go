// dcc2.go — host-side Domain Cached Credentials v2 (mscash2) compute + verify
// Spec, delegating to internal/dcc2.
//
// Wrap-vs-native: native — DCC2 composes the in-tree MD4 (internal/nthash) and
// PBKDF2-HMAC-SHA1 (internal/wpa) over UTF-16LE inputs. It is an offline
// credential primitive: compute the cached-credential hash of a candidate, or
// verify a candidate against a $DCC2$ value from a SECURITY-hive / secretsdump
// dump. Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/dcc2"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(dcc2Spec)
}

var dcc2Spec = Spec{
	Name: "dcc2",
	Description: "Compute or verify a Domain Cached Credentials v2 (DCC2 / MS-Cache v2 / mscash2) hash — the " +
		"format Windows (Vista / Server 2008+) caches domain logons in locally, dumped from a compromised " +
		"workstation's SECURITY registry hive (e.g. impacket secretsdump), hashcat mode 2100. Unlike an NT " +
		"hash a DCC2 **cannot be passed-the-hash** — it is offline-crack-only — and this is the compute/verify " +
		"side of the credential toolkit (hash_identify recognises $DCC2$, hash_crack attacks it, but neither " +
		"could produce or check one). Use it to confirm a password recovered from a cached-credentials dump, " +
		"build a test value for an authorized lab, or check a candidate.\n\n" +
		"The algorithm: DCC1 = MD4(MD4(password) ‖ lower(username)) (UTF-16LE); DCC2 = PBKDF2-HMAC-SHA1(DCC1, " +
		"lower(username), iterations, 16). The lowercased username is the salt; the stored form is " +
		"`$DCC2$<iterations>#<username>#<hex>` (default 10240 iterations).\n\n" +
		"Provide **password** and either a full **hash** (`$DCC2$…`) to verify against (the username + " +
		"iterations are taken from it, constant-time compared), or — for compute mode — a **username** and " +
		"optional **iterations** (default 10240). Output is the hash in compute mode, or matched true/false " +
		"in verify mode.\n\n" +
		"Offline compute from an operator-supplied string — no network, no device, transmits nothing, so it " +
		"is Low risk. A malformed hash (wrong prefix / field count / iteration count / non-hex) is rejected, " +
		"never silently \"verified\". Verified in-tree against the canonical hashcat mode-2100 example " +
		"($DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f, password 'hashcat'). Wrap-vs-native: native — " +
		"reuses the in-tree MD4 (internal/nthash) + PBKDF2 (internal/wpa), standard-library crypto only.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"password":{"type":"string","description":"The password to hash or verify."},
			"hash":{"type":"string","description":"A full $DCC2$<iterations>#<username>#<hex> value to verify against (verify mode); the username + iterations are taken from it."},
			"username":{"type":"string","description":"Compute-mode username (the PBKDF2 salt, lowercased). Required for compute mode."},
			"iterations":{"type":"integer","description":"Compute-mode iteration count (default 10240)."}
		},
		"required":["password"]
	}`),
	Required:  []string{"password"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   dcc2Handler,
}

func dcc2Handler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	password, ok := p["password"].(string)
	if !ok {
		return "", fmt.Errorf("dcc2: 'password' is required")
	}

	// Verify mode: a full hash was supplied.
	if h := strings.TrimSpace(str(p, "hash")); h != "" {
		res, err := dcc2.Verify(password, h)
		if err != nil {
			return "", fmt.Errorf("dcc2: %w", err)
		}
		out, _ := json.MarshalIndent(map[string]any{
			"mode": "verify", "matched": res.Matched, "scheme": "dcc2",
			"username": res.Username, "iterations": res.Iterations,
		}, "", "  ")
		return string(out), nil
	}

	// Compute mode.
	username := strings.TrimSpace(str(p, "username"))
	if username == "" {
		return "", fmt.Errorf("dcc2: 'username' is required for compute mode (it is the salt)")
	}
	iterations := 0
	if n, ok := p["iterations"].(float64); ok {
		iterations = int(n)
	}
	hash, err := dcc2.Compute(username, password, iterations)
	if err != nil {
		return "", fmt.Errorf("dcc2: %w", err)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"mode": "compute", "scheme": "dcc2", "hash": hash,
	}, "", "  ")
	return string(out), nil
}
