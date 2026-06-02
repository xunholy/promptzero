// bcrypt.go — host-side bcrypt password-hash compute + verify Spec.
//
// Wrap-vs-native: wrap (existing dependency). bcrypt is the dominant modern
// web-application password hash; this is the compute/verify side of the
// credential toolkit (hash_identify recognises bcrypt → hashcat 3200, and
// hash_crack runs a dictionary attack, but neither generates a hash nor does a
// single-shot verify). Unlike the rest of the credential cluster (internal/otp,
// nthash, unixcrypt, wpa — all native), bcrypt is NOT reimplemented natively:
// it is Blowfish-based, and a faithful port would require vendoring the
// 1024-entry Blowfish S-boxes (the hexadecimal digits of pi), which cannot be
// hand-verified — a copied, un-auditable constant table is less trustworthy
// than the audited golang.org/x/crypto/bcrypt, which is ALREADY a project
// dependency (hash_crack uses it). This is the documented-exception case the
// Wrap-vs-native convention allows: native genuinely infeasible, no new dep.
// Offline compute/verify from an operator-supplied string; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(bcryptSpec)
}

var bcryptSpec = Spec{
	Name: "bcrypt",
	Description: "Compute or verify a bcrypt password hash ($2a$/$2b$/$2y$) — the dominant modern " +
		"web-application password hash and the compute/verify side of the credential toolkit. " +
		"hash_identify recognises bcrypt (hashcat 3200) and hash_crack runs a dictionary attack, but " +
		"neither generates a hash nor does a single-shot verify. Use it to confirm a cracked password, " +
		"build a hash for an authorized lab/account, or check one candidate against a captured hash.\n\n" +
		"Provide **password** and either a full **hash** ($2…$) to verify against (constant-time, the " +
		"bcrypt design), or — for compute mode — an optional **cost** (4-31, default 10; each +1 doubles " +
		"the work). Output is the hash + embedded cost in compute mode, or matched true/false + the cost in " +
		"verify mode. bcrypt only considers the first 72 bytes of the password (a hard limit, surfaced as " +
		"an error).\n\n" +
		"Offline compute/verify from an operator-supplied string — no network, no device, transmits " +
		"nothing, so it is Low risk. Verified in-tree against the canonical published bcrypt vector plus a " +
		"generate→verify round-trip. Wrap-vs-native: wrap — bcrypt is Blowfish-based; a native port would " +
		"need the un-hand-verifiable 1024-entry S-box table, so the audited golang.org/x/crypto/bcrypt " +
		"(already a dependency, used by hash_crack) is used instead.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"password":{"type":"string","description":"The password to hash or verify (only the first 72 bytes are used)."},
			"hash":{"type":"string","description":"A full $2a$/$2b$/$2y$ bcrypt hash to verify the password against (verify mode)."},
			"cost":{"type":"integer","description":"Compute-mode cost factor 4-31 (default 10; each +1 doubles the work)."}
		},
		"required":["password"]
	}`),
	Required:  []string{"password"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   bcryptHandler,
}

func bcryptHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	password, ok := p["password"].(string)
	if !ok {
		return "", fmt.Errorf("bcrypt: 'password' is required")
	}

	// Verify mode: a full hash was supplied.
	if h := strings.TrimSpace(str(p, "hash")); h != "" {
		cost, costErr := bcrypt.Cost([]byte(h))
		if costErr != nil {
			return "", fmt.Errorf("bcrypt: not a valid bcrypt hash: %w", costErr)
		}
		err := bcrypt.CompareHashAndPassword([]byte(h), []byte(password))
		matched := err == nil
		if err != nil && !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return "", fmt.Errorf("bcrypt: %w", err)
		}
		out, _ := json.MarshalIndent(map[string]any{
			"mode": "verify", "matched": matched, "cost": cost, "scheme": "bcrypt",
		}, "", "  ")
		return string(out), nil
	}

	// Compute mode.
	cost := intOr(p, "cost", bcrypt.DefaultCost)
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return "", fmt.Errorf("bcrypt: cost must be %d-%d (got %d)", bcrypt.MinCost, bcrypt.MaxCost, cost)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		if errors.Is(err, bcrypt.ErrPasswordTooLong) {
			return "", fmt.Errorf("bcrypt: password exceeds bcrypt's 72-byte limit")
		}
		return "", fmt.Errorf("bcrypt: %w", err)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"mode": "compute", "hash": string(hash), "cost": cost, "scheme": "bcrypt",
	}, "", "  ")
	return string(out), nil
}
