// postgres_password.go — host-side PostgreSQL md5 password compute + verify
// Spec, delegating to internal/pgpassword.
//
// Wrap-vs-native: native — PostgreSQL's md5 authentication value is a single
// salted MD5 ("md5" + hex(MD5(password+username))) over crypto/md5. It is an
// offline credential primitive: compute the stored value for a candidate
// password, or verify a candidate against a value from a pg_authid /
// pg_dumpall --globals dump. The DB-credential sibling of mysql_password.
// Offline compute from operator-supplied strings; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/pgpassword"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(postgresPasswordSpec)
}

var postgresPasswordSpec = Spec{
	Name: "postgres_password",
	Description: "Compute or verify a PostgreSQL md5 password — the value stored in pg_authid.rolpassword " +
		"(pg_shadow.passwd) for a role using md5 authentication (hashcat mode 12), and the DB-credential " +
		"sibling of mysql_password. Use it to confirm a password recovered from a pg_authid / `pg_dumpall " +
		"--globals` dump, build a test credential for an authorized lab, or check a candidate against a " +
		"captured value.\n\n" +
		"PostgreSQL salts the password with the **role name** before a single MD5: the stored value is " +
		"`md5` + hex(MD5(password ‖ username)) — the literal 'md5' followed by 32 lowercase hex digits. " +
		"Because the salt is the username, the same password under two roles yields different values, so " +
		"**verification requires the username** as well as the password.\n\n" +
		"Provide **password** + **username**, and either a full **hash** (`md5`-prefixed or bare 32-hex, " +
		"either case) to verify against (constant-time compared), or nothing else to compute. Output is the " +
		"stored value in compute mode, or matched true/false in verify mode.\n\n" +
		"Offline compute from an operator-supplied string — no network, no device, transmits nothing, so it " +
		"is Low risk. A malformed value (missing 'md5' prefix / wrong length / non-hex) is rejected, never " +
		"silently \"verified\". SCRAM-SHA-256 (the PostgreSQL 10+ default, hashcat 28600 — salted + iterated " +
		"PBKDF2/HMAC) is out of scope. Verified in-tree against the documented pg_md5_encrypt construction. " +
		"Wrap-vs-native: native — crypto/md5, standard-library only.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"password":{"type":"string","description":"The password to hash or verify."},
			"username":{"type":"string","description":"The PostgreSQL role name — the salt. Required (the stored value is md5(password+username))."},
			"hash":{"type":"string","description":"A full PostgreSQL md5 value to verify against (verify mode): 'md5'+32 hex, or bare 32 hex, either case."}
		},
		"required":["password","username"]
	}`),
	Required:  []string{"password", "username"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   postgresPasswordHandler,
}

func postgresPasswordHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	password, ok := p["password"].(string)
	if !ok {
		return "", fmt.Errorf("postgres_password: 'password' is required")
	}
	username, ok := p["username"].(string)
	if !ok {
		return "", fmt.Errorf("postgres_password: 'username' is required (it is the salt)")
	}

	// Verify mode: a full hash was supplied.
	if h := strings.TrimSpace(str(p, "hash")); h != "" {
		matched, err := pgpassword.Verify(password, username, h)
		if err != nil {
			return "", fmt.Errorf("postgres_password: %w", err)
		}
		out, _ := json.MarshalIndent(map[string]any{
			"mode": "verify", "matched": matched, "scheme": "postgres-md5",
		}, "", "  ")
		return string(out), nil
	}

	// Compute mode.
	out, _ := json.MarshalIndent(map[string]any{
		"mode": "compute", "scheme": "postgres-md5", "hash": pgpassword.Compute(password, username),
	}, "", "  ")
	return string(out), nil
}
