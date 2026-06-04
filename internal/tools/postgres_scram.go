// postgres_scram.go — host-side PostgreSQL SCRAM-SHA-256 verifier compute +
// verify Spec, delegating to internal/pgscram.
//
// Wrap-vs-native: native — the PostgreSQL scram-sha-256 stored verifier is
// PBKDF2-HMAC-SHA256 (the in-tree internal/wpa.PBKDF2) + two HMAC-SHA256 passes
// + SHA-256 + base64, per RFC 5802 / RFC 7677. It is an offline credential
// primitive: compute the verifier for a candidate password, or verify a
// candidate against a verifier from a pg_authid dump. The modern (PG 10+)
// successor to postgres_password's md5 verifier. Offline compute from
// operator-supplied strings; no network or device.

package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/pgscram"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(postgresScramSpec)
}

var postgresScramSpec = Spec{
	Name: "postgres_scram",
	Description: "Compute or verify a PostgreSQL SCRAM-SHA-256 password verifier — the value stored in " +
		"pg_authid.rolpassword for a role using scram-sha-256 authentication (the **default since " +
		"PostgreSQL 10**, the modern successor to the md5 verifier handled by postgres_password; hashcat " +
		"mode 28600). Use it to confirm a password recovered from a pg_authid / `pg_dumpall --globals` " +
		"dump, build a test credential for an authorized lab, or check a candidate against a captured " +
		"verifier.\n\n" +
		"The stored verifier is `SCRAM-SHA-256$<iterations>:<base64 salt>$<base64 StoredKey>:<base64 " +
		"ServerKey>` where (RFC 5802): SaltedPassword = PBKDF2-HMAC-SHA256(password, salt, iterations); " +
		"ClientKey = HMAC(SaltedPassword, 'Client Key'); StoredKey = SHA256(ClientKey); ServerKey = " +
		"HMAC(SaltedPassword, 'Server Key'). Verification recomputes StoredKey from the candidate password " +
		"+ the verifier's own salt/iterations and constant-time compares.\n\n" +
		"Provide **password** and either a full **verifier** (`SCRAM-SHA-256$…`) to verify against, or — " +
		"for compute mode — an optional **salt** (base64; random 16-byte if omitted) and **iterations** " +
		"(default 4096, PostgreSQL's default). Output is the verifier string in compute mode, or matched " +
		"true/false plus iterations + salt length in verify mode.\n\n" +
		"Offline compute from an operator-supplied string — no network, no device, transmits nothing, so " +
		"it is Low risk. A malformed verifier (wrong prefix / field count / base64 / iteration count) is " +
		"rejected, never silently \"verified\". Verified in-tree against the **RFC 7677 §3** worked example " +
		"(password 'pencil') — the derivation reproduces the RFC's ClientProof and ServerSignature " +
		"byte-for-byte. Non-ASCII passwords: PostgreSQL applies SASLprep (RFC 4013), a no-op for ASCII; " +
		"this tool matches that for ASCII and uses raw UTF-8 otherwise. Wrap-vs-native: native — " +
		"internal/wpa.PBKDF2 + crypto/hmac + crypto/sha256, standard-library only.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"password":{"type":"string","description":"The password to hash or verify."},
			"verifier":{"type":"string","description":"A full SCRAM-SHA-256$… verifier to check the password against (verify mode)."},
			"salt":{"type":"string","description":"Compute-mode salt as base64 (random 16-byte if omitted)."},
			"iterations":{"type":"integer","description":"Compute-mode PBKDF2 iteration count (default 4096)."}
		},
		"required":["password"]
	}`),
	Required:  []string{"password"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   postgresScramHandler,
}

func postgresScramHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	password, ok := p["password"].(string)
	if !ok {
		return "", fmt.Errorf("postgres_scram: 'password' is required")
	}

	// Verify mode: a full verifier was supplied.
	if v := strings.TrimSpace(str(p, "verifier")); v != "" {
		res, err := pgscram.Verify(password, v)
		if err != nil {
			return "", fmt.Errorf("postgres_scram: %w", err)
		}
		out, _ := json.MarshalIndent(map[string]any{
			"mode": "verify", "matched": res.Matched, "scheme": "scram-sha-256",
			"iterations": res.Iterations, "salt_len": res.SaltLen,
		}, "", "  ")
		return string(out), nil
	}

	// Compute mode.
	var salt []byte
	if s := strings.TrimSpace(str(p, "salt")); s != "" {
		dec, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return "", fmt.Errorf("postgres_scram: salt must be base64: %w", err)
		}
		salt = dec
	}
	iterations := 0
	if n, ok := p["iterations"].(float64); ok {
		iterations = int(n)
	}
	verifier, err := pgscram.Compute(password, salt, iterations)
	if err != nil {
		return "", fmt.Errorf("postgres_scram: %w", err)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"mode": "compute", "scheme": "scram-sha-256", "verifier": verifier,
	}, "", "  ")
	return string(out), nil
}
