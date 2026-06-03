// mysql_password.go — host-side MySQL / MariaDB mysql_native_password compute +
// verify Spec, delegating to internal/mysqlpw.
//
// Wrap-vs-native: native — mysql_native_password is an unsalted double SHA-1
// ("*" + UPPER(hex(SHA1(SHA1(password))))) over crypto/sha1. It is an offline
// credential primitive: compute the hash of a candidate password, or verify a
// candidate against a hash from a mysql.user dump. Complements hash_identify
// (which recognises it as MySQL4.1+, hashcat 300) and hash_crack_dictionary
// (which attacks it). Offline compute from operator-supplied strings; no
// network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/mysqlpw"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(mysqlPasswordSpec)
}

var mysqlPasswordSpec = Spec{
	Name: "mysql_password",
	Description: "Compute or verify a MySQL / MariaDB mysql_native_password hash — the value stored in " +
		"mysql.user (the \"4.1+\" PASSWORD() format, hashcat mode 300) and the compute/verify side of the " +
		"credential toolkit (hash_identify recognises it as MySQL4.1+, hash_crack_dictionary attacks it, but " +
		"neither could produce or check one). Use it to confirm a password recovered from a mysql.user dump, " +
		"build a test credential for an authorized lab, or check a candidate against a captured hash.\n\n" +
		"The hash is an unsalted double SHA-1: `*` + UPPER(hex(SHA1(SHA1(password)))) — a 41-character string " +
		"(literal '*' + 40 uppercase hex). There is no per-row salt, so equal passwords share a hash.\n\n" +
		"Provide **password** and either a full **hash** (`*`-prefixed or bare 40-hex, either case) to verify " +
		"against (constant-time compared), or nothing else to compute. Output is the hash in compute mode, or " +
		"matched true/false in verify mode.\n\n" +
		"Offline compute from an operator-supplied string — no network, no device, transmits nothing, so it " +
		"is Low risk. A malformed hash (wrong length / non-hex) is rejected, never silently \"verified\". The " +
		"pre-4.1 OLD_PASSWORD (16-hex, hashcat 200) and the caching_sha2_password / sha256_password plugins " +
		"(salted, iterated) are out of scope. Verified in-tree against the published MySQL vector " +
		"PASSWORD('password') = *2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19. Wrap-vs-native: native — " +
		"crypto/sha1, standard-library only.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"password":{"type":"string","description":"The password to hash or verify."},
			"hash":{"type":"string","description":"A full mysql_native_password hash to verify against (verify mode): '*'+40 hex, or bare 40 hex, either case."}
		},
		"required":["password"]
	}`),
	Required:  []string{"password"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   mysqlPasswordHandler,
}

func mysqlPasswordHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	password, ok := p["password"].(string)
	if !ok {
		return "", fmt.Errorf("mysql_password: 'password' is required")
	}

	// Verify mode: a full hash was supplied.
	if h := strings.TrimSpace(str(p, "hash")); h != "" {
		matched, err := mysqlpw.Verify(password, h)
		if err != nil {
			return "", fmt.Errorf("mysql_password: %w", err)
		}
		out, _ := json.MarshalIndent(map[string]any{
			"mode": "verify", "matched": matched, "scheme": "mysql_native_password",
		}, "", "  ")
		return string(out), nil
	}

	// Compute mode.
	out, _ := json.MarshalIndent(map[string]any{
		"mode": "compute", "scheme": "mysql_native_password", "hash": mysqlpw.Compute(password),
	}, "", "  ")
	return string(out), nil
}
