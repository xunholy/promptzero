// phpass_password.go — host-side phpass (WordPress $P$ / phpBB $H$) password
// hash verify + compute Spec, delegating to internal/phpass.
//
// Wrap-vs-native: native — phpass is an iterated MD5 finished with phpass's own
// base64, over crypto/md5. WordPress is the most-deployed CMS, so its user-table
// hashes are a top offline-crack target (hashcat 400); this is the compute/
// verify side, complementing hash_crack's new phpass dictionary mode. Offline
// compute over operator-supplied strings; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/phpass"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(phpassPasswordSpec)
}

var phpassPasswordSpec = Spec{
	Name: "phpass_password",
	Description: "Compute or verify a phpass portable password hash — WordPress ($P$…) and phpBB3 ($H$…). " +
		"WordPress is the most-deployed CMS, so these are among the most common user-DB offline-crack " +
		"targets (hashcat 400); this is the compute/verify side (hash_crack also gained a 'phpass' " +
		"dictionary mode).\n\n" +
		"Provide **password** and either a full **hash** ($P$… / $H$…) to verify against (constant-time), " +
		"or — for compute mode — optional **magic** ($P$ default, or $H$), **rounds_log** (iteration " +
		"exponent, 2^rounds_log; WordPress uses 13), and **salt** (8 chars; random if omitted). Output is " +
		"matched true/false in verify mode, or the hash string in compute mode.\n\n" +
		"Offline compute from an operator-supplied string — no network, no device, transmits nothing, so it " +
		"is Low risk. Verified in-tree byte-for-byte against the reference passlib library. Wrap-vs-native: " +
		"native — iterated MD5 + phpass base64, standard-library only.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"password":{"type":"string","description":"The password to hash or verify."},
			"hash":{"type":"string","description":"A full phpass hash ($P$… / $H$…) to verify against (verify mode)."},
			"magic":{"type":"string","description":"Compute-mode scheme: $P$ (WordPress, default) or $H$ (phpBB3).","enum":["$P$","$H$"]},
			"rounds_log":{"type":"integer","description":"Compute-mode iteration exponent (2^rounds_log; default 13, WordPress)."},
			"salt":{"type":"string","description":"Compute-mode 8-char salt (random if omitted)."}
		},
		"required":["password"]
	}`),
	Required:  []string{"password"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   phpassPasswordHandler,
}

func phpassPasswordHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	password, ok := p["password"].(string)
	if !ok {
		return "", fmt.Errorf("phpass_password: 'password' is required")
	}

	// Verify mode.
	if h := strings.TrimSpace(str(p, "hash")); h != "" {
		matched, err := phpass.Verify(h, password)
		if err != nil {
			return "", fmt.Errorf("phpass_password: %w", err)
		}
		out, _ := json.MarshalIndent(map[string]any{"mode": "verify", "matched": matched}, "", "  ")
		return string(out), nil
	}

	// Compute mode.
	magic := strings.TrimSpace(str(p, "magic"))
	if magic == "" {
		magic = "$P$"
	}
	roundsLog := intOr(p, "rounds_log", 13)
	salt := str(p, "salt")
	if salt == "" {
		s, err := randomSalt(8)
		if err != nil {
			return "", fmt.Errorf("phpass_password: %w", err)
		}
		salt = s
	}
	hash, err := phpass.Compute(magic, roundsLog, salt, password)
	if err != nil {
		return "", fmt.Errorf("phpass_password: %w", err)
	}
	out, _ := json.MarshalIndent(map[string]any{"mode": "compute", "hash": hash}, "", "  ")
	return string(out), nil
}
