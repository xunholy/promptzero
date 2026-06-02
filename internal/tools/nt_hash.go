// nt_hash.go — host-side Windows NT (NTLM) hash compute Spec, delegating to
// internal/nthash.
//
// Wrap-vs-native: native — the NT hash is MD4(UTF-16LE(password)); MD4 (RFC
// 1320) is implemented in-tree rather than taken from the discouraged
// golang.org/x/crypto/md4. It is the compute side of the credential toolkit:
// hash_identify recognises an NTLM hash and hash_crack attacks one, but neither
// produces one. Computing an NT hash from a known/candidate password confirms a
// cracked password, prepares a pass-the-hash value, or builds test data.
// Offline compute from an operator-supplied string; no network or device.

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/nthash"
	"github.com/xunholy/promptzero/internal/risk"
)

// blankLM is the LM hash of an empty/disabled password — the constant placeholder
// that fills the LM field of a modern pwdump/PtH line (no LM hash is computed).
const blankLM = "aad3b435b51404eeaad3b435b51404ee"

func init() { //nolint:gochecknoinits
	Register(ntHashSpec)
}

var ntHashSpec = Spec{
	Name: "nt_hash",
	Description: "Compute the Windows NT (NTLM) hash of a password — the compute side of the credential " +
		"toolkit. hash_identify recognises an NTLM hash and hash_crack attacks one; this produces one. " +
		"Computing the NT hash of a known or candidate password confirms a cracked password, prepares a " +
		"pass-the-hash value, or builds test data.\n\n" +
		"The NT hash is MD4 of the password encoded as little-endian UTF-16 (the Windows convention). " +
		"Field: **password** (any Unicode string). Output is the NT hash (hex), plus a pwdump / " +
		"pass-the-hash line (blankLM:NT — the LM field is the fixed no-LM placeholder, hashcat -m 1000 / " +
		"PtH form). The legacy LM hash is out of scope.\n\n" +
		"Offline compute from an operator-supplied string — no network, no device, transmits nothing, so " +
		"it is Low risk. Verified in-tree against the full RFC 1320 MD4 test suite and the published NTLM " +
		"vector (NTHash(\"password\") = 8846f7ea…). Wrap-vs-native: native — MD4 implemented in-tree, " +
		"standard-library only.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"password":{"type":"string","description":"The password to hash (any Unicode string; encoded UTF-16LE per Windows)."}
		},
		"required":["password"]
	}`),
	Required:  []string{"password"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ntHashHandler,
}

func ntHashHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	pw, ok := p["password"].(string)
	if !ok {
		return "", fmt.Errorf("nt_hash: 'password' is required")
	}
	nt := hex.EncodeToString(nthash.NTHash(pw))
	out, _ := json.MarshalIndent(map[string]any{
		"nt_hash":      nt,
		"algorithm":    "MD4(UTF-16LE(password))",
		"pwdump_line":  blankLM + ":" + nt,
		"hashcat_mode": 1000,
	}, "", "  ")
	return string(out), nil
}
