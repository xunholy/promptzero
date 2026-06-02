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
	Description: "Compute the Windows NT (NTLM) and legacy LM hashes of a password — the compute side of " +
		"the credential toolkit. hash_identify recognises an NTLM/LM hash and hash_crack attacks one; this " +
		"produces one. Computing the hashes of a known or candidate password confirms a cracked password, " +
		"prepares a pass-the-hash value, or builds test data.\n\n" +
		"The NT hash is MD4 of the password encoded as little-endian UTF-16; the LM hash is DES of the " +
		"constant \"KGS!@#$%\" under each 7-byte half of the uppercased, 14-char password. Field: " +
		"**password** (any Unicode string). Output is the NT and LM hashes (hex), plus the full pwdump / " +
		"pass-the-hash line (LM:NT, hashcat -m 1000 NT / -m 3000 LM). LM is shown only for ASCII passwords " +
		"of ≤ 14 characters (Windows stores no LM hash otherwise — the disabled-LM placeholder is " +
		"shown with a note).\n\n" +
		"Offline compute from an operator-supplied string — no network, no device, transmits nothing, so " +
		"it is Low risk. Verified in-tree against the full RFC 1320 MD4 test suite, the published NTLM " +
		"vector (NTHash(\"password\") = 8846f7ea…), and three cross-confirming LM vectors. Wrap-vs-native: " +
		"native — MD4 implemented in-tree, LM via crypto/des, standard-library only.",
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

	// The LM hash: real value for an ASCII password of <=14 chars; otherwise the
	// disabled-LM placeholder (matching what Windows actually stores), with a note.
	lmHex := blankLM
	var notes []string
	switch {
	case hasNonASCII(pw):
		notes = append(notes, "LM hash omitted: LM is defined only for ASCII passwords (OEM-codepage dependent otherwise); the disabled-LM placeholder is shown")
	case len(pw) > 14:
		notes = append(notes, "LM hash omitted: Windows stores no LM hash for passwords longer than 14 characters; the disabled-LM placeholder is shown")
	default:
		lm, err := nthash.LMHash(pw)
		if err != nil {
			notes = append(notes, "LM hash omitted: "+err.Error())
		} else {
			lmHex = hex.EncodeToString(lm)
		}
	}

	res := map[string]any{
		"nt_hash":         nt,
		"lm_hash":         lmHex,
		"algorithm":       "NT = MD4(UTF-16LE(password)); LM = DES(\"KGS!@#$%\") per 7-byte half of UPPER(password)",
		"pwdump_line":     lmHex + ":" + nt,
		"hashcat_mode_nt": 1000,
		"hashcat_mode_lm": 3000,
	}
	if len(notes) > 0 {
		res["notes"] = notes
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}

// hasNonASCII reports whether s contains a non-ASCII rune.
func hasNonASCII(s string) bool {
	for _, r := range s {
		if r > 127 {
			return true
		}
	}
	return false
}
