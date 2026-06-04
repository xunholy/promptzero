// netntlm_hashcat.go — host-side NetNTLM crack-line builder Spec, delegating to
// internal/netntlm.
//
// Wrap-vs-native: native — it reuses the in-tree internal/ntlm AUTHENTICATE
// parser and assembles the hashcat 5500/5600 crack line (a length split + a
// format string). The capture->crackable-hash step of the SMB-relay / Responder
// loot workflow, complementing ntlm_decode (which surfaces the pieces). Offline.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/netntlm"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(netntlmHashcatSpec)
}

var netntlmHashcatSpec = Spec{
	Name: "netntlm_hashcat",
	Description: "Assemble the **hashcat crack line** for a captured NTLM challenge-response authentication — " +
		"the capture→crackable-hash step of the SMB-relay / Responder / NTLM-over-HTTP loot workflow. " +
		"ntlm_decode surfaces the pieces (the server challenge from the CHALLENGE message, the " +
		"NtChallengeResponse from the AUTHENTICATE message) but leaves you to hand-assemble; this emits the " +
		"ready-to-crack line:\n\n" +
		"- **NetNTLMv2** (hashcat `-m 5600`): `user::domain:serverChallenge:NTProofStr:blob` (the modern " +
		"default; NtChallengeResponse = NTProofStr(16 bytes) ‖ blob).\n" +
		"- **NetNTLMv1** (hashcat `-m 5500`): `user::domain:LMresp:NTresp:serverChallenge` (when the " +
		"NtChallengeResponse is exactly 24 bytes — e.g. an NTLM-downgrade capture).\n\n" +
		"Provide **authenticate** (the NTLMSSP AUTHENTICATE message hex — what ntlm_decode reads) and the " +
		"8-byte **server_challenge** hex (from `ntlm_decode` of the prior CHALLENGE message), OR provide the " +
		"full **challenge** message hex and the server challenge is extracted from it. Output is the crack " +
		"line + the hashcat mode + the user/domain.\n\n" +
		"Pure offline transform — reads operator-supplied hex, transmits nothing, so it is Low risk. The " +
		"input must be an NTLMSSP AUTHENTICATE message with an NtChallengeResponse and an 8-byte server " +
		"challenge, else it errors (never a malformed/guessed line). Verified in-tree against the canonical " +
		"hashcat mode-5600 example (admin::N46iSNekpT:…), reproduced byte-for-byte. Wrap-vs-native: native — " +
		"reuses the internal/ntlm parser; a length split + format string.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"authenticate":{"type":"string","description":"The NTLMSSP AUTHENTICATE message as hex (the type-3 message; the same input ntlm_decode takes)."},
			"server_challenge":{"type":"string","description":"The 8-byte server challenge as hex (from ntlm_decode of the CHALLENGE message). Separators tolerated."},
			"challenge":{"type":"string","description":"Alternatively, the full NTLMSSP CHALLENGE message hex; the server challenge is extracted from it."}
		},
		"required":["authenticate"]
	}`),
	Required:  []string{"authenticate"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   netntlmHashcatHandler,
}

func netntlmHashcatHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	auth := strings.TrimSpace(str(p, "authenticate"))
	if auth == "" {
		return "", fmt.Errorf("netntlm_hashcat: 'authenticate' is required")
	}
	sc := strings.TrimSpace(str(p, "server_challenge"))
	if sc == "" {
		if ch := strings.TrimSpace(str(p, "challenge")); ch != "" {
			extracted, err := netntlm.ServerChallengeFromChallenge(ch)
			if err != nil {
				return "", fmt.Errorf("netntlm_hashcat: %w", err)
			}
			sc = extracted
		} else {
			return "", fmt.Errorf("netntlm_hashcat: provide 'server_challenge' (8-byte hex) or 'challenge' (the CHALLENGE message hex)")
		}
	}
	res, err := netntlm.CrackLine(auth, sc)
	if err != nil {
		return "", fmt.Errorf("netntlm_hashcat: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
