// SPDX-License-Identifier: AGPL-3.0-or-later

// Package netntlm assembles the hashcat crack line for a captured NTLM
// challenge-response authentication — the loot of an SMB-relay / Responder /
// NTLM-over-HTTP capture. ntlm_decode surfaces the pieces (the server challenge
// from the CHALLENGE message and the NtChallengeResponse from the AUTHENTICATE
// message) but leaves the operator to hand-assemble the crack line; this closes
// that gap, emitting the ready-to-crack:
//
//	NetNTLMv2 (hashcat -m 5600): user::domain:serverChallenge:NTProofStr:blob
//	NetNTLMv1 (hashcat -m 5500): user::domain:LMresp:NTresp:serverChallenge
//
// from the AUTHENTICATE message + the server challenge. The version is chosen by
// the NtChallengeResponse length (exactly 24 bytes = NTLMv1, longer = NTLMv2,
// whose response is NTProofStr(16) ‖ blob). Pure offline transform; no network
// or device.
//
// # Wrap-vs-native judgement
//
// Native. It reuses the in-tree internal/ntlm AUTHENTICATE parser and does a
// length split + string format — there is nothing to wrap. Consistent with the
// other in-tree credential/loot tooling.
//
// # Verifiable / no confidently-wrong output
//
// Anchored to the canonical hashcat mode-5600 example hash
// (admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe…:5c7830…): an AUTHENTICATE message
// built (via impacket) to embed that example's user / domain / NtChallengeResponse,
// combined with the example's server challenge, reproduces the example line
// byte-for-byte. The input must be an NTLMSSP AUTHENTICATE message with an
// NtChallengeResponse and an 8-byte server challenge, else it errors — it never
// emits a malformed/guessed line.
package netntlm

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ntlm"
)

// Result is the assembled crack line.
type Result struct {
	Format      string `json:"format"`       // NetNTLMv1 / NetNTLMv2
	HashcatMode int    `json:"hashcat_mode"` // 5500 / 5600
	User        string `json:"user,omitempty"`
	Domain      string `json:"domain,omitempty"`
	Line        string `json:"crack_line"`
	Note        string `json:"note,omitempty"`
}

// CrackLine builds the hashcat NetNTLM crack line from an NTLMSSP AUTHENTICATE
// message (hex) and the 8-byte server challenge (hex, from the prior CHALLENGE
// message — see ServerChallengeFromChallenge).
func CrackLine(authenticateHex, serverChallengeHex string) (*Result, error) {
	res, err := ntlm.Decode(authenticateHex)
	if err != nil {
		return nil, fmt.Errorf("netntlm: AUTHENTICATE decode: %w", err)
	}
	a := res.Authenticate
	if a == nil {
		return nil, fmt.Errorf("netntlm: not an NTLMSSP AUTHENTICATE message (got %s)", res.MessageTypeName)
	}
	scb, err := hexClean(serverChallengeHex)
	if err != nil {
		return nil, fmt.Errorf("netntlm: server_challenge: %w", err)
	}
	if len(scb) != 8 {
		return nil, fmt.Errorf("netntlm: server_challenge must be 8 bytes, got %d", len(scb))
	}
	sc := hex.EncodeToString(scb)

	ntb, err := hex.DecodeString(a.NtChallengeResponseHex)
	if err != nil || len(ntb) == 0 {
		return nil, fmt.Errorf("netntlm: AUTHENTICATE has no usable NtChallengeResponse")
	}
	user, domain := a.UserName, a.DomainName

	if len(ntb) == 24 {
		// NetNTLMv1 (hashcat 5500).
		lm := a.LmChallengeResponseHex
		if lm == "" {
			lm = strings.Repeat("0", 48)
		}
		return &Result{
			Format: "NetNTLMv1", HashcatMode: 5500, User: user, Domain: domain,
			Line: fmt.Sprintf("%s::%s:%s:%s:%s", user, domain, lm, a.NtChallengeResponseHex, sc),
			Note: "crack with: hashcat -m 5500 (NetNTLMv1; consider NTLM downgrade / ESS context)",
		}, nil
	}
	if len(ntb) < 16 {
		return nil, fmt.Errorf("netntlm: NtChallengeResponse %d bytes — too short for NTLMv2", len(ntb))
	}
	// NetNTLMv2 (hashcat 5600): NtChallengeResponse = NTProofStr(16) ‖ blob.
	ntProof := hex.EncodeToString(ntb[:16])
	blob := hex.EncodeToString(ntb[16:])
	return &Result{
		Format: "NetNTLMv2", HashcatMode: 5600, User: user, Domain: domain,
		Line: fmt.Sprintf("%s::%s:%s:%s:%s", user, domain, sc, ntProof, blob),
		Note: "crack with: hashcat -m 5600 (NetNTLMv2)",
	}, nil
}

// ServerChallengeFromChallenge extracts the 8-byte server challenge (hex) from
// an NTLMSSP CHALLENGE message, for feeding to CrackLine.
func ServerChallengeFromChallenge(challengeHex string) (string, error) {
	res, err := ntlm.Decode(challengeHex)
	if err != nil {
		return "", fmt.Errorf("netntlm: CHALLENGE decode: %w", err)
	}
	if res.Challenge == nil {
		return "", fmt.Errorf("netntlm: not an NTLMSSP CHALLENGE message (got %s)", res.MessageTypeName)
	}
	return res.Challenge.ServerChallenge, nil
}

func hexClean(s string) ([]byte, error) {
	s = strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "",
		":", "", "-", "", "_", "", "0x", "", "0X", "").Replace(strings.TrimSpace(s))
	return hex.DecodeString(s)
}
