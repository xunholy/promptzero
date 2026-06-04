// SPDX-License-Identifier: AGPL-3.0-or-later

package netntlm

import "testing"

// authV2Hex is an NTLMSSP AUTHENTICATE message built (via impacket) to embed
// the canonical hashcat mode-5600 example's user (admin), domain (N46iSNekpT),
// and NtChallengeResponse (NTProofStr 88dcbe… ‖ blob 5c7830…).
const (
	authV2Hex       = "4e544c4d5353500003000000000000005e000000450045005e00000014001400400000000a000a0054000000000000005e00000000000000a3000000038208004e0034003600690053004e0065006b0070005400610064006d0069006e0088dcbe4446168966a153a0064958dac65c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030"
	serverChalV2    = "08ca45b7d7ea58ee"
	wantHashcat5600 = "admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030"
)

// TestNetNTLMv2MatchesHashcatExample anchors the assembled line byte-for-byte
// against the published hashcat 5600 example.
func TestNetNTLMv2MatchesHashcatExample(t *testing.T) {
	r, err := CrackLine(authV2Hex, serverChalV2)
	if err != nil {
		t.Fatalf("CrackLine: %v", err)
	}
	if r.Format != "NetNTLMv2" || r.HashcatMode != 5600 {
		t.Errorf("format/mode = %q / %d, want NetNTLMv2 / 5600", r.Format, r.HashcatMode)
	}
	if r.User != "admin" || r.Domain != "N46iSNekpT" {
		t.Errorf("user/domain = %q / %q", r.User, r.Domain)
	}
	if r.Line != wantHashcat5600 {
		t.Errorf("crack line mismatch:\n got  %q\n want %q", r.Line, wantHashcat5600)
	}
}

// TestServerChallengeFromChallengeRoundTrip + v1 use a synthetic case driven by
// the v2 vector's structure. Server-challenge extraction is exercised against a
// CHALLENGE message in the ntlm package's own tests; here we cover the tolerant
// hex input (separators) and the error paths.
func TestServerChallengeSeparatorsTolerated(t *testing.T) {
	r, err := CrackLine(authV2Hex, "08:ca:45:b7:d7:ea:58:ee")
	if err != nil {
		t.Fatalf("CrackLine with separators: %v", err)
	}
	if r.Line != wantHashcat5600 {
		t.Errorf("separator-tolerant server challenge produced a different line")
	}
}

func TestRejectsBadInputs(t *testing.T) {
	// Wrong server challenge length.
	if _, err := CrackLine(authV2Hex, "0102"); err == nil {
		t.Error("want error for a non-8-byte server challenge")
	}
	// Not an AUTHENTICATE message (a CHALLENGE message's bytes won't have
	// Authenticate set).
	if _, err := CrackLine("4e544c4d535350000200000000000000", serverChalV2); err == nil {
		t.Error("want error for a non-AUTHENTICATE message")
	}
	// Garbage.
	if _, err := CrackLine("notntlm", serverChalV2); err == nil {
		t.Error("want error for non-NTLM input")
	}
}
