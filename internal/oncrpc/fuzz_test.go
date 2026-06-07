// SPDX-License-Identifier: AGPL-3.0-or-later

package oncrpc

import (
	"encoding/hex"
	"testing"
)

// FuzzParse exercises the ONC RPC (Sun RPC) message decoder — reachable from
// the nlm_decode tool with attacker-controlled bytes — on arbitrary input; it
// must never panic (a malformed / truncated message returns an error or a
// *Message, never a crash).
func FuzzParse(f *testing.F) {
	seeds := []string{
		// portmap GETPORT call (xid 0x11223344, prog 100000, v2, proc 3)
		"112233440000000000000002000186a0000000020000000300000000000000000000000000000000000186a3000000030000001100000000",
		// accepted reply
		"11223344000000010000000000000000000000000000000000000801",
		// call with auth flavor + verifier + body
		"0000000100000000" + "00000002000186a500000003000000010000000100000004aabbccdd00000000" + "00000000" + "deadbeef",
		"112233", // too short
		"",
	}
	for _, s := range seeds {
		if b, err := hex.DecodeString(s); err == nil {
			f.Add(b)
		}
	}
	f.Fuzz(func(_ *testing.T, b []byte) { _, _ = Parse(b) })
}
