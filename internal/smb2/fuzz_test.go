// SPDX-License-Identifier: AGPL-3.0-or-later

package smb2

import (
	"encoding/hex"
	"testing"
)

func FuzzDecode(f *testing.F) {
	seeds := []string{
		hex.EncodeToString(sessionSetupResponse(ntlmType2())),
		hex.EncodeToString(sessionSetupRequest(ntlmType2())),
		hex.EncodeToString(sessionSetupResponse([]byte{0x60, 0x82, 0x02, 0x00})), // Kerberos-ish, no NTLMSSP
		hex.EncodeToString(header(0x00, 0x00, 0x00, 1, 0, 0)),                    // bare negotiate header
		"FE534D42",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		// Must never panic for any input, including malformed security buffers
		// routed into the NTLM decoder.
		_, _ = Decode(s)
	})
}
