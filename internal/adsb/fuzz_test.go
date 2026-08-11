// SPDX-License-Identifier: AGPL-3.0-or-later

package adsb

import (
	"encoding/hex"
	"testing"
)

// FuzzDecode asserts the parser never panics on arbitrary input. The
// fuzzer's raw bytes are hex-encoded so every input reaches the binary
// parser itself (not the hex-reject path) — the untrusted paste-and-decode
// surface. Length/count fields, nesting, and offsets must be bounds-checked.
func FuzzDecode(f *testing.F) {
	for _, s := range [][]byte{{}, {0x00}, {0x01, 0x02, 0x03, 0x04}, {0xff, 0xff, 0xff, 0xff}} {
		f.Add(s)
	}
	// DF20 Comm-B frames exercise the BDS register inference + decode path.
	for _, h := range []string{
		"A000029C85E42F313000007047D3", // BDS40
		"A000139381951536E024D4CCF6B5", // BDS50
		"A00004128F39F91A7E27C46ADC21", // BDS60
		"A000083E202CC371C31DE0AA1CCF", // BDS20
		"28000AAA000000",               // DF5 squawk 7700 (emergency)
		"20000C83000000",               // DF4 altitude 38000 (Gillham)
		"200003B0000000",               // DF4 altitude 5000 (25-ft)
	} {
		if b, err := hex.DecodeString(h); err == nil {
			f.Add(b)
		}
	}
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = Decode(hex.EncodeToString(b)) // must not panic
	})
}

// FuzzBDSExplicit asserts the explicit Comm-B register decoders never panic
// on arbitrary MB fields. These are reached from the adsb_bds30/44/45 tools
// with operator/SDR-supplied hex — an attacker-influenceable surface the
// full-frame FuzzDecode does not cover (it goes through the register
// inference, not the explicit decoders).
func FuzzBDSExplicit(f *testing.F) {
	for _, h := range []string{
		"185BD5CF400000", // BDS44 golden
		"0001FB80000000", // BDS45 golden
		"30E0000686CB0C", // BDS30 golden
		"", "00", "00000000000000", "FFFFFFFFFFFFFF",
	} {
		if b, err := hex.DecodeString(h); err == nil {
			f.Add(b)
		}
	}
	f.Fuzz(func(_ *testing.T, b []byte) {
		if len(b) < 7 {
			return // the decoders require a 7-byte MB (guarded by len < 7 -> nil)
		}
		_ = DecodeBDS30(b)
		_ = DecodeBDS44(b)
		_ = DecodeBDS45(b)
	})
}

// FuzzCPRFrames asserts the CPR frame-pair resolvers never panic on arbitrary
// hex frames. GlobalPositionFromFrames / LocalPositionFromFrame are reached
// from the adsb_cpr_decode / adsb_cpr_local tools; they parse two frames and
// run float position maths, so a malformed pair must resolve to an error, not
// a crash.
func FuzzCPRFrames(f *testing.F) {
	for _, pair := range [][2]string{
		{"8D40621D58C382D690C8AC2863A7", "8D40621D58C386435CC412692AD6"},
		{"", ""},
		{"8D4840D6202CC371C32CE0576098", "00"},
	} {
		f.Add(pair[0], pair[1])
	}
	f.Fuzz(func(_ *testing.T, a, b string) {
		_, _ = GlobalPositionFromFrames(a, b, true)
		_, _ = GlobalPositionFromFrames(a, b, false)
		_, _ = LocalPositionFromFrame(a, 52.0, 3.9)
	})
}
