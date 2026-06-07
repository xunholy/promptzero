// SPDX-License-Identifier: AGPL-3.0-or-later

package ir

import "testing"

// FuzzDecodeRaw exercises the raw IR timing decoder (NEC / Samsung / SIRC /
// RC5 dispatch) on arbitrary timing strings — leader detection, the
// pulse-distance bit reader, the SIRC pulse-width reader and the RC5 Manchester
// reconstruction must never panic or index out of range on malformed /
// truncated / non-numeric input.
func FuzzDecodeRaw(f *testing.F) {
	seeds := []string{
		"",
		"9000 4500",
		"9000 2250 560",
		genNEC(0x04, 0x08),
		genSamsung(0x07, 0x02),
		genSIRC(0x12, 0x05, 0, 12),
		genRC5(0x14, 0x01, 0),
		genRC5(0x00, 0x40, 1),
		"889 889 1778 889 889",
		"2400 600 1200 600",
		kaseikyoOK,
		"3456 1728 432 432",
		"abc def",
		"9000",
		"-9000 -4500 560 560",
		"4500 4500 560 1690",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = DecodeRaw(s) })
}
