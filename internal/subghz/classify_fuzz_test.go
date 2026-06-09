// SPDX-License-Identifier: AGPL-3.0-or-later

package subghz

import (
	"strings"
	"testing"
)

// pulsesFromBytes derives a signed pulse train from fuzz bytes: each byte's
// low bit selects mark (+) vs space (-) and the remaining bits scale a 100 µs
// grid, so the fuzzer controls both the sign pattern and the magnitudes across
// the decoders' timing windows (≈100 µs … 12.8 ms) — including the
// non-alternating mark/space sequences every decoder must reject gracefully.
func pulsesFromBytes(b []byte) []int {
	pulses := make([]int, len(b))
	for i, v := range b {
		mag := (int(v>>1) + 1) * 100
		if v&1 == 0 {
			mag = -mag
		}
		pulses[i] = mag
	}
	return pulses
}

// FuzzClassify asserts the Classifier — every one of the 33 registered pulse
// decoders — never panics or hangs on an arbitrary pulse train. The decoders
// index pulses[i+1] inside their bit loops and do arithmetic on attacker-shaped
// durations, so this is the high-leverage harness: one input exercises all of
// them at once. The derived top-n (including n <= 0, the "return all" path) is
// also fuzzed.
func FuzzClassify(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1})
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7})
	// A spread that lands near several decoders' te windows.
	f.Add([]byte{200, 201, 100, 101, 50, 51, 20, 21, 8, 9})
	f.Fuzz(func(_ *testing.T, b []byte) {
		pulses := pulsesFromBytes(b)
		n := len(b) % 7 // 0..6 — n==0 hits the "return every match" branch
		_ = NewClassifier().Classify(pulses, n)
	})
}

// FuzzParseSub asserts the .sub file parser and the full parse→classify
// pipeline never panic on arbitrary file text — the RAW_Data integer scan, the
// header parsing, and the downstream classification of whatever pulses come
// out. Operators feed untrusted capture files here.
func FuzzParseSub(f *testing.F) {
	f.Add("")
	f.Add("RAW_Data: 1 2 3")
	f.Add("Filetype: Flipper SubGhz Key File\nVersion: 1\n" +
		"Frequency: 433920000\nPreset: FuriHalSubGhzPresetOok650Async\n" +
		"Protocol: RAW\nRAW_Data: 350 -350 1050 -350 350 -1050\n")
	f.Fuzz(func(_ *testing.T, s string) {
		sf, err := Parse(strings.NewReader(s))
		if err != nil || sf == nil {
			return
		}
		_ = NewClassifier().Classify(sf.Pulses, 3) // pipeline must not panic
	})
}
