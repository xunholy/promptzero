// SPDX-License-Identifier: AGPL-3.0-or-later

package subghz

import "testing"

// FuzzAnalyzeJamming asserts the RSSI analyser never panics — percentile
// interpolation, the occupancy/dwell scan, and the stats must hold for any
// sample slice (including single-element and extreme values).
func FuzzAnalyzeJamming(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{200})
	f.Add([]byte{0, 50, 100, 150, 200, 255})
	f.Fuzz(func(_ *testing.T, b []byte) {
		samples := make([]float64, len(b))
		for i, v := range b {
			samples[i] = -float64(v) // map 0..255 -> 0..-255 dBm-ish
		}
		_, _ = AnalyzeJamming(samples, JammingOpts{}) // must not panic
	})
}
