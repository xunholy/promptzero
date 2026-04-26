// SPDX-License-Identifier: AGPL-3.0-or-later

// Package subghz — fixture generation helpers.
// This file is in package subghz (not subghz_test) to access internal helpers.
// The TestGenFixtures function is the authoritative generator for the synthetic
// .sub files under testdata/. Run with -run TestGenFixtures to regenerate.

package subghz_test

import (
	"os"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/subghz"
)

// TestGenFixtures writes the synthetic .sub test fixtures to testdata/.
// Not a regular test; it writes files and can be run with:
//
//	go test -run TestGenFixtures ./internal/subghz/testdata/
func TestGenFixtures(t *testing.T) {
	dir := "." // This file is IN testdata/, so "." is the right dir.

	// Princeton PT2262: addr=0xAAA data=0x5 te=350
	{
		val := uint32((0xAAA << 4) | 0x5)
		bits := make([]byte, 16)
		for i := 0; i < 16; i++ {
			bits[i] = byte((val >> uint(15-i)) & 1)
		}
		pulses := subghz.EncodePWMPulses(bits, 350, 1, 31, 3, 1, 1, 3, 3)
		text := subghz.SubFileString(433920000, "FuriHalSubGhzPresetOok650Async", pulses)
		write(t, dir+"/princeton_pt2262.sub", text)
	}

	// CAME: code=0xA5B te=320
	{
		code := uint32(0xA5B)
		bits := make([]byte, 12)
		for i := 0; i < 12; i++ {
			bits[i] = byte((code >> uint(11-i)) & 1)
		}
		var camePulses []int
		camePulses = append(camePulses, 320, -(36*320))
		for _, b := range bits {
			if b != 0 {
				camePulses = append(camePulses, 320, -320)
			} else {
				camePulses = append(camePulses, 320, -(2 * 320))
			}
		}
		// 3 repetitions
		full := make([]int, len(camePulses))
		copy(full, camePulses)
		for i := 1; i < 3; i++ {
			full = append(full, camePulses...)
		}
		text := subghz.SubFileString(433920000, "FuriHalSubGhzPresetOok650Async", full)
		write(t, dir+"/came.sub", text)
	}

	// KeeLoq HCS: hopping=0xDEADC0DE serial=0x12345678 button=1 te=400 (LSB-first)
	{
		hopping := uint32(0xDEADC0DE)
		serial := uint32(0x12345678)
		button := uint32(0x1)
		bits := make([]byte, 0, 66)
		// LSB-first for hopping
		for i := 0; i < 32; i++ {
			bits = append(bits, byte((hopping>>uint(i))&1))
		}
		for i := 0; i < 32; i++ {
			bits = append(bits, byte((serial>>uint(i))&1))
		}
		bits = append(bits, byte(button&1), byte((button>>1)&1))

		pulses := subghz.EncodePWMPulses(bits, 400, 1, 10, 3, 1, 1, 3, 3)
		text := subghz.SubFileString(433920000, "FuriHalSubGhzPresetOok650Async", pulses)
		write(t, dir+"/keeloq_hcs.sub", text)
	}

	t.Logf("fixtures written to %s", dir)
	_ = strings.Contains("", "") // suppress import
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil { //nolint:gosec
		t.Fatalf("write %s: %v", path, err)
	}
}
