// SPDX-License-Identifier: AGPL-3.0-or-later

package subghz

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// SubFile represents a parsed Flipper Zero .sub capture file.
//
// The .sub format is a simple key/value text file:
//
//	Filetype: Flipper SubGhz Key File
//	Version: 1
//	Frequency: 433920000
//	Preset: FuriHalSubGhzPresetOok650Async
//	Protocol: RAW
//	RAW_Data: 500 -1000 500 -500 ...
//
// RAW_Data lines contain signed integer pulse durations in microseconds.
// Positive values are mark (carrier on), negative are space (carrier off).
// Multiple RAW_Data lines are concatenated into a single pulse slice.
type SubFile struct {
	// Filetype is the header line value, e.g. "Flipper SubGhz Key File".
	Filetype string

	// Version is the integer version field.
	Version int

	// Frequency is the carrier frequency in Hz.
	Frequency uint64

	// Preset is the RF preset string, e.g. "FuriHalSubGhzPresetOok650Async".
	Preset string

	// Protocol is the declared protocol name (often "RAW" for raw captures).
	Protocol string

	// Pulses contains the raw timing data: positive = mark, negative = space,
	// values in microseconds.
	Pulses []int
}

// Parse reads a Flipper .sub file from r and returns the parsed SubFile.
// It is lenient: unknown keys are ignored so that future Flipper firmware
// versions adding new fields do not break the parser.
func Parse(r io.Reader) (*SubFile, error) {
	sf := &SubFile{}
	scanner := bufio.NewScanner(r)
	// bufio.Scanner's default token cap is 64 KiB, but a real
	// `RAW_Data:` line is regularly much longer — each pulse is
	// ~5 ASCII bytes (4 digits + space) so a multi-second sub-GHz
	// capture (~13 k pulses) already exceeds 64 KiB. Pre-v0.154
	// those .sub files surfaced as `subghz: scan: bufio.Scanner:
	// token too long` and the parser never reached the RAW_Data
	// branch. 8 MiB is well above any realistic per-line size
	// while bounded enough to refuse a pathological multi-GB line
	// that would otherwise OOM the agent. Same defense pattern as
	// validator/badusb.go (1 MiB Buffer call) and
	// tools/security.go's hash_crack_dictionary scanner (1 MiB).
	scanner.Buffer(make([]byte, 0, 64*1024), 8<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)

		switch key {
		case "Filetype":
			sf.Filetype = val
		case "Version":
			v, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("subghz: parse Version %q: %w", val, err)
			}
			sf.Version = v
		case "Frequency":
			f, err := strconv.ParseUint(val, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("subghz: parse Frequency %q: %w", val, err)
			}
			sf.Frequency = f
		case "Preset":
			sf.Preset = val
		case "Protocol":
			sf.Protocol = val
		case "RAW_Data":
			pulses, err := parsePulses(val)
			if err != nil {
				return nil, fmt.Errorf("subghz: parse RAW_Data: %w", err)
			}
			sf.Pulses = append(sf.Pulses, pulses...)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("subghz: scan: %w", err)
	}
	return sf, nil
}

// parsePulses splits a space-separated list of signed integers.
func parsePulses(s string) ([]int, error) {
	fields := strings.Fields(s)
	out := make([]int, 0, len(fields))
	for _, f := range fields {
		v, err := strconv.Atoi(f)
		if err != nil {
			return nil, fmt.Errorf("pulse value %q: %w", f, err)
		}
		out = append(out, v)
	}
	return out, nil
}
