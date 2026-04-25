// SPDX-License-Identifier: AGPL-3.0-or-later

package subghz

import (
	"strings"
	"testing"
)

func TestParseMinimal(t *testing.T) {
	const src = `Filetype: Flipper SubGhz Key File
Version: 1
Frequency: 433920000
Preset: FuriHalSubGhzPresetOok650Async
Protocol: RAW
RAW_Data: 500 -1000 500 -500
`
	sf, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if sf.Filetype != "Flipper SubGhz Key File" {
		t.Errorf("Filetype = %q", sf.Filetype)
	}
	if sf.Version != 1 {
		t.Errorf("Version = %d", sf.Version)
	}
	if sf.Frequency != 433920000 {
		t.Errorf("Frequency = %d", sf.Frequency)
	}
	if sf.Preset != "FuriHalSubGhzPresetOok650Async" {
		t.Errorf("Preset = %q", sf.Preset)
	}
	if sf.Protocol != "RAW" {
		t.Errorf("Protocol = %q", sf.Protocol)
	}
	want := []int{500, -1000, 500, -500}
	if len(sf.Pulses) != len(want) {
		t.Fatalf("Pulses len = %d, want %d", len(sf.Pulses), len(want))
	}
	for i, p := range sf.Pulses {
		if p != want[i] {
			t.Errorf("Pulses[%d] = %d, want %d", i, p, want[i])
		}
	}
}

func TestParseMultipleRawDataLines(t *testing.T) {
	const src = `Filetype: Flipper SubGhz Key File
Version: 1
Frequency: 315000000
Preset: FuriHalSubGhzPresetOok650Async
Protocol: RAW
RAW_Data: 100 -200 300
RAW_Data: -400 500
`
	sf, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	want := []int{100, -200, 300, -400, 500}
	if len(sf.Pulses) != len(want) {
		t.Fatalf("Pulses len = %d, want %d", len(sf.Pulses), len(want))
	}
}

func TestParseIgnoresUnknownKeys(t *testing.T) {
	const src = `Filetype: Flipper SubGhz Key File
Version: 1
Frequency: 433920000
Preset: FuriHalSubGhzPresetOok650Async
Protocol: RAW
FutureKey: some future value
RAW_Data: 300 -300
`
	sf, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sf.Pulses) != 2 {
		t.Errorf("Pulses len = %d, want 2", len(sf.Pulses))
	}
}

func TestParseIgnoresComments(t *testing.T) {
	const src = `# This is a comment
Filetype: Flipper SubGhz Key File
Version: 1
Frequency: 433920000
Preset: FuriHalSubGhzPresetOok650Async
Protocol: RAW
# another comment
RAW_Data: 400 -400
`
	sf, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sf.Pulses) != 2 {
		t.Errorf("Pulses len = %d, want 2", len(sf.Pulses))
	}
}

func TestParseInvalidVersion(t *testing.T) {
	const src = `Filetype: Flipper SubGhz Key File
Version: notanumber
Frequency: 433920000
Preset: FuriHalSubGhzPresetOok650Async
Protocol: RAW
RAW_Data: 300 -300
`
	_, err := Parse(strings.NewReader(src))
	if err == nil {
		t.Error("expected error for invalid Version, got nil")
	}
}

func TestParseInvalidFrequency(t *testing.T) {
	const src = `Filetype: Flipper SubGhz Key File
Version: 1
Frequency: badfreq
Preset: FuriHalSubGhzPresetOok650Async
Protocol: RAW
RAW_Data: 300 -300
`
	_, err := Parse(strings.NewReader(src))
	if err == nil {
		t.Error("expected error for invalid Frequency, got nil")
	}
}

func TestParseEmpty(t *testing.T) {
	sf, err := Parse(strings.NewReader(""))
	if err != nil {
		t.Fatalf("Parse error on empty: %v", err)
	}
	if len(sf.Pulses) != 0 {
		t.Errorf("expected no pulses, got %d", len(sf.Pulses))
	}
}

func TestSubFileStringRoundTrip(t *testing.T) {
	pulses := []int{350, -1050, 350, -350, 1050, -350}
	text := SubFileString(433920000, "FuriHalSubGhzPresetOok650Async", pulses)
	sf, err := Parse(strings.NewReader(text))
	if err != nil {
		t.Fatalf("Parse round-trip error: %v", err)
	}
	if len(sf.Pulses) != len(pulses) {
		t.Fatalf("pulse count: got %d, want %d", len(sf.Pulses), len(pulses))
	}
	for i := range pulses {
		if sf.Pulses[i] != pulses[i] {
			t.Errorf("pulse[%d]: got %d, want %d", i, sf.Pulses[i], pulses[i])
		}
	}
}

func TestSubFileStringLargeChunking(t *testing.T) {
	// Verify that >512 pulses are split across multiple RAW_Data lines.
	pulses := make([]int, 1024)
	for i := range pulses {
		if i%2 == 0 {
			pulses[i] = 350
		} else {
			pulses[i] = -350
		}
	}
	text := SubFileString(433920000, "FuriHalSubGhzPresetOok650Async", pulses)
	count := strings.Count(text, "RAW_Data:")
	if count < 2 {
		t.Errorf("expected ≥2 RAW_Data lines for 1024 pulses, got %d", count)
	}
	sf, err := Parse(strings.NewReader(text))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(sf.Pulses) != len(pulses) {
		t.Errorf("pulse count: got %d, want %d", len(sf.Pulses), len(pulses))
	}
}
