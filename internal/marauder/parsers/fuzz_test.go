package parsers

import (
	"strings"
	"testing"
)

// FuzzParsersLine sweeps every line-oriented Marauder parser with arbitrary
// input. Marauder output embeds attacker-influenceable bytes verbatim (SSIDs,
// BLE names, MACs echoed back from a scan), so these parsers must never panic
// or hang on hostile input — they may only return (_, false). Go's fuzzer
// treats any panic as a failure, so calling each parser is the assertion.
func FuzzParsersLine(f *testing.F) {
	seeds := []string{
		"0 | -55 | 6 | AA:BB:CC:DD:EE:FF | OPEN | HomeWifi_2G",
		"0 | -55 | 6 | AA:BB:CC:DD:EE:FF | OPEN | Free > WiFi", // #188 attacker-SSID class
		"12 | -70 | 11 | 11:22:33:44:55:66 | WPA2 | \x1b[31mred\x1b[0m",
		"",
		"   ",
		"|||||",
		"| | | | | |",
		"\x00\x1b]0;title\x07",
		"not a valid marauder line at all",
		strings.Repeat("|", 4096),
		strings.Repeat("A", 8192),
		"0 | notanumber | x | zz:zz | ? | name",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		_, _ = ParseScanAP(line)
		_, _ = ParseScanSta(line)
		_, _ = ParseSniffBeacon(line)
		_, _ = ParseSniffProbe(line)
		_, _ = ParseSniffDeauth(line)
		_, _ = ParsePacketCount(line)
		_, _ = ParseLs(line)
		_, _ = ParseBLESniff(line)
		_, _ = ParseBLEWardrive(line)
		_, _ = ParseAttackStatus(line)
		_, _ = ParseEvilPortal(line)
		_, _ = ParseRaw(line)
	})
}

// FuzzParsersBlock sweeps the multi-line block parsers. The fuzzed string is
// split into lines and handed to each block parser; neither may panic.
func FuzzParsersBlock(f *testing.F) {
	seeds := []string{
		"Packets/s: 42\nTotal: 1000",
		"Lat: 51.5074\nLon: -0.1278\nSats: 9",
		"",
		"\n\n\n",
		strings.Repeat("k: v\n", 500),
		"Lat: notanumber\nLon: \x00\x1b",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, blob string) {
		block := strings.Split(blob, "\n")
		_, _ = ParseRawStats(block)
		_, _ = ParseGPSData(block)
	})
}
