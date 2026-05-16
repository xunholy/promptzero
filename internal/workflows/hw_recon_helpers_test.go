package workflows

import (
	"strings"
	"testing"
)

// Tests pinning the pure helpers feeding HWReconBlackbox:
// parseI2CAddresses, parseOneWireDevices, gpioValueFromOutput,
// summariseHWRecon, suggestHWReconNextSteps. All were at 0% statement
// coverage — quiet drift in any of them would mis-classify probe
// findings or skip the follow-up hint set the operator depends on.

func TestParseI2CAddresses_ExtractsAndDedupes(t *testing.T) {
	out := `Scanning I2C bus...
Found 0x3c
Found 0x68
Duplicate 0x3C
Final: 0x68, 0x76`
	got := parseI2CAddresses(out)
	want := []string{"0x3c", "0x68", "0x76"}
	if len(got) != len(want) {
		t.Fatalf("got %v; want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("idx %d: got %q want %q", i, got[i], w)
		}
	}
}

func TestParseI2CAddresses_EmptyInputReturnsEmpty(t *testing.T) {
	got := parseI2CAddresses("")
	if len(got) != 0 {
		t.Errorf("parseI2CAddresses(\"\") = %v; want empty", got)
	}
	got2 := parseI2CAddresses("no addresses here")
	if len(got2) != 0 {
		t.Errorf("parseI2CAddresses(no-match) = %v; want empty", got2)
	}
}

func TestParseI2CAddresses_CaseNormalised(t *testing.T) {
	// Mixed case must dedupe with lowercase canonical form.
	out := "0x3C 0X3c 0x3c 0xAB"
	got := parseI2CAddresses(out)
	// 0x3C / 0X3c / 0x3c all collapse; 0xAB stays separate.
	// Regex is `0x[0-9A-Fa-f]{2}` so 0X uppercase won't match; only
	// the lowercase 0x form. Pin behaviour: case-insensitive value,
	// case-sensitive prefix.
	for _, addr := range got {
		if addr != strings.ToLower(addr) {
			t.Errorf("addr %q not lowercased", addr)
		}
	}
}

func TestParseOneWireDevices_ExtractsBothFormats(t *testing.T) {
	out := `Searching...
Device 28:FF:1A:2B:3C:4D:5E:6F
Device 28FF1A2B3C4D5E70
Duplicate 28:ff:1a:2b:3c:4d:5e:6f
Final.`
	got := parseOneWireDevices(out)
	if len(got) != 2 {
		t.Fatalf("got %d; want 2 (with colon-stripping dedupe)", len(got))
	}
	for _, rom := range got {
		if strings.Contains(rom, ":") {
			t.Errorf("rom %q still contains colons", rom)
		}
		if rom != strings.ToUpper(rom) {
			t.Errorf("rom %q not uppercased", rom)
		}
	}
}

func TestParseOneWireDevices_NoDevices(t *testing.T) {
	if got := parseOneWireDevices(""); len(got) != 0 {
		t.Errorf("parseOneWireDevices(\"\") = %v; want empty", got)
	}
	if got := parseOneWireDevices("no devices found"); len(got) != 0 {
		t.Errorf("parseOneWireDevices(no-match) = %v; want empty", got)
	}
}

func TestGpioValueFromOutput(t *testing.T) {
	cases := []struct {
		out  string
		want int
	}{
		{"Pin PA4 = 1", 1},
		{"= 1", 1},
		{"Pin is HIGH", 1},
		{"high", 1},
		{"HIGH", 1},
		{"Pin PA4 = 0", 0},
		{"low", 0},
		{"", 0},
		{"garbage output", 0},
		{"Pin reads = 1.0V", 1}, // contains "= 1" — wins
	}
	for _, c := range cases {
		if got := gpioValueFromOutput(c.out); got != c.want {
			t.Errorf("gpioValueFromOutput(%q) = %d; want %d", c.out, got, c.want)
		}
	}
}

func TestSummariseHWRecon_EmptyEverything(t *testing.T) {
	got := summariseHWRecon(nil, nil, nil)
	for _, want := range []string{"I2C: 0", "OneWire: 0", "GPIO: 0/0"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary missing %q: %q", want, got)
		}
	}
}

func TestSummariseHWRecon_WithFindings(t *testing.T) {
	got := summariseHWRecon(
		[]string{"0x3c", "0x68"},
		[]string{"28FF1A2B3C4D5E6F"},
		map[string]int{"PA4": 1, "PA6": 0, "PA7": 1},
	)
	// 3 high-count test: 2/3 high.
	for _, want := range []string{"I2C: 2 devices", "OneWire: 1 devices", "GPIO: 2/3 high", "0x3c", "0x68"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary missing %q: %q", want, got)
		}
	}
}

func TestSuggestHWReconNextSteps_KnownAddrs(t *testing.T) {
	cases := []struct {
		i2c     []string
		onewire []string
		hint    string
	}{
		{[]string{"0x3c"}, nil, "SSD1306"},
		{[]string{"0x3d"}, nil, "SSD1306"},
		{[]string{"0x68"}, nil, "RTC"},
		{[]string{"0x76"}, nil, "BMP280"},
		{[]string{"0x77"}, nil, "BMP280"},
		{[]string{"0x50"}, nil, "EEPROM"},
	}
	for _, c := range cases {
		next := suggestHWReconNextSteps(c.i2c, c.onewire)
		joined := strings.Join(next, " | ")
		if !strings.Contains(joined, c.hint) {
			t.Errorf("for i2c=%v expected hint mentioning %q; got: %v", c.i2c, c.hint, next)
		}
	}
}

func TestSuggestHWReconNextSteps_OneWirePresent(t *testing.T) {
	next := suggestHWReconNextSteps(nil, []string{"28FF1A2B3C4D5E6F"})
	joined := strings.Join(next, " | ")
	if !strings.Contains(joined, "OneWire") {
		t.Errorf("expected OneWire mention; got: %v", next)
	}
	if !strings.Contains(joined, "loader_unitemp") {
		t.Errorf("expected loader_unitemp suggestion; got: %v", next)
	}
}

func TestSuggestHWReconNextSteps_NothingFound(t *testing.T) {
	next := suggestHWReconNextSteps(nil, nil)
	if len(next) == 0 {
		t.Fatal("empty suggestions for nothing-found case")
	}
	joined := strings.Join(next, " | ")
	if !strings.Contains(joined, "No common devices") {
		t.Errorf("expected 'No common devices' hint; got: %v", next)
	}
}

func TestSuggestHWReconNextSteps_UnknownI2CAddr(t *testing.T) {
	// Unknown I2C address with no OneWire: fall back to "No common
	// devices" hint (since no known addr matched).
	next := suggestHWReconNextSteps([]string{"0x42"}, nil)
	if len(next) == 0 {
		t.Fatal("empty suggestions for unknown-addr case")
	}
	joined := strings.Join(next, " | ")
	if !strings.Contains(joined, "No common devices") {
		t.Errorf("expected fallback hint; got: %v", next)
	}
}
