package flipper

import (
	"reflect"
	"testing"
)

// Tests pinning the two pure parser helpers used by DeviceInfoMap,
// PowerInfoMap, and StorageFSInfoMap. Both were at 0% coverage —
// catching parsing drift here keeps the device-info paths trustworthy.

func TestParseKVBlock_HappyPath(t *testing.T) {
	raw := "Hardware: f7\n" +
		"Firmware: 0.103.1\n" +
		"Branch: dev\n"
	got := parseKVBlock(raw)
	want := map[string]string{
		"Hardware": "f7",
		"Firmware": "0.103.1",
		"Branch":   "dev",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseKVBlock = %v; want %v", got, want)
	}
}

func TestParseKVBlock_Empty(t *testing.T) {
	got := parseKVBlock("")
	if len(got) != 0 {
		t.Errorf("parseKVBlock(\"\") = %v; want empty map", got)
	}
}

func TestParseKVBlock_TrimsWhitespace(t *testing.T) {
	raw := "  Key1  :   value with spaces   \n" +
		"\tKey2\t:\tvalue2\t\n"
	got := parseKVBlock(raw)
	if got["Key1"] != "value with spaces" {
		t.Errorf("Key1 = %q; want %q", got["Key1"], "value with spaces")
	}
	if got["Key2"] != "value2" {
		t.Errorf("Key2 = %q; want %q", got["Key2"], "value2")
	}
}

func TestParseKVBlock_ValueWithColonsIsPreserved(t *testing.T) {
	// First colon delimits; subsequent colons belong to the value.
	raw := "url: https://example.com:8443/path\n"
	got := parseKVBlock(raw)
	if got["url"] != "https://example.com:8443/path" {
		t.Errorf("url = %q; want full URL", got["url"])
	}
}

func TestParseKVBlock_SkipsLinesWithoutColon(t *testing.T) {
	raw := "Banner: Flipper Zero\n" +
		"=== separator ===\n" +
		"Firmware: 0.103.1\n"
	got := parseKVBlock(raw)
	if len(got) != 2 {
		t.Errorf("len = %d; want 2 (banner + firmware, separator skipped). got: %v", len(got), got)
	}
	if _, ok := got["=== separator ==="]; ok {
		t.Errorf("separator line should not be a key")
	}
}

func TestParseKVBlock_EmptyKeySkipped(t *testing.T) {
	// Leading colon → empty key after trim → must be skipped.
	raw := ": value\nReal: data\n"
	got := parseKVBlock(raw)
	if _, ok := got[""]; ok {
		t.Errorf("empty key should not be stored")
	}
	if got["Real"] != "data" {
		t.Errorf("Real = %q; want %q", got["Real"], "data")
	}
}

func TestParseKVBlock_EmptyValueAllowed(t *testing.T) {
	raw := "Optional:\nName: filled\n"
	got := parseKVBlock(raw)
	if v, ok := got["Optional"]; !ok || v != "" {
		t.Errorf("Optional: ok=%v val=%q; want present with empty value", ok, v)
	}
}

func TestParseKVBlock_BlankLinesIgnored(t *testing.T) {
	raw := "\n\nKey: value\n\n\n"
	got := parseKVBlock(raw)
	if len(got) != 1 || got["Key"] != "value" {
		t.Errorf("got %v; want single Key=value", got)
	}
}

func TestParseKVBlock_LastValueWins(t *testing.T) {
	// Duplicate keys: later wins (Go map overwrite semantics — pinning so
	// nothing accidentally changes this).
	raw := "Mode: scan\nMode: emulate\n"
	got := parseKVBlock(raw)
	if got["Mode"] != "emulate" {
		t.Errorf("Mode = %q; want emulate (last wins)", got["Mode"])
	}
}

// --- isSDProductLine ---

func TestIsSDProductLine_Accepts(t *testing.T) {
	// "%02x%s %s v%i.%i" — leading 2 hex chars + product/oem + " v"/"V" marker.
	cases := []string{
		"02SD SD32G v3.0",
		"1B Samsung EVO v1.2",
		"FFAAA BBB V9.8",
		"abXY YY v0.1", // lowercase hex prefix
	}
	for _, line := range cases {
		if !isSDProductLine(line) {
			t.Errorf("isSDProductLine(%q) = false; want true", line)
		}
	}
}

func TestIsSDProductLine_Rejects(t *testing.T) {
	cases := []string{
		"",              // empty
		"     ",         // too short / no hex prefix
		"XY",            // non-hex prefix
		"ABCDE",         // no version marker and < 6 chars
		"02SD SD32G",    // no version marker
		"GG Stuff v1.0", // 'G' not hex
		"  02 SD v1.0",  // leading whitespace (not hex)
		"_2 SD v1.0",    // first char non-hex
	}
	for _, line := range cases {
		if isSDProductLine(line) {
			t.Errorf("isSDProductLine(%q) = true; want false", line)
		}
	}
}
