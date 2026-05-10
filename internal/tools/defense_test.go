package tools

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/defense"
)

// defense_test.go covers the four pure helpers in defense.go that
// previously had 0% coverage. They drive the BLE defense
// classifier tool: parsing arbitrary JSON ad payloads into the
// typed Advertisement shape, decoding hex/base64 manufacturer-
// data values, formatting Matches for the LLM-visible response,
// and converting match sets into the operator-facing verdict
// string ("clean" / "review_needed" / "spam_attack_likely").

// TestParseManufacturerID pins the parser for the JSON-keyed
// manufacturer-ID strings. "0x" prefix → hex parse, otherwise
// decimal. Values > 0xFFFF rejected.
func TestParseManufacturerID(t *testing.T) {
	type tc struct {
		in     string
		want   uint16
		hasErr bool
	}
	cases := []tc{
		// Decimal.
		{"0", 0, false},
		{"76", 0x004C, false}, // Apple
		{"65535", 0xFFFF, false},
		{"  42  ", 42, false}, // whitespace tolerated
		// Hex.
		{"0x004C", 0x004C, false},
		{"0xFFFF", 0xFFFF, false},
		{"0X1234", 0x1234, false},
		{"0x0", 0, false},
		// Errors: out-of-range.
		{"65536", 0, true},
		{"0x10000", 0, true},
		// Errors: garbage.
		{"not-a-number", 0, true},
		{"", 0, true},
	}
	for _, c := range cases {
		got, err := parseManufacturerID(c.in)
		if (err != nil) != c.hasErr {
			t.Errorf("parseManufacturerID(%q) err=%v, hasErr=%v", c.in, err, c.hasErr)
			continue
		}
		if err == nil && got != c.want {
			t.Errorf("parseManufacturerID(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestParseAdvertisement_AllFields exercises the JSON → typed
// conversion for every field the tool surfaces. Address is
// canonicalised to upper; LocalName passes through; service
// UUIDs become a string slice; manufacturer_data and
// service_data are hex; manufacturer_data_b64 is base64.
func TestParseAdvertisement_AllFields(t *testing.T) {
	hexMD := hex.EncodeToString([]byte{0x12, 0x34, 0x56})
	b64MD := base64.StdEncoding.EncodeToString([]byte{0xAB, 0xCD})
	hexSD := hex.EncodeToString([]byte{0xDE, 0xAD})

	args := map[string]any{
		"address":    "aa:bb:cc:dd:ee:ff",
		"local_name": "TestDevice",
		"service_uuids": []any{
			"0000110b-0000-1000-8000-00805f9b34fb",
			"non-string-ignored", // string is fine; non-strings filtered
		},
		"manufacturer_data": map[string]any{
			"76":     hexMD,
			"0x0590": hex.EncodeToString([]byte{0x99}), // Microsoft via hex key
		},
		"manufacturer_data_b64": map[string]any{
			"100": b64MD,
		},
		"service_data": map[string]any{
			"3": hexSD,
		},
	}
	ad, err := parseAdvertisement(args)
	if err != nil {
		t.Fatalf("parseAdvertisement: %v", err)
	}
	if ad.Address != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("Address = %q, want upper-canonical", ad.Address)
	}
	if ad.LocalName != "TestDevice" {
		t.Errorf("LocalName = %q, want TestDevice", ad.LocalName)
	}
	if len(ad.ServiceUUIDs) == 0 || ad.ServiceUUIDs[0] != "0000110b-0000-1000-8000-00805f9b34fb" {
		t.Errorf("ServiceUUIDs = %v", ad.ServiceUUIDs)
	}
	if v, ok := ad.ManufacturerData[0x004C]; !ok || string(v) != string([]byte{0x12, 0x34, 0x56}) {
		t.Errorf("ManufacturerData[0x004C] = %x, want 123456", v)
	}
	if v, ok := ad.ManufacturerData[0x0590]; !ok || v[0] != 0x99 {
		t.Errorf("ManufacturerData[0x0590] missing or wrong")
	}
	if v, ok := ad.ManufacturerData[100]; !ok || string(v) != string([]byte{0xAB, 0xCD}) {
		t.Errorf("ManufacturerData[100] (b64) = %x, want abcd", v)
	}
	if v, ok := ad.ServiceData[3]; !ok || string(v) != string([]byte{0xDE, 0xAD}) {
		t.Errorf("ServiceData[3] = %x, want dead", v)
	}
}

// TestParseAdvertisement_ErrorPaths pins the validation errors:
// invalid manufacturer key, non-hex data, non-base64 data.
func TestParseAdvertisement_ErrorPaths(t *testing.T) {
	t.Run("invalid_manufacturer_key", func(t *testing.T) {
		_, err := parseAdvertisement(map[string]any{
			"manufacturer_data": map[string]any{
				"not-a-number": hex.EncodeToString([]byte{0x12}),
			},
		})
		if err == nil || !strings.Contains(err.Error(), "manufacturer_data key") {
			t.Errorf("err = %v, want manufacturer_data key error", err)
		}
	})
	t.Run("non_hex_manufacturer_data", func(t *testing.T) {
		_, err := parseAdvertisement(map[string]any{
			"manufacturer_data": map[string]any{
				"76": "not-hex!!",
			},
		})
		if err == nil || !strings.Contains(err.Error(), "not hex") {
			t.Errorf("err = %v, want 'not hex' error", err)
		}
	})
	t.Run("non_base64_manufacturer_data_b64", func(t *testing.T) {
		_, err := parseAdvertisement(map[string]any{
			"manufacturer_data_b64": map[string]any{
				"76": "@@@-not-base64-@@@",
			},
		})
		if err == nil || !strings.Contains(err.Error(), "not base64") {
			t.Errorf("err = %v, want 'not base64' error", err)
		}
	})
	t.Run("invalid_service_data_key", func(t *testing.T) {
		_, err := parseAdvertisement(map[string]any{
			"service_data": map[string]any{
				"not-a-number": hex.EncodeToString([]byte{0x12}),
			},
		})
		if err == nil || !strings.Contains(err.Error(), "service_data key") {
			t.Errorf("err = %v, want service_data key error", err)
		}
	})
}

// TestParseAdvertisement_EmptyAndMinimal pins the empty-input and
// minimal-input paths. parseAdvertisement must tolerate a missing
// field (no panic, just produces a zero-valued field) — the LLM
// can supply any subset of the ad properties.
func TestParseAdvertisement_EmptyAndMinimal(t *testing.T) {
	t.Run("empty_args", func(t *testing.T) {
		ad, err := parseAdvertisement(map[string]any{})
		if err != nil {
			t.Fatalf("empty args: %v", err)
		}
		if ad.Address != "" || ad.LocalName != "" {
			t.Errorf("empty ad = %+v, want zero values", ad)
		}
	})
	t.Run("address_only", func(t *testing.T) {
		ad, err := parseAdvertisement(map[string]any{"address": "11:22:33:44:55:66"})
		if err != nil {
			t.Fatalf("address-only: %v", err)
		}
		if ad.Address != "11:22:33:44:55:66" {
			t.Errorf("Address = %q", ad.Address)
		}
	})
}

// TestFormatMatches pins the LLM-facing match render: signature,
// description, source_mac become string-string map entries.
func TestFormatMatches(t *testing.T) {
	matches := []defense.Match{
		{
			Signature:   defense.SigAppleContinuitySpam,
			Description: "0x42 NearbyInfo with truncated payload",
			SourceMAC:   "AA:BB:CC:DD:EE:FF",
		},
		{
			Signature:   defense.SigSamsungWatchSpam,
			Description: "samsung watch buds",
			SourceMAC:   "11:22:33:44:55:66",
		},
	}
	out := formatMatches(matches)
	if len(out) != 2 {
		t.Fatalf("len(out) = %d, want 2", len(out))
	}
	if out[0]["signature"] != "apple_continuity_spam" {
		t.Errorf("[0].signature = %q", out[0]["signature"])
	}
	if !strings.Contains(out[0]["description"], "truncated") {
		t.Errorf("[0].description = %q", out[0]["description"])
	}
	if out[0]["source_mac"] != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("[0].source_mac = %q", out[0]["source_mac"])
	}
	if out[1]["signature"] != "samsung_watch_spam" {
		t.Errorf("[1].signature = %q", out[1]["signature"])
	}

	// Empty input → empty (non-nil) slice; the consuming JSON
	// marshaller renders [] either way but len-0 vs nil affects
	// downstream code that branches on slice-emptiness.
	if got := formatMatches(nil); len(got) != 0 {
		t.Errorf("formatMatches(nil) len = %d, want 0", len(got))
	}
}

// TestVerdictFor pins the operator-facing verdict mapping:
// - no matches → "clean"
// - any spam-class signature → "spam_attack_likely"
// - other matches (e.g. SigFlipperServiceUUID) → "review_needed"
func TestVerdictFor(t *testing.T) {
	if got := verdictFor(nil); got != "clean" {
		t.Errorf("verdictFor(nil) = %q, want clean", got)
	}
	if got := verdictFor([]defense.Match{}); got != "clean" {
		t.Errorf("verdictFor([]) = %q, want clean", got)
	}

	spamSigs := []defense.SignatureID{
		defense.SigAppleContinuitySpam,
		defense.SigSwiftPairMalformed,
		defense.SigSamsungWatchSpam,
		defense.SigGoogleFastPairSpam,
		defense.SigHighFrequencyMACRotation,
	}
	for _, sig := range spamSigs {
		got := verdictFor([]defense.Match{{Signature: sig}})
		if got != "spam_attack_likely" {
			t.Errorf("verdictFor([%v]) = %q, want spam_attack_likely", sig, got)
		}
	}

	// Non-spam signature (FlipperServiceUUID is informational) → review_needed.
	got := verdictFor([]defense.Match{{Signature: defense.SigFlipperServiceUUID}})
	if got != "review_needed" {
		t.Errorf("verdictFor([FlipperServiceUUID]) = %q, want review_needed", got)
	}

	// Mixed: a spam signature anywhere in the slice wins over review_needed.
	got = verdictFor([]defense.Match{
		{Signature: defense.SigFlipperServiceUUID},
		{Signature: defense.SigAppleContinuitySpam},
	})
	if got != "spam_attack_likely" {
		t.Errorf("verdictFor mixed = %q, want spam_attack_likely (any spam wins)", got)
	}
}
