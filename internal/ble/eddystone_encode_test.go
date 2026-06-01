// SPDX-License-Identifier: AGPL-3.0-or-later

package ble

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestEncodeEddystoneURL_SpecVector hand-verifies the exact bytes of an
// Eddystone-URL frame against the documented scheme/expansion tables:
// "https://www.example.com" → 10 <tx> 01 "example" 07 (scheme 0x01 =
// https://www., 0x07 = ".com").
func TestEncodeEddystoneURL_SpecVector(t *testing.T) {
	b, err := EncodeEddystone(EddystoneEncodeRequest{Kind: "url", TxPower: 0x12, URL: "https://www.example.com"})
	if err != nil {
		t.Fatalf("EncodeEddystone: %v", err)
	}
	want := "1012016578616D706C6507"
	if got := strings.ToUpper(hex.EncodeToString(b)); got != want {
		t.Errorf("URL frame = %s, want %s", got, want)
	}
}

// TestEncodeEddystoneURL_RoundTrip covers the scheme longest-prefix and a
// mid-URL expansion (".com/").
func TestEncodeEddystoneURL_RoundTrip(t *testing.T) {
	cases := []string{
		"https://www.example.com",
		"https://www.example.com/",
		"http://promptzero.net/path",
		"https://sub.domain.org/a/b",
	}
	for _, url := range cases {
		b, err := EncodeEddystone(EddystoneEncodeRequest{Kind: "url", TxPower: -10, URL: url})
		if err != nil {
			t.Fatalf("Encode(%q): %v", url, err)
		}
		d, err := DecodeEddystone(hex.EncodeToString(b))
		if err != nil {
			t.Fatalf("Decode(%q): %v", url, err)
		}
		if d.FrameName != "URL" {
			t.Errorf("%q: frame = %s, want URL", url, d.FrameName)
		}
		if got := d.Fields["url"]; got != url {
			t.Errorf("url round-trips to %v, want %q", got, url)
		}
		if got := d.Fields["tx_power_dbm"]; got != -10 {
			t.Errorf("%q: tx_power round-trips to %v, want -10", url, got)
		}
	}
}

func TestEncodeEddystoneURL_LongestScheme(t *testing.T) {
	// "https://www." (0x01) must be chosen over "https://" (0x03).
	b, err := EncodeEddystone(EddystoneEncodeRequest{Kind: "url", URL: "https://www.x.com"})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if b[2] != 0x01 {
		t.Errorf("scheme byte = 0x%02X, want 0x01 (https://www.)", b[2])
	}
}

func TestEncodeEddystoneUID_RoundTrip(t *testing.T) {
	b, err := EncodeEddystone(EddystoneEncodeRequest{
		Kind: "uid", TxPower: -42,
		Namespace: "00010203040506070809",
		Instance:  "AABBCCDDEEFF",
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	d, err := DecodeEddystone(hex.EncodeToString(b))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if d.FrameName != "UID" {
		t.Fatalf("frame = %s, want UID", d.FrameName)
	}
	if d.Fields["namespace"] != "00010203040506070809" {
		t.Errorf("namespace = %v", d.Fields["namespace"])
	}
	if d.Fields["instance"] != "AABBCCDDEEFF" {
		t.Errorf("instance = %v", d.Fields["instance"])
	}
	if d.Fields["tx_power_dbm"] != -42 {
		t.Errorf("tx_power = %v, want -42", d.Fields["tx_power_dbm"])
	}
}

func TestEncodeEddystoneTLM_RoundTrip(t *testing.T) {
	b, err := EncodeEddystone(EddystoneEncodeRequest{
		Kind: "tlm", BatteryMV: 3300, TemperatureC: 25.5, AdvCount: 1000, Uptime100ms: 36000,
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	d, err := DecodeEddystone(hex.EncodeToString(b))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if d.FrameName != "TLM" {
		t.Fatalf("frame = %s, want TLM", d.FrameName)
	}
	if d.Fields["battery_mv"] != 3300 {
		t.Errorf("battery = %v, want 3300", d.Fields["battery_mv"])
	}
	if d.Fields["temperature_c"] != 25.5 {
		t.Errorf("temperature = %v, want 25.5", d.Fields["temperature_c"])
	}
	if d.Fields["adv_count"] != 1000 {
		t.Errorf("adv_count = %v, want 1000", d.Fields["adv_count"])
	}
	if d.Fields["uptime_100ms"] != 36000 {
		t.Errorf("uptime = %v, want 36000", d.Fields["uptime_100ms"])
	}
}

func TestEncodeEddystoneEID_RoundTrip(t *testing.T) {
	b, err := EncodeEddystone(EddystoneEncodeRequest{Kind: "eid", TxPower: 0, EphemeralID: "0123456789ABCDEF"})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	d, err := DecodeEddystone(hex.EncodeToString(b))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if d.FrameName != "EID" || d.Fields["ephemeral_id"] != "0123456789ABCDEF" {
		t.Errorf("EID round-trip = %+v", d.Fields)
	}
}

// TestEncodeEddystone_Wrap confirms the uuid and ad framings decode via the
// prefix-stripping path.
func TestEncodeEddystone_Wrap(t *testing.T) {
	for _, wrap := range []string{"uuid", "ad"} {
		b, err := EncodeEddystone(EddystoneEncodeRequest{Kind: "url", URL: "https://www.x.com", Wrap: wrap})
		if err != nil {
			t.Fatalf("Encode(wrap=%s): %v", wrap, err)
		}
		d, err := DecodeEddystone(hex.EncodeToString(b))
		if err != nil {
			t.Fatalf("Decode(wrap=%s): %v", wrap, err)
		}
		if d.FrameName != "URL" || d.Fields["url"] != "https://www.x.com" {
			t.Errorf("wrap=%s round-trip = %+v", wrap, d.Fields)
		}
	}
}

func TestEncodeEddystone_Errors(t *testing.T) {
	bad := []EddystoneEncodeRequest{
		{Kind: "bogus"},
		{Kind: "url", URL: "ftp://nope.com"},                                                     // unsupported scheme
		{Kind: "url", URL: "https://www.has space.com"},                                          // unencodable byte
		{Kind: "uid", Namespace: "0011", Instance: "AABBCCDDEEFF"},                               // short namespace
		{Kind: "uid", Namespace: "00010203040506070809", Instance: "AABB"},                       // short instance
		{Kind: "eid", EphemeralID: "0123"},                                                       // short eid
		{Kind: "uid", TxPower: 500, Namespace: "00010203040506070809", Instance: "AABBCCDDEEFF"}, // tx out of range
	}
	for i, r := range bad {
		if _, err := EncodeEddystone(r); err == nil {
			t.Errorf("case %d (%+v): expected error, got nil", i, r)
		}
	}
}
