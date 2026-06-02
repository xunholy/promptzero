// SPDX-License-Identifier: AGPL-3.0-or-later

package wpa

import (
	"crypto/sha1" //nolint:gosec // RFC 6070 vectors are PBKDF2-HMAC-SHA1.
	"encoding/hex"
	"testing"
)

// TestPBKDF2_RFC6070 gates the PBKDF2 core against the RFC 6070 HMAC-SHA1 test
// vectors — the authoritative reference.
func TestPBKDF2_RFC6070(t *testing.T) {
	cases := []struct {
		pw, salt   string
		iter, dk   int
		wantHexStr string
	}{
		{"password", "salt", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"},
		{"password", "salt", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"},
		{"password", "salt", 4096, 20, "4b007901b765489abead49d926f721d065a429c1"},
		{"passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25,
			"3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"},
	}
	for _, c := range cases {
		got := hex.EncodeToString(PBKDF2([]byte(c.pw), []byte(c.salt), c.iter, c.dk, sha1.New))
		if got != c.wantHexStr {
			t.Errorf("PBKDF2(%q,%q,%d,%d) = %s, want %s", c.pw, c.salt, c.iter, c.dk, got, c.wantHexStr)
		}
	}
}

// TestDerivePMK_IEEE80211i gates the PMK derivation against the IEEE 802.11i
// Annex published WPA-PSK test vectors.
func TestDerivePMK_IEEE80211i(t *testing.T) {
	cases := []struct {
		pass, ssid, want string
	}{
		{"password", "IEEE", "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"},
		{"ThisIsAPassword", "ThisIsASSID", "0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af"},
	}
	for _, c := range cases {
		pmk, err := DerivePMK(c.pass, c.ssid)
		if err != nil {
			t.Fatalf("DerivePMK(%q,%q): %v", c.pass, c.ssid, err)
		}
		if got := hex.EncodeToString(pmk); got != c.want {
			t.Errorf("DerivePMK(%q,%q) = %s, want %s", c.pass, c.ssid, got, c.want)
		}
	}
}

func TestDerivePMK_Validation(t *testing.T) {
	bad := []struct {
		name, pass, ssid string
	}{
		{"short passphrase", "short", "ssid"},
		{"long passphrase", string(make([]byte, 64)), "ssid"}, // 64 > 63
		{"empty ssid", "validpass", ""},
		{"long ssid", "validpass", "012345678901234567890123456789012"}, // 33 bytes
	}
	for _, c := range bad {
		if _, err := DerivePMK(c.pass, c.ssid); err == nil {
			t.Errorf("%s: expected error, got nil", c.name)
		}
	}
	// Non-printable byte in an otherwise valid-length passphrase.
	if _, err := DerivePMK("valid\x00pass", "ssid"); err == nil {
		t.Error("non-printable passphrase byte should error")
	}
	// Boundary: exactly 8 and 63 chars are valid.
	if _, err := DerivePMK("12345678", "ssid"); err != nil {
		t.Errorf("8-char passphrase should be valid: %v", err)
	}
}
