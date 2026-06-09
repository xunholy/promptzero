// SPDX-License-Identifier: AGPL-3.0-or-later

package discordtoken_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/discordtoken"
)

// TestDecodeAccountFromUserID builds a token from Discord's own documented
// snowflake example (175928847299117063 → 2016-04-30T11:18:25.796Z) and confirms
// the decode recovers the user ID and account creation time.
func TestDecodeAccountFromUserID(t *testing.T) {
	const userID = "175928847299117063"
	seg1 := base64.RawURLEncoding.EncodeToString([]byte(userID))
	token := seg1 + ".G3xxxx.HmAcSiGnAtUrE123"

	r, err := discordtoken.Decode(token)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Type != "Discord user/bot token" {
		t.Errorf("type = %q", r.Type)
	}
	if r.UserID != userID {
		t.Errorf("user_id = %q; want %q", r.UserID, userID)
	}
	if !strings.HasPrefix(r.AccountCreatedUTC, "2016-04-30T11:18:25") {
		t.Errorf("account_created_utc = %q; want 2016-04-30T11:18:25…", r.AccountCreatedUTC)
	}
	if !r.HasHMAC {
		t.Errorf("has_hmac = false; want true")
	}
}

// TestStandardBase64Segment confirms the standard (non-url) Base64 alphabet is
// also accepted for the user-ID segment.
func TestStandardBase64Segment(t *testing.T) {
	const userID = "80351110224678912"
	seg1 := base64.StdEncoding.EncodeToString([]byte(userID))
	r, err := discordtoken.Decode(seg1 + ".x.y")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.UserID != userID {
		t.Errorf("user_id = %q; want %q", r.UserID, userID)
	}
}

// TestMFAToken identifies an mfa.-prefixed token without claiming an account.
func TestMFAToken(t *testing.T) {
	r, err := discordtoken.Decode("mfa." + strings.Repeat("a", 84))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Type != "Discord MFA token" {
		t.Errorf("type = %q; want Discord MFA token", r.Type)
	}
	if r.UserID != "" {
		t.Errorf("MFA token should have no user ID, got %q", r.UserID)
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]string{
		"empty":             "",
		"no dots":           "justastring",
		"first not user id": base64.RawURLEncoding.EncodeToString([]byte("not-digits")) + ".x.y",
		"jwt-like":          "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig", // header isn't ASCII digits
	}
	for name, in := range cases {
		if _, err := discordtoken.Decode(in); err == nil {
			t.Errorf("%s: Decode(%q) = nil error, want error", name, in)
		}
	}
}
