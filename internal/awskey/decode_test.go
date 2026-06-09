// SPDX-License-Identifier: AGPL-3.0-or-later

package awskey_test

import (
	"testing"

	"github.com/xunholy/promptzero/internal/awskey"
)

// TestPublishedVectors anchors against the two published key→account vectors —
// the second is the psanford reference implementation's own test vector.
func TestPublishedVectors(t *testing.T) {
	cases := []struct {
		keyID   string
		account string
		typ     string
		usable  bool
	}{
		{"ASIAY34FZKBOKMUTVV7A", "609629065308", "ASIA", true},
		{"ASIAQNZGKIQY56JQ7WML", "029608264753", "ASIA", true},
	}
	for _, tc := range cases {
		r, err := awskey.Decode(tc.keyID)
		if err != nil {
			t.Fatalf("Decode(%s): %v", tc.keyID, err)
		}
		if r.AccountID != tc.account {
			t.Errorf("%s: account = %s; want %s", tc.keyID, r.AccountID, tc.account)
		}
		if r.KeyType != tc.typ {
			t.Errorf("%s: key_type = %s; want %s", tc.keyID, r.KeyType, tc.typ)
		}
		if r.Usable != tc.usable {
			t.Errorf("%s: usable = %v; want %v", tc.keyID, r.Usable, tc.usable)
		}
	}
}

// TestLowercaseAccepted confirms a lower-cased key decodes the same (operators
// paste keys in either case).
func TestLowercaseAccepted(t *testing.T) {
	up, err := awskey.Decode("ASIAY34FZKBOKMUTVV7A")
	if err != nil {
		t.Fatal(err)
	}
	lo, err := awskey.Decode("asiay34fzkbokmutvv7a")
	if err != nil {
		t.Fatalf("lowercase: %v", err)
	}
	if up.AccountID != lo.AccountID {
		t.Errorf("lowercase account %s != uppercase %s", lo.AccountID, up.AccountID)
	}
}

// TestPrefixTypes confirms each known prefix is recognised and the usable flag
// is set only for the two real access-key prefixes.
func TestPrefixTypes(t *testing.T) {
	// Reuse a known-good body so base32 + length validate; only the prefix varies.
	const body = "Y34FZKBOKMUTVV7A"
	for _, p := range []struct {
		prefix string
		usable bool
	}{
		{"AKIA", true}, {"ASIA", true}, {"AROA", false}, {"AIDA", false}, {"ANPA", false},
	} {
		r, err := awskey.Decode(p.prefix + body)
		if err != nil {
			t.Fatalf("%s: %v", p.prefix, err)
		}
		if r.KeyType != p.prefix || r.Description == "" {
			t.Errorf("%s: type=%q desc=%q", p.prefix, r.KeyType, r.Description)
		}
		if r.Usable != p.usable {
			t.Errorf("%s: usable=%v want %v", p.prefix, r.Usable, p.usable)
		}
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]string{
		"empty":           "",
		"too short":       "AKIA1234",
		"too long":        "ASIAY34FZKBOKMUTVV7AXX",
		"unknown prefix":  "ZZZZY34FZKBOKMUTVV7A",
		"non-base32 body": "AKIA0189000000000000", // 0,1,8,9 are not base32
	}
	for name, in := range cases {
		if _, err := awskey.Decode(in); err == nil {
			t.Errorf("%s: Decode(%q) = nil error, want error", name, in)
		}
	}
}
