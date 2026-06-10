package tools

import (
	"context"
	"encoding/json"
	"testing"
)

// The pymacaroons cross-implementation v2 binary vector (see
// internal/macaroon): location "my location", identifier "my identifier",
// caveats fp/tp, signature 483b…6636.
const goldV2Macaroon = "AgELbXkgbG9jYXRpb24CDW15IGlkZW50aWZpZXIAAglmcCBjYXZlYXQAAQt0cCBsb2NhdGlvbg" +
	"IJdHAgY2F2ZWF0BEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACn8yDEet8ud+825gOjM0pZOVE8/" +
	"HpV6Zqxac+kl0BYToVaY64VfiwHj5rWgBREOkAAAYgSDs4gcmZDlCZy2aV2jFk2qZNpgQXvK+enc" +
	"TAqZaPZjY"

func decodeMacaroonView(t *testing.T, in string) macaroonView {
	t.Helper()
	out, err := macaroonDecodeHandler(context.Background(), nil, map[string]any{"macaroon": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	var v macaroonView
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, out)
	}
	return v
}

func TestMacaroonDecode_GoldVector(t *testing.T) {
	v := decodeMacaroonView(t, goldV2Macaroon)
	if v.Version != 2 || v.Location != "my location" || v.Identifier != "my identifier" {
		t.Errorf("v=%d loc=%q id=%q", v.Version, v.Location, v.Identifier)
	}
	if v.SignatureHex != "483b3881c9990e5099cb6695da3164daa64da60417bcaf9e9dc4c0a9968f6636" {
		t.Errorf("sig = %s", v.SignatureHex)
	}
	if len(v.Caveats) != 2 {
		t.Fatalf("caveats = %d, want 2", len(v.Caveats))
	}
	if v.Caveats[0].ID != "fp caveat" || !v.Caveats[0].FirstParty {
		t.Errorf("caveat[0] = %+v", v.Caveats[0])
	}
	if v.Caveats[1].ID != "tp caveat" || v.Caveats[1].Location != "tp location" || v.Caveats[1].FirstParty {
		t.Errorf("caveat[1] = %+v", v.Caveats[1])
	}
	if v.Caveats[1].VIDHex == "" {
		t.Error("third-party caveat should carry a vid_hex")
	}
}

// The L402 header shape ("L402 <macaroon>:<preimage>") must strip the scheme
// and split out the preimage.
func TestMacaroonDecode_L402Form(t *testing.T) {
	v := decodeMacaroonView(t, "L402 "+goldV2Macaroon+":deadbeefcafe")
	if v.Location != "my location" {
		t.Errorf("location = %q (scheme/preimage not stripped?)", v.Location)
	}
	if v.Preimage != "deadbeefcafe" {
		t.Errorf("preimage = %q, want deadbeefcafe", v.Preimage)
	}
}

func TestMacaroonDecode_Errors(t *testing.T) {
	for name, in := range map[string]string{
		"empty":        "",
		"not base64":   "@@@not-a-macaroon@@@",
		"not macaroon": "aGVsbG8gd29ybGQ", // valid base64, "hello world"
	} {
		if _, err := macaroonDecodeHandler(context.Background(), nil, map[string]any{"macaroon": in}); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestSplitL402(t *testing.T) {
	cases := []struct{ in, body, pre string }{
		{"abc", "abc", ""},
		{"L402 abc:pre", "abc", "pre"},
		{"lsat ABC:DEF", "ABC", "DEF"},
		{"abc:pre", "abc", "pre"},
	}
	for _, c := range cases {
		b, p := splitL402(c.in)
		if b != c.body || p != c.pre {
			t.Errorf("splitL402(%q) = (%q,%q), want (%q,%q)", c.in, b, p, c.body, c.pre)
		}
	}
}
