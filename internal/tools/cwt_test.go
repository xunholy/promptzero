// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// RFC 8392 A.1 example claims (unsecured CWT).
const cwtRFCClaims = "a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77" +
	"037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b71"

func TestCWTDecode_HexAndBase64(t *testing.T) {
	spec, ok := Get("cwt_decode")
	if !ok {
		t.Fatal("cwt_decode not registered")
	}
	check := func(out string) {
		t.Helper()
		var r struct {
			COSEType string `json:"cose_type"`
			Claims   struct {
				Issuer  string `json:"iss"`
				Subject string `json:"sub"`
			} `json:"claims"`
			Note string `json:"note"`
		}
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatalf("unmarshal: %v\n%s", err, out)
		}
		if r.COSEType != "unsecured" || r.Claims.Issuer != "coap://as.example.com" || r.Claims.Subject != "erikw" {
			t.Errorf("got %+v", r)
		}
		if r.Note == "" {
			t.Error("expected a not-verified note")
		}
	}

	out, err := spec.Handler(context.Background(), &Deps{}, map[string]any{"input": cwtRFCClaims})
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	check(out)

	raw, _ := hex.DecodeString(cwtRFCClaims)
	out2, err := spec.Handler(context.Background(), &Deps{}, map[string]any{"input": base64.RawURLEncoding.EncodeToString(raw)})
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	check(out2)
}

func TestCWTDecode_Errors(t *testing.T) {
	spec, _ := Get("cwt_decode")
	if _, err := spec.Handler(context.Background(), &Deps{}, map[string]any{}); err == nil {
		t.Error("missing input should error")
	}
	if _, err := spec.Handler(context.Background(), &Deps{}, map[string]any{"input": "6161"}); err == nil {
		t.Error("a bare text string is not a CWT and should error")
	}
}
