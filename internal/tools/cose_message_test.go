// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestCoseMessageDecode_HexAndBase64(t *testing.T) {
	spec, ok := Get("cose_message_decode")
	if !ok {
		t.Fatal("cose_message_decode not registered")
	}
	// Tagged COSE_Sign1: {1:-7} protected, kid, payload cafe, sig deadbeef.
	hexMsg := "d28443a10126a10442313142cafe44deadbeef"

	check := func(out string) {
		t.Helper()
		var r struct {
			Type      string `json:"type"`
			Protected struct {
				Algorithm string `json:"algorithm"`
			} `json:"protected_header"`
			SignatureHex string `json:"signature_hex"`
			Note         string `json:"note"`
		}
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatalf("unmarshal: %v\n%s", err, out)
		}
		if r.Type != "COSE_Sign1" || r.Protected.Algorithm != "ES256" || r.SignatureHex != "DEADBEEF" {
			t.Errorf("got %+v", r)
		}
		if r.Note == "" {
			t.Error("expected a not-verified note")
		}
	}

	out, err := spec.Handler(context.Background(), &Deps{}, map[string]any{"input": hexMsg})
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	check(out)

	raw, _ := hex.DecodeString(hexMsg)
	out2, err := spec.Handler(context.Background(), &Deps{}, map[string]any{"input": base64.RawURLEncoding.EncodeToString(raw)})
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	check(out2)
}

func TestCoseMessageDecode_Errors(t *testing.T) {
	spec, _ := Get("cose_message_decode")
	if _, err := spec.Handler(context.Background(), &Deps{}, map[string]any{}); err == nil {
		t.Error("missing input should error")
	}
	if _, err := spec.Handler(context.Background(), &Deps{}, map[string]any{"input": "01"}); err == nil {
		t.Error("non-array CBOR is not a COSE message and should error")
	}
}
