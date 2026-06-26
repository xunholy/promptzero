// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestCoseKeyDecode_HexAndBase64(t *testing.T) {
	spec, ok := Get("cose_key_decode")
	if !ok {
		t.Fatal("cose_key_decode not registered")
	}
	// EC2/ES256/P-256 public key: {1:2, 3:-7, -1:1, -2:x, -3:y}.
	x := strings.Repeat("11", 32)
	y := strings.Repeat("22", 32)
	hexKey := "a5" + "0102" + "0326" + "2001" + "215820" + x + "225820" + y

	check := func(out string) {
		t.Helper()
		var r struct {
			KeyType   string `json:"key_type"`
			Algorithm string `json:"algorithm"`
			Curve     string `json:"curve"`
		}
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatalf("unmarshal: %v\n%s", err, out)
		}
		if r.KeyType != "EC2" || r.Algorithm != "ES256" || r.Curve != "P-256" {
			t.Errorf("got %+v, want EC2/ES256/P-256", r)
		}
	}

	out, err := spec.Handler(context.Background(), &Deps{}, map[string]any{"input": hexKey})
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	check(out)

	raw, _ := hex.DecodeString(hexKey)
	out2, err := spec.Handler(context.Background(), &Deps{}, map[string]any{"input": base64.RawURLEncoding.EncodeToString(raw)})
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	check(out2)
}

func TestCoseKeyDecode_Errors(t *testing.T) {
	spec, _ := Get("cose_key_decode")
	if _, err := spec.Handler(context.Background(), &Deps{}, map[string]any{}); err == nil {
		t.Error("missing input should error")
	}
	if _, err := spec.Handler(context.Background(), &Deps{}, map[string]any{"input": "01"}); err == nil {
		t.Error("non-map CBOR should error (not a COSE_Key)")
	}
}
