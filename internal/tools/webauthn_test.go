// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestWebAuthnDecode_HexAndBase64(t *testing.T) {
	spec, ok := Get("webauthn_authdata_decode")
	if !ok {
		t.Fatal("webauthn_authdata_decode not registered")
	}
	// 32-byte RP hash (all 0xAB) + flags 0x05 (UP|UV) + counter 0x00000009.
	hexAD := strings.Repeat("ab", 32) + "05" + "00000009"

	checkUPUV := func(out string) {
		t.Helper()
		var r struct {
			SignCount int `json:"sign_count"`
			Flags     struct {
				UserPresent  bool `json:"user_present"`
				UserVerified bool `json:"user_verified"`
			} `json:"flags"`
		}
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatalf("unmarshal: %v\n%s", err, out)
		}
		if !r.Flags.UserPresent || !r.Flags.UserVerified {
			t.Errorf("flags = %+v, want UP+UV", r.Flags)
		}
		if r.SignCount != 9 {
			t.Errorf("sign_count = %d, want 9", r.SignCount)
		}
	}

	// Hex input.
	out, err := spec.Handler(context.Background(), &Deps{}, map[string]any{"input": hexAD})
	if err != nil {
		t.Fatalf("hex handler: %v", err)
	}
	checkUPUV(out)

	// Same bytes as base64url (the predominant WebAuthn form).
	raw := append(append(make([]byte, 0), repeat(0xAB, 32)...), 0x05, 0x00, 0x00, 0x00, 0x09)
	b64 := base64.RawURLEncoding.EncodeToString(raw)
	out2, err := spec.Handler(context.Background(), &Deps{}, map[string]any{"input": b64})
	if err != nil {
		t.Fatalf("base64 handler: %v", err)
	}
	checkUPUV(out2)
}

func TestWebAuthnDecode_Errors(t *testing.T) {
	spec, _ := Get("webauthn_authdata_decode")
	if _, err := spec.Handler(context.Background(), &Deps{}, map[string]any{}); err == nil {
		t.Error("missing input should error")
	}
	if _, err := spec.Handler(context.Background(), &Deps{}, map[string]any{"input": "ab"}); err == nil {
		t.Error("too-short authData should error")
	}
}

func repeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
