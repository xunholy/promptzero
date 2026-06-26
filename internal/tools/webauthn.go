// SPDX-License-Identifier: AGPL-3.0-or-later

// webauthn.go registers webauthn_authdata_decode, which parses the
// WebAuthn / FIDO2 authenticator-data structure an operator captures from a
// passkey / security-key registration or assertion.

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/webauthn"
)

func init() { //nolint:gochecknoinits
	Register(webauthnAuthDataDecodeSpec)
}

// maxWebAuthnInput bounds the encoded authData a single call will decode.
// Real authenticator data is a few hundred bytes; 64 KiB is generous.
const maxWebAuthnInput = 64 << 10

var webauthnAuthDataDecodeSpec = Spec{
	Name: "webauthn_authdata_decode",
	Description: "Decode **WebAuthn / FIDO2 authenticator data** (the `authData` byte string from a passkey or " +
		"security-key registration attestation or assertion). Input is base64url (the usual WebAuthn JSON form), " +
		"base64, or hex. Surfaces:\n" +
		"- **flags** — user-present / user-verified gestures, the backup-eligible & backup-state bits that mark a " +
		"syncable passkey, and whether attested-credential-data / extensions are present;\n" +
		"- **sign_count** — the signature counter (a value that goes backwards across assertions is the classic " +
		"cloned-authenticator tell);\n" +
		"- **rp_id_hash** — SHA-256 of the Relying Party ID;\n" +
		"- on registration: the **AAGUID** (authenticator model), the **credential ID**, and the credential " +
		"**COSE public key** (raw bytes — pipe to `cose_key_decode` for the key type / algorithm / curve).\n\n" +
		"Offline, read-only; transmits nothing. Low risk.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"input":{"type":"string","description":"authenticator data as base64url, base64, or hex"}
		},
		"required":["input"]
	}`),
	Required:  []string{"input"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   webauthnAuthDataDecodeHandler,
}

func webauthnAuthDataDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	in := strings.TrimSpace(str(p, "input"))
	if in == "" {
		return "", fmt.Errorf("webauthn_authdata_decode: 'input' is required")
	}
	if len(in) > maxWebAuthnInput {
		return "", fmt.Errorf("webauthn_authdata_decode: input %d bytes exceeds cap of %d", len(in), maxWebAuthnInput)
	}

	raw, err := decodeAuthDataInput(in)
	if err != nil {
		return "", fmt.Errorf("webauthn_authdata_decode: %w", err)
	}
	ad, err := webauthn.Decode(raw)
	if err != nil {
		return "", err
	}
	body, _ := json.MarshalIndent(ad, "", "  ")
	return string(body), nil
}

// decodeAuthDataInput accepts hex or base64 (std/url, padded or raw). Hex is
// only used when the input is unambiguously hex (even length, all hex
// digits) — otherwise it's treated as base64, the predominant WebAuthn form.
func decodeAuthDataInput(s string) ([]byte, error) {
	if len(s)%2 == 0 && isHexOnly(s) {
		return hex.DecodeString(s)
	}
	return decodeBase64Loose(s)
}

func isHexOnly(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}
