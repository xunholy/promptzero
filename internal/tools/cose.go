// SPDX-License-Identifier: AGPL-3.0-or-later

// cose.go registers cose_key_decode, which interprets a COSE_Key
// (RFC 9052 / IANA COSE registries) into readable key parameters. It pairs
// with webauthn_authdata_decode (whose credential public key is a COSE_Key)
// and is independently useful for CWT and IoT keys.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/cose"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(coseKeyDecodeSpec)
}

var coseKeyDecodeSpec = Spec{
	Name: "cose_key_decode",
	Description: "Decode a **COSE_Key** (RFC 9052 / RFC 8152, IANA COSE registries) into readable parameters: " +
		"key type (OKP / EC2 / RSA / Symmetric), signature algorithm (ES256 / EdDSA / RS256 / …), curve " +
		"(P-256 / Ed25519 / …), and the public-key coordinates (EC2 x/y, OKP x, RSA modulus/exponent). Also " +
		"flags when a private-key component is present. COSE_Keys carry the public key in WebAuthn / FIDO2 " +
		"credentials, CWT (CBOR Web Tokens), and many IoT flows — feed the credential public key from " +
		"`webauthn_authdata_decode` here to read what it is. Input is hex, base64, or base64url. Offline, " +
		"read-only. Low risk.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"input":{"type":"string","description":"the COSE_Key (CBOR) as hex, base64, or base64url"}
		},
		"required":["input"]
	}`),
	Required:  []string{"input"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   coseKeyDecodeHandler,
}

func coseKeyDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	in := strings.TrimSpace(str(p, "input"))
	if in == "" {
		return "", fmt.Errorf("cose_key_decode: 'input' is required")
	}
	if len(in) > maxWebAuthnInput {
		return "", fmt.Errorf("cose_key_decode: input %d bytes exceeds cap of %d", len(in), maxWebAuthnInput)
	}
	raw, err := decodeAuthDataInput(in) // hex, else base64 (std/url) — shared with webauthn
	if err != nil {
		return "", fmt.Errorf("cose_key_decode: %w", err)
	}
	k, err := cose.DecodeKey(raw)
	if err != nil {
		return "", err
	}
	body, _ := json.MarshalIndent(k, "", "  ")
	return string(body), nil
}
