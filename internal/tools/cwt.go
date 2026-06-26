// SPDX-License-Identifier: AGPL-3.0-or-later

// cwt.go registers cwt_decode, the CBOR Web Token (RFC 8392) decoder — the
// CBOR/IoT counterpart of jwt_decode. It completes the token-decoder set
// (jwt / paseto / macaroon / cwt) and builds on the COSE / CBOR decoders.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/cwt"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(cwtDecodeSpec)
}

var cwtDecodeSpec = Spec{
	Name: "cwt_decode",
	Description: "Decode a **CWT (CBOR Web Token, RFC 8392)** — the CBOR-native counterpart of a JWT, used for " +
		"OAuth / proof-of-possession on constrained & IoT devices. Unwraps the COSE envelope (COSE_Sign1 / " +
		"COSE_Mac0, or COSE_Encrypt0 when the claims are encrypted) and the optional CWT tag, reports the signing " +
		"algorithm from the COSE protected header, and decodes the claims (iss / sub / aud / exp / nbf / iat / " +
		"cti) with timestamps shown as both epoch and RFC 3339.\n\n" +
		"Does NOT verify the signature or MAC (that needs the issuer's key) — the output says so explicitly; " +
		"encrypted payloads are reported but not decoded. Input is hex, base64, or base64url. Offline, " +
		"read-only. Low risk.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"input":{"type":"string","description":"the CWT (CBOR) as hex, base64, or base64url"}
		},
		"required":["input"]
	}`),
	Required:  []string{"input"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   cwtDecodeHandler,
}

func cwtDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	in := strings.TrimSpace(str(p, "input"))
	if in == "" {
		return "", fmt.Errorf("cwt_decode: 'input' is required")
	}
	if len(in) > maxWebAuthnInput {
		return "", fmt.Errorf("cwt_decode: input %d bytes exceeds cap of %d", len(in), maxWebAuthnInput)
	}
	raw, err := decodeAuthDataInput(in) // hex, else base64 (std/url) — shared decoder
	if err != nil {
		return "", fmt.Errorf("cwt_decode: %w", err)
	}
	tok, err := cwt.Decode(raw)
	if err != nil {
		return "", err
	}
	body, _ := json.MarshalIndent(tok, "", "  ")
	return string(body), nil
}
