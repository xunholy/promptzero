// SPDX-License-Identifier: AGPL-3.0-or-later

// cose_message.go registers cose_message_decode, a general COSE message
// (RFC 9052) structure decoder. It complements cose_key_decode (keys) and
// cwt_decode (the CWT-claims interpretation of a COSE envelope) by exposing
// the full message structure of any COSE artifact.

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
	Register(coseMessageDecodeSpec)
}

var coseMessageDecodeSpec = Spec{
	Name: "cose_message_decode",
	Description: "Decode a **COSE message** (RFC 9052): COSE_Sign1 / COSE_Sign / COSE_Mac0 / COSE_Mac / " +
		"COSE_Encrypt0 / COSE_Encrypt. Surfaces the message type, the fully-decoded **protected & unprotected " +
		"headers** (algorithm, crit, content-type, kid, IV), the **payload** (or detached marker), and the " +
		"type-specific final element(s) — signature, MAC tag, or ciphertext, plus signature/recipient counts for " +
		"the multi-recipient forms. COSE messages wrap WebAuthn packed attestation, COSE-signed firmware / SUIT " +
		"manifests, and IoT artifacts; pairs with `cose_key_decode` and `cwt_decode`.\n\n" +
		"Structure only — does NOT verify signatures/MACs or decrypt (keys required); the output says so. Input " +
		"is hex, base64, or base64url. Offline, read-only. Low risk.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"input":{"type":"string","description":"the COSE message (CBOR) as hex, base64, or base64url"}
		},
		"required":["input"]
	}`),
	Required:  []string{"input"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   coseMessageDecodeHandler,
}

func coseMessageDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	in := strings.TrimSpace(str(p, "input"))
	if in == "" {
		return "", fmt.Errorf("cose_message_decode: 'input' is required")
	}
	if len(in) > maxWebAuthnInput {
		return "", fmt.Errorf("cose_message_decode: input %d bytes exceeds cap of %d", len(in), maxWebAuthnInput)
	}
	raw, err := decodeAuthDataInput(in) // hex, else base64 (std/url) — shared decoder
	if err != nil {
		return "", fmt.Errorf("cose_message_decode: %w", err)
	}
	msg, err := cose.DecodeMessage(raw)
	if err != nil {
		return "", err
	}
	body, _ := json.MarshalIndent(msg, "", "  ")
	return string(body), nil
}
