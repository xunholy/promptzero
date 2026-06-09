// aws_key_decode.go — host-side AWS access key ID decoder Spec, delegating to
// internal/awskey.
//
// Wrap-vs-native: native — the AWS account ID is bit-packed into the key ID
// (base32-decode the body, mask, shift); a base32 decode + a shift, stdlib only.
// Recovers the owning account ID + the credential type from a leaked key
// OFFLINE (no sts:GetAccessKeyInfo call, no log, no detection) — cloud-pentest
// recon. Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/awskey"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(awsKeyDecodeSpec)
}

var awsKeyDecodeSpec = Spec{
	Name: "aws_key_decode",
	Description: "Decode an **AWS access key ID** (`AKIA…` / `ASIA…` / `AROA…` and the other 20-char AWS unique " +
		"IDs) into the **AWS account ID** bit-packed inside it and the **credential type**. A leaked AWS key " +
		"is prime cloud-pentest / IR loot, and recovering the owning **account ID** + the key type — " +
		"**offline, without calling AWS** (no `sts get-access-key-info`, no CloudTrail entry, no detection) — " +
		"is a standard recon technique that scopes the blast radius of a found credential.\n\n" +
		"Identifies the credential type from the prefix (AKIA = long-term IAM access key, ASIA = temporary " +
		"STS key, AROA = role, AIDA = user, ANPA = managed policy, …) and flags whether it is a **usable " +
		"access key** (AKIA/ASIA) versus a resource unique ID that merely leaks the account. **No " +
		"confidently-wrong output**: only the recognised AWS unique-ID prefixes are accepted; a wrong length, " +
		"an unknown prefix, or a non-base32 body is rejected rather than decoded into a bogus account ID. No " +
		"network, no device, transmits nothing — Low risk. Pairs with the credential tooling.\n\n" +
		"Source: docs/catalog/gap-analysis.md (cloud-credential forensics). Wrap-vs-native: native — base32 " +
		"decode + a mask + a shift, stdlib only, no new go.mod dep. Anchored to the published vectors " +
		"(ASIAY34FZKBOKMUTVV7A → 609629065308, ASIAQNZGKIQY56JQ7WML → 029608264753).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"key_id":{"type":"string","description":"The 20-character AWS access key ID (e.g. AKIAIOSFODNN7EXAMPLE / ASIAY34FZKBOKMUTVV7A)."}
		},
		"required":["key_id"]
	}`),
	Required:  []string{"key_id"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   awsKeyDecodeHandler,
}

func awsKeyDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	keyID := strings.TrimSpace(str(p, "key_id"))
	if keyID == "" {
		return "", fmt.Errorf("aws_key_decode: 'key_id' is required")
	}
	res, err := awskey.Decode(keyID)
	if err != nil {
		return "", fmt.Errorf("aws_key_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
