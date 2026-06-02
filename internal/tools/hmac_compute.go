// hmac_compute.go — host-side HMAC compute / verify Spec, delegating to
// internal/hmacutil.
//
// Wrap-vs-native: native — HMAC is crypto/hmac over crypto/sha*. It is the
// keyed-MAC tier of the toolkit and the API/webhook-auth analogue of
// jwt_verify: verify or forge a webhook signature (GitHub X-Hub-Signature-256,
// Stripe-Signature, generic API signing) with a known/leaked secret, or check
// a protocol HMAC auth tag. Complements crc_compute / checksum_compute (the
// unkeyed checksums). Offline compute, no network/device.

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/hmacutil"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(hmacComputeSpec)
}

var hmacComputeSpec = Spec{
	Name: "hmac_compute",
	Description: "Compute or verify an HMAC-SHA1/SHA256/SHA512 message authentication code — the " +
		"keyed-MAC tier of the toolkit and the API/webhook-auth analogue of jwt_verify. Verify or forge a " +
		"webhook signature (GitHub X-Hub-Signature-256, Stripe-Signature, generic API request signing) " +
		"with a known or leaked secret, or check a protocol's HMAC auth tag. Complements crc_compute / " +
		"checksum_compute (the unkeyed checksums).\n\n" +
		"Fields: **data** (the message — UTF-8 text by default, or hex when **data_hex** is true), **key** " +
		"(the secret — UTF-8 by default, or hex when **key_hex** is true), **algorithm** (SHA256 default / " +
		"SHA1 / SHA512), and **expected** (optional hex MAC — switches to verify mode, constant-time " +
		"compared). Output is the HMAC hex, plus verified true/false when expected is given.\n\n" +
		"Offline compute — reads strings, transmits nothing, so it is Low risk. Verified in-tree against " +
		"the RFC 4231 published HMAC vectors. Wrap-vs-native: native — crypto/hmac over crypto/sha*, " +
		"standard library only.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"data":{"type":"string","description":"Message to authenticate (UTF-8 text, or hex if data_hex=true)."},
			"key":{"type":"string","description":"HMAC secret (UTF-8 text, or hex if key_hex=true)."},
			"algorithm":{"type":"string","description":"SHA256 (default), SHA1, or SHA512.","enum":["SHA1","SHA256","SHA512"]},
			"data_hex":{"type":"boolean","description":"Treat data as hex (default false = UTF-8)."},
			"key_hex":{"type":"boolean","description":"Treat key as hex (default false = UTF-8)."},
			"expected":{"type":"string","description":"Optional: an observed MAC as hex — switches to verify mode."}
		},
		"required":["data","key"]
	}`),
	Required:  []string{"data", "key"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   hmacComputeHandler,
}

func hmacComputeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	data, err := bytesArg(str(p, "data"), boolOf(p["data_hex"]))
	if err != nil {
		return "", fmt.Errorf("hmac_compute: data: %w", err)
	}
	key, err := bytesArg(str(p, "key"), boolOf(p["key_hex"]))
	if err != nil {
		return "", fmt.Errorf("hmac_compute: key: %w", err)
	}
	algo := str(p, "algorithm")

	if exp := strings.TrimSpace(str(p, "expected")); exp != "" {
		ok, err := hmacutil.Verify(algo, key, data, exp)
		if err != nil {
			return "", fmt.Errorf("hmac_compute: %w", err)
		}
		mac, _ := hmacutil.Compute(algo, key, data)
		out, _ := json.MarshalIndent(map[string]any{
			"mode": "verify", "algorithm": algoName(algo), "hmac": hex.EncodeToString(mac), "verified": ok,
		}, "", "  ")
		return string(out), nil
	}

	mac, err := hmacutil.Compute(algo, key, data)
	if err != nil {
		return "", fmt.Errorf("hmac_compute: %w", err)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"mode": "compute", "algorithm": algoName(algo), "hmac": hex.EncodeToString(mac),
	}, "", "  ")
	return string(out), nil
}

// bytesArg decodes an arg as hex (when asHex) or returns its UTF-8 bytes.
func bytesArg(s string, asHex bool) ([]byte, error) {
	if asHex {
		clean := strings.NewReplacer(" ", "", ":", "", "-", "").Replace(strings.TrimSpace(s))
		clean = strings.TrimPrefix(strings.TrimPrefix(clean, "0x"), "0X")
		return hex.DecodeString(clean)
	}
	return []byte(s), nil
}

func algoName(a string) string {
	a = strings.ToUpper(strings.TrimSpace(a))
	if a == "" {
		return "SHA256"
	}
	return a
}
