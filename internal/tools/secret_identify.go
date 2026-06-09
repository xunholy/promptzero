// secret_identify.go — host-side credential/secret identifier Spec, delegating
// to internal/secretid.
//
// Wrap-vs-native: native — routes a captured string to the in-tree decoders
// (aws_key_decode / github_token_decode / azure_sas_decode / bip39_decode /
// jwt_decode) for validation and matches documented vendor prefixes for the
// rest. The credential analogue of hash_identify. Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/secretid"
)

func init() { //nolint:gochecknoinits
	Register(secretIdentifySpec)
}

var secretIdentifySpec = Spec{
	Name: "secret_identify",
	Description: "Identify a captured string as a known **secret / credential type** — the triage entry point " +
		"for *\"I found this in loot, what is it?\"*. The credential analogue of `hash_identify`: paste an " +
		"unknown token pulled from a repo, a config, a `.env`, a log, or a memory capture and get the type, " +
		"and — where the format carries a checksum or structure — **whether it validates**.\n\n" +
		"Recognises and **validates** AWS access keys (→ account ID), GitHub tokens (→ CRC32 checksum), " +
		"Azure Storage SAS tokens, BIP-39 wallet seed phrases (→ SHA-256 checksum), and JWTs (→ alg); " +
		"recognises **by structure** PGP / OpenSSH / PEM private keys and X.509 certificates; and recognises " +
		"**by documented prefix** a curated set of vendor tokens (Slack, GitLab, Stripe, npm, OpenAI / " +
		"Anthropic, Google, SendGrid, DigitalOcean, Shopify, …). **No confidently-wrong output**: a result " +
		"asserts the **format** (and, when checked, its validity), never that a credential is live; a " +
		"validated format carries its decoder's reference-anchored verification while a prefix-only match is " +
		"labelled `validated:false`; an unrecognised string is returned unmatched with a **shape hint** " +
		"(hex / base64 / try hash_identify) rather than guessed. No network, no device, transmits nothing — " +
		"Low risk. Routes to `aws_key_decode` / `github_token_decode` / `azure_sas_decode` / `bip39_decode` " +
		"/ `jwt_decode` / `pgp_packet_decode` / `x509_certificate_decode` for the full decode.\n\n" +
		"Source: docs/catalog/gap-analysis.md (credential forensics — the unified triage front end). " +
		"Wrap-vs-native: native orchestration over the in-tree decoders + a documented vendor-prefix table, " +
		"no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"value":{"type":"string","description":"The captured string to identify (a token, key, mnemonic, PEM block, …)."}
		},
		"required":["value"]
	}`),
	Required:  []string{"value"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   secretIdentifyHandler,
}

func secretIdentifyHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	value := strings.TrimSpace(str(p, "value"))
	if value == "" {
		return "", fmt.Errorf("secret_identify: 'value' is required")
	}
	out, _ := json.MarshalIndent(secretid.Identify(value), "", "  ")
	return string(out), nil
}
