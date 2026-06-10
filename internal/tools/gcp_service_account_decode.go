// gcp_service_account_decode.go — host-side GCP service-account key decoder Spec,
// delegating to internal/gcpsakey.
//
// Wrap-vs-native: native — a GCP service-account key is the documented JSON key
// file; decode is encoding/json + stdlib crypto/x509 PKCS#8 parsing +
// internal/roca, no new go.mod dep. Turns a leaked SA key into its identity +
// blast radius (project, account, key validity, ROCA status) for cloud-IR /
// supply-chain leak triage. Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/gcpsakey"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(gcpServiceAccountDecodeSpec)
}

var gcpServiceAccountDecodeSpec = Spec{
	Name: "gcp_service_account_decode",
	Description: "Decode a **GCP service-account JSON key** into the identity and blast radius it carries. A " +
		"service-account key (`{\"type\":\"service_account\",\"project_id\":…,\"private_key\":\"-----BEGIN " +
		"PRIVATE KEY-----…\"}`) is among the **most damaging and most frequently-leaked cloud credentials** — " +
		"a long-lived, often highly-privileged identity committed to repos, baked into CI, and dropped in " +
		"container images. When one turns up in loot the questions are *whose* identity it is, in *which* " +
		"project, and whether the embedded key is genuine — all answerable **offline, with no GCP call**.\n\n" +
		"Surfaces the identity fields (`project_id`, `client_email`, `client_id`, `private_key_id`); " +
		"**classifies the account** — flagging the default **Compute Engine** / **App Engine** SAs, which carry " +
		"the broad Editor role by default and so raise the impact; **parses the embedded PKCS#8 RSA key** to " +
		"confirm it is real and report its size + a SubjectPublicKeyInfo SHA-256 fingerprint; and runs the " +
		"**ROCA (CVE-2017-15361)** weak-key test on the modulus. **No confidently-wrong output**: it asserts " +
		"the key's **structure and identity only** — never that the key is live or what IAM roles it holds " +
		"(that needs a GCP API call); a `private_key` that fails to parse is reported as such (identity fields " +
		"still surfaced), not asserted genuine; a JSON without the service-account shape is rejected. No " +
		"network, no device, transmits nothing — Low risk. Pairs with the credential tooling (`aws_key_decode` " +
		"/ `azure_sas_decode` / `secret_identify` / `roca_detect`).\n\n" +
		"Source: docs/catalog/gap-analysis.md (secret / credential forensics). Wrap-vs-native: native — " +
		"encoding/json + stdlib crypto/x509 PKCS#8 + internal/roca, no new go.mod dep. Key-file schema is " +
		"Google's documented format; the public-key fingerprint is anchored to an openssl-computed vector.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"key":{"type":"string","description":"The service-account JSON key file contents."}
		},
		"required":["key"]
	}`),
	Required:  []string{"key"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   gcpServiceAccountDecodeHandler,
}

func gcpServiceAccountDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	key := strings.TrimSpace(str(p, "key"))
	if key == "" {
		return "", fmt.Errorf("gcp_service_account_decode: 'key' is required")
	}
	res, err := gcpsakey.Decode(key)
	if err != nil {
		return "", fmt.Errorf("gcp_service_account_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
