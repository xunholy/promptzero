// kubeconfig_decode.go — host-side Kubernetes kubeconfig decoder Spec,
// delegating to internal/kubeconfig.
//
// Wrap-vs-native: native — gopkg.in/yaml.v3 (already a direct dep) over the
// documented kubeconfig schema; no new go.mod dep. Turns a captured kubeconfig
// into its attack surface (cluster endpoints, TLS posture, credential shape per
// user) for cluster-pentest / IR triage. Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/kubeconfig"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(kubeconfigDecodeSpec)
}

var kubeconfigDecodeSpec = Spec{
	Name: "kubeconfig_decode",
	Description: "Decode a **Kubernetes kubeconfig** into the attack surface it exposes. A kubeconfig is one of " +
		"the highest-value artifacts in a cluster pentest or incident — it bundles the API endpoint(s) and, " +
		"frequently, a **directly-usable credential** (an embedded client key, a bearer token, or a basic-auth " +
		"password). When one turns up in loot the questions are which clusters it reaches, whether any has " +
		"**certificate verification disabled** (`insecure-skip-tls-verify` — a MITM foothold), and whether it " +
		"carries a credential that works on its own vs. one that defers to an external helper. This answers " +
		"them **offline — no API server is contacted**.\n\n" +
		"Reports each **cluster** (API server URL, TLS-verify posture, CA presence), each **user** reduced to " +
		"its **credential kinds** (client-certificate / client-key / token / basic-auth / `exec:<plugin>` / " +
		"`auth-provider:<name>`) with an **embedded-credential** flag (true for an embedded key/token/password " +
		"— usable as-is; false for an `exec`/`auth-provider` that needs the operator's own cloud login), and " +
		"each **context** (cluster+user+namespace, with the current one marked). Summarises the insecure " +
		"clusters and whether any embedded credential is present. **No confidently-wrong output**: it reports " +
		"**structure and credential shape only** — it never asserts a credential is live or its RBAC (needs a " +
		"cluster call) and **does not emit the secret material** (presence is flagged, values are not); input " +
		"that is not a `kind: Config` document is rejected. No network, no device, transmits nothing — Low " +
		"risk. Pairs with the credential tooling (`secret_identify` / `gcp_service_account_decode` / " +
		"`jwt_decode`).\n\n" +
		"Source: docs/catalog/gap-analysis.md (credential / cloud forensics). Wrap-vs-native: native — " +
		"gopkg.in/yaml.v3 (already a direct dep) over the documented kubeconfig (clientcmd api.v1.Config) " +
		"schema, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"kubeconfig":{"type":"string","description":"The kubeconfig file contents (YAML)."}
		},
		"required":["kubeconfig"]
	}`),
	Required:  []string{"kubeconfig"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   kubeconfigDecodeHandler,
}

func kubeconfigDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	cfg := strings.TrimSpace(str(p, "kubeconfig"))
	if cfg == "" {
		return "", fmt.Errorf("kubeconfig_decode: 'kubeconfig' is required")
	}
	res, err := kubeconfig.Decode(cfg)
	if err != nil {
		return "", fmt.Errorf("kubeconfig_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
