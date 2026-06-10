// dockercfg_decode.go — host-side Docker registry config decoder Spec,
// delegating to internal/dockercfg.
//
// Wrap-vs-native: native — encoding/json + encoding/base64 over the documented
// Docker config schema; no new go.mod dep. Turns a captured registry config
// (config.json / legacy .dockercfg / k8s dockerconfigjson pull secret) into the
// registries + usernames it authenticates as for loot triage. Offline; no
// network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/dockercfg"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(dockercfgDecodeSpec)
}

var dockercfgDecodeSpec = Spec{
	Name: "dockercfg_decode",
	Description: "Decode a **Docker registry credential config** into the registries it authenticates to and " +
		"the username each entry carries. Registry creds turn up constantly in loot — `~/.docker/config.json` " +
		"on developer and CI hosts, the legacy `.dockercfg`, and most consequentially the Kubernetes " +
		"`kubernetes.io/dockerconfigjson` **image-pull secret** (whose decoded payload is exactly this " +
		"format). A registry credential with push access is a **supply-chain primitive** (publish a malicious " +
		"image tag), so the questions are which registries it reaches, what username it authenticates as, and " +
		"whether the credential is **embedded** (usable as-is) or delegated to a **credential helper** " +
		"(`credHelpers` / `credsStore`, which needs the operator's own login). Answered **offline — no " +
		"registry is contacted**.\n\n" +
		"Handles the modern `config.json` and the legacy `.dockercfg`; for each registry reports the host, the " +
		"**username** (from the base64 `auth` field), whether a **password** or an **identity token** is " +
		"present, and any per-registry credential helper. **No confidently-wrong output**: it reports the " +
		"registry, username, and credential **shape** only — it **does not emit the decoded password** " +
		"(presence is flagged, the secret is not echoed), never contacts a registry, and never asserts the " +
		"credential is live; a malformed `auth` field is flagged rather than treated as a credential, and " +
		"input that is not a recognisable Docker config is rejected. No network, no device, transmits nothing " +
		"— Low risk. Pairs with `kubeconfig_decode` (k8s pull secrets) and `secret_identify`.\n\n" +
		"Source: docs/catalog/gap-analysis.md (credential / cloud forensics). Wrap-vs-native: native — " +
		"encoding/json + encoding/base64 over the documented docker/cli config schema, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"config":{"type":"string","description":"The Docker config JSON (config.json / .dockercfg / decoded dockerconfigjson)."}
		},
		"required":["config"]
	}`),
	Required:  []string{"config"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   dockercfgDecodeHandler,
}

func dockercfgDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	cfg := strings.TrimSpace(str(p, "config"))
	if cfg == "" {
		return "", fmt.Errorf("dockercfg_decode: 'config' is required")
	}
	res, err := dockercfg.Decode(cfg)
	if err != nil {
		return "", fmt.Errorf("dockercfg_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
