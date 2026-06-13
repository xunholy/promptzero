// rclone_config_decode.go — host-side rclone-config credential extractor Spec,
// delegating to internal/rcloneconfig.
//
// Wrap-vs-native: native — an INI scanner plus rclone's exact obscure-reveal
// transform (AES-256-CTR under rclone's hardcoded key, stdlib crypto only, no
// new go.mod dep). An rclone.conf off a backup / sync / CI host yields live
// cloud-storage credentials; its obscured passwords are reversible offline.
// Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/rcloneconfig"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(rcloneConfigDecodeSpec)
}

var rcloneConfigDecodeSpec = Spec{
	Name: "rclone_config_decode",
	Description: "Extract **cloud-remote credentials** from an **rclone config** (`rclone.conf`) — common loot on a " +
		"**backup / sync / CI host**, where each `[remote]` holds the credentials for an S3 bucket, a Google " +
		"Drive, an SFTP/WebDAV server, and so on. The uniquely recoverable part is rclone's **obscured " +
		"passwords**: rclone does **not** store them in plaintext, but it does **not** encrypt them with a user " +
		"secret either — it 'obscures' them with **AES-256-CTR under a single hardcoded key** (explicitly **not** " +
		"a security measure, per rclone's own docs), so they are **fully reversible offline**. This **reveals** " +
		"them and surfaces the **plaintext secrets** (S3 access/secret keys, OAuth tokens) the config holds " +
		"verbatim, per remote (with its `type`).\n\n" +
		"**No confidently-wrong output**: a password field (`pass` / `password` / `password2`) is revealed only " +
		"when its value is a valid obscure blob that decodes to **printable** text; a value that does not decode, " +
		"or decodes to non-printable bytes, is reported as **plaintext** / **unrevealable** with the raw value " +
		"surfaced — never a garbage 'password'. Input that is not an rclone config is rejected. No network, no " +
		"device, transmits nothing — Low risk. Pairs with `vpn_config_decode` / `wifi_config_decode` / " +
		"`bluez_pairing_decode` (the host-loot extraction set).\n\n" +
		"Source: docs/catalog/gap-analysis.md (cloud / credential forensics). Wrap-vs-native: native — INI " +
		"scanner + rclone's exact reveal transform (stdlib crypto, no new go.mod dep); key and algorithm taken " +
		"verbatim from rclone `fs/config/obscure/obscure.go` and anchored to rclone's own published reveal " +
		"vectors.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"config":{"type":"string","description":"The rclone config file contents (rclone.conf)."}
		},
		"required":["config"]
	}`),
	Required:  []string{"config"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   rcloneConfigDecodeHandler,
}

func rcloneConfigDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	cfg := strings.TrimSpace(str(p, "config"))
	if cfg == "" {
		return "", fmt.Errorf("rclone_config_decode: 'config' is required")
	}
	res, err := rcloneconfig.Decode(cfg)
	if err != nil {
		return "", fmt.Errorf("rclone_config_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
