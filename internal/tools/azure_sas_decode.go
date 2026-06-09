// azure_sas_decode.go — host-side Azure Storage SAS token decoder Spec,
// delegating to internal/azuresas.
//
// Wrap-vs-native: native — a SAS token is a URL query string; decoding it is a
// query-param parse + a lookup of Azure's documented single-letter field codes,
// stdlib only. Surfaces a leaked SAS token's blast radius (permissions / expiry
// / scope) offline — cloud-IR / pentest triage. Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/azuresas"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(azureSASDecodeSpec)
}

var azureSASDecodeSpec = Spec{
	Name: "azure_sas_decode",
	Description: "Decode an **Azure Storage SAS token** — the `?sv=…&sp=…&se=…&sig=…` query string that grants " +
		"delegated access to Azure Blob / Queue / Table / File storage — into its **blast radius**: the SAS " +
		"type (service / account / user-delegation), the **granted permissions** expanded to human " +
		"operations, the **validity window** (start / expiry), the **scope** (services / resource types / " +
		"resource), the allowed **IP range** and **protocol**, and any stored-access-policy reference. A " +
		"leaked SAS token (in a URL, a config, a log, a repo) is real cloud-IR / pentest loot, and the first " +
		"question is always *what can this token do, and until when?* — answered here **offline**.\n\n" +
		"Accepts a full URL or a bare query string (with or without a leading `?`). The HMAC **signature " +
		"cannot be verified without the account key**, so it is reported present-but-opaque, not validated. " +
		"**No confidently-wrong output**: permission letters are **context-dependent** (e.g. `p` = " +
		"Permissions/ACL on a blob but Process on a queue; `r` = Read on a blob but Query on a table), so " +
		"they are expanded against the resource context derived from `sr` / `ss` / `tn`; when the context " +
		"isn't definite (account SAS, or a context-free token) the common Blob meaning is shown **with a " +
		"caveat note**, and an unknown letter is surfaced raw. A string with no SAS fields is rejected. No " +
		"network, no device, transmits nothing — Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (cloud-credential forensics — the Azure companion to " +
		"aws_key_decode). Wrap-vs-native: native — net/url query parse + the documented Azure SAS field-code " +
		"tables, stdlib only, no new go.mod dep. Anchored to the Microsoft SAS reference's worked example " +
		"(sp=rw … sr=b → Read+Write on a blob).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"sas":{"type":"string","description":"The Azure SAS token: a full URL (https://acct.blob.core.windows.net/…?sv=…) or a bare query string (sv=…&sp=…&sig=…)."}
		},
		"required":["sas"]
	}`),
	Required:  []string{"sas"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   azureSASDecodeHandler,
}

func azureSASDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	sas := strings.TrimSpace(str(p, "sas"))
	if sas == "" {
		return "", fmt.Errorf("azure_sas_decode: 'sas' is required")
	}
	res, err := azuresas.Decode(sas)
	if err != nil {
		return "", fmt.Errorf("azure_sas_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
