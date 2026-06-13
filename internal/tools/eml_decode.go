// eml_decode.go — host-side phishing-email triage Spec, delegating to
// internal/eml.
//
// Wrap-vs-native: native — Go stdlib net/mail + mime/multipart parse the
// message; the phishing-triage analysis is layered on top. No new go.mod dep.
// The email is the delivery envelope for the .lnk / PDF / pickle payloads the
// other malware-triage tools decode. Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/eml"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(emlDecodeSpec)
}

var emlDecodeSpec = Spec{
	Name: "eml_decode",
	Description: "Triage a raw **email message** (`.eml` / RFC 5322) for **phishing indicators** — the delivery " +
		"envelope for the payloads the other malware-triage tools decode (a `.lnk` / weaponised PDF / macro " +
		"doc arrives as an attachment). Parses the message (stdlib RFC 5322 headers + MIME body) and layers " +
		"the analyst triage: the **From / Reply-To / Return-Path** identities and domains (and their " +
		"**mismatches** — the classic spoof), the **SPF / DKIM / DMARC** results from `Authentication-Results`, " +
		"the **Received-hop** count, every **attachment** (filename / type / decoded size) with a **danger " +
		"flag** for executable / script / **double-extension** (`invoice.pdf.exe`) / archive files, and the " +
		"**URLs** in the body (IP-literal and punycode/IDN called out).\n\n" +
		"**No confidently-wrong output**: parsing uses the stdlib RFC 5322 / MIME parsers; a header absent from " +
		"the message is left empty, never guessed; the **suspicious** verdict is a labelled heuristic (a " +
		"From↔Reply-To domain mismatch, an auth failure, a dangerous attachment, or an IP/punycode URL) — a " +
		"clean result is **not** a guarantee of safety; attachment bytes are size-capped and **never executed**. " +
		"No network, no device, transmits nothing — Low risk. **Chains into** `lnk_decode` / `pdf_malware_scan` " +
		"/ `pickle_decode` for the decoded attachment.\n\n" +
		"Provide the **raw email text** (`.eml`). Source: docs/catalog/gap-analysis.md (malware / phishing " +
		"triage). Wrap-vs-native: native — Go stdlib `net/mail` + `mime/multipart` + the triage layer, no new " +
		"go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"eml":{"type":"string","description":"The raw email message (.eml / RFC 5322 text, with headers, a blank line, then the MIME body)."}
		},
		"required":["eml"]
	}`),
	Required:  []string{"eml"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   emlDecodeHandler,
}

func emlDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "eml")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("eml_decode: 'eml' is required")
	}
	res, err := eml.Decode([]byte(raw))
	if err != nil {
		return "", fmt.Errorf("eml_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
