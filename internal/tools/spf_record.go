// spf_record.go — host-side SPF record decoder/analyser Spec, delegating to
// internal/spf.
//
// Wrap-vs-native: native — RFC 7208 term tokenising, stdlib only. Statically
// analyses an SPF DNS TXT record (mechanisms, the terminal `all` qualifier,
// the direct DNS-lookup count) offline. No network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/spf"
)

func init() { //nolint:gochecknoinits
	Register(spfRecordDecodeSpec)
}

var spfRecordDecodeSpec = Spec{
	Name: "spf_record_decode",
	Description: "Decode and **statically analyse an SPF record** (the `v=spf1 …` TXT record) — the third leg of " +
		"the **email-authentication triad** alongside `dkim_record_decode` and `dmarc_record_decode`. SPF " +
		"declares which hosts may send mail for a domain, so it is a direct read on **spoofability**. The " +
		"headline findings are **objective and fall straight out of the record**: the terminal **`all` " +
		"qualifier** sets the default disposition — `+all` authorises the **ENTIRE internet** to send as the " +
		"domain (critical), `?all` is neutral (no protection), `~all` softfail, `-all` fail (strict) — and the " +
		"count of **DNS-lookup-causing mechanisms** feeds the **RFC 7208 limit of 10** (exceeding it is a " +
		"permerror that makes SPF fail open). Decodes every mechanism (qualifier + type + value), the " +
		"`redirect=` / `exp=` modifiers, flags the **deprecated `ptr`** mechanism, and warns on a missing " +
		"terminal `all`, terms after `all` (unreachable), and multiple `all`.\n\n" +
		"**Scope / no confidently-wrong output**: this is **offline static analysis of one record** — the " +
		"reported lookup count is the number of lookup terms **in this record** (a **lower bound**; each " +
		"`include`/`redirect` resolves to more, and the RFC limit applies across the full resolved tree, " +
		"which needs live DNS — stated explicitly, never overclaimed). The `all` qualifier and mechanism " +
		"structure are fully determined offline; `+all` is flagged critical because it **objectively** " +
		"authorises all senders. A record not beginning with `v=spf1` is **rejected**. DNS multi-string " +
		"output (dig's `\"part1\" \"part2\"`) is reconstructed per TXT concatenation semantics. No network, " +
		"no device, transmits nothing — Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (email-authentication forensics — completes the triad). " +
		"Wrap-vs-native: native — RFC 7208 term tokenising, stdlib only, **no new go.mod dep**. Pinned to " +
		"live published records (google.com 1 include / `~all`; github.com 8 includes; the dig multi-string " +
		"join).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"record":{"type":"string","description":"The SPF TXT record, e.g. 'v=spf1 include:_spf.google.com ~all'. dig-style multi-string quoting is tolerated."}
		},
		"required":["record"]
	}`),
	Required:  []string{"record"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   spfRecordDecodeHandler,
}

func spfRecordDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	record := strings.TrimSpace(str(p, "record"))
	if record == "" {
		return "", fmt.Errorf("spf_record_decode: 'record' is required")
	}
	res, err := spf.Decode(record)
	if err != nil {
		return "", fmt.Errorf("spf_record_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
