// dmarc_record.go — host-side DMARC policy record decoder Spec, delegating to
// internal/dmarc.
//
// Wrap-vs-native: native — RFC 7489 tag=value parsing, stdlib only. Decodes a
// DMARC DNS TXT record into its anti-spoofing enforcement posture, offline.
// No network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/dmarc"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(dmarcRecordDecodeSpec)
}

var dmarcRecordDecodeSpec = Spec{
	Name: "dmarc_record_decode",
	Description: "Decode a **DMARC policy DNS record** (the `_dmarc.<domain>` TXT record) into a domain's " +
		"**anti-spoofing enforcement posture**. DMARC is the policy that ties **SPF and DKIM** together and " +
		"tells receivers what to do with mail that fails alignment, so it is **the single best read on whether " +
		"a domain can be spoofed**. The headline finding is **objective and falls straight out of the record**: " +
		"`p=none` means the domain is **monitoring only and does NOT block spoofed mail** (the most common " +
		"DMARC misconfiguration — the domain looks protected but isn't), while `p=quarantine` / `p=reject` " +
		"actually enforce. Decodes the requested **policy** (`p`), **subdomain policy** (`sp`), sampling " +
		"**percent** (`pct`), **DKIM/SPF alignment** modes (`adkim`/`aspf`), failure-reporting options (`fo`), " +
		"and the **aggregate / forensic report destinations** (`rua`/`ruf` — themselves useful OSINT for " +
		"mapping a target's mail-security vendor).\n\n" +
		"**No confidently-wrong output**: the **`enforcing` verdict is derived directly from `p`** (objective, " +
		"not a guess); `pct<100` under an enforcing policy is flagged as **partial enforcement**; RFC 7489 " +
		"defaults (pct=100, adkim/aspf=r, ri=86400) are surfaced explicitly; a record missing the required " +
		"`p=` is surfaced **with a warning** (not a fabricated policy); a record not beginning with `v=DMARC1` " +
		"(e.g. an SPF record) is **rejected**. No network, no device, transmits nothing — Low risk. Pairs with " +
		"`dkim_record_decode` (the two halves of email-auth posture).\n\n" +
		"Source: docs/catalog/gap-analysis.md (email-authentication forensics). Wrap-vs-native: native — " +
		"RFC 7489 §6.3 tag=value parsing, stdlib only, **no new go.mod dep**. Pinned to **live published " +
		"records** (google.com / paypal.com `p=reject`, github.com `p=quarantine; sp=reject; pct=100; fo=1`) " +
		"and the RFC tag definitions / defaults.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"record":{"type":"string","description":"The DMARC policy TXT record, e.g. 'v=DMARC1; p=reject; rua=mailto:...'."}
		},
		"required":["record"]
	}`),
	Required:  []string{"record"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   dmarcRecordDecodeHandler,
}

func dmarcRecordDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	record := strings.TrimSpace(str(p, "record"))
	if record == "" {
		return "", fmt.Errorf("dmarc_record_decode: 'record' is required")
	}
	res, err := dmarc.Decode(record)
	if err != nil {
		return "", fmt.Errorf("dmarc_record_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
