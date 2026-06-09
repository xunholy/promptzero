// email_auth.go — host-side unified email-authentication record router Spec,
// delegating to internal/emailauth.
//
// Wrap-vs-native: native orchestration over the in-tree SPF / DKIM / DMARC
// decoders. Detects an email-auth DNS TXT record's kind and dispatches to the
// matching decoder, offline. No network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/emailauth"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(emailAuthDecodeSpec)
}

var emailAuthDecodeSpec = Spec{
	Name: "email_auth_decode",
	Description: "**Unified front-end for email-authentication records** — the email-security analogue of " +
		"`secret_identify` / `hash_identify`. Paste **any** email-auth DNS TXT record (**SPF**, **DKIM**, or " +
		"**DMARC**) and it **detects the kind and routes** to the matching decoder, so you (or an agent) " +
		"pulling records from a bulk DNS dump / a config / a capture need not pre-classify them. The result " +
		"names the detected `kind` and carries the full typed decode — SPF mechanisms + `all` qualifier + " +
		"lookup count, DKIM key type/size + weak-key flag + RSA modulus (for `roca_detect` chaining), or " +
		"DMARC enforcement posture (`p=none` monitoring-only, alignment, reports).\n\n" +
		"Detection is by the record's **`v=` version tag** (the unambiguous discriminator SPF and DMARC both " +
		"require, and DKIM uses when present); a DKIM key record that omits the optional `v=` is recognised " +
		"by its `p=`/`k=` tags. **No confidently-wrong output**: routing is by the explicit version prefix, " +
		"so an SPF record is never sent to the DKIM decoder; an unrecognised record (no `v=spf1`/`v=DMARC1`/" +
		"`v=DKIM1` prefix and no DKIM `p=`/`k=`) is **rejected**, never guessed; each underlying decoder " +
		"keeps its own RFC-anchored validation. No network, no device, transmits nothing — Low risk. The " +
		"single entry point to `spf_record_decode` + `dkim_record_decode` + `dmarc_record_decode`.\n\n" +
		"Source: docs/catalog/gap-analysis.md (email-authentication forensics — the unified router over the " +
		"triad). Wrap-vs-native: native orchestration over the already-verified, independently spec-/oracle-" +
		"anchored and fuzzed in-tree decoders — **no new go.mod dep**, no new parsing logic, no new external " +
		"trust.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"record":{"type":"string","description":"An email-auth DNS TXT record (SPF v=spf1…, DMARC v=DMARC1;…, or DKIM v=DKIM1;…/k=…;p=…). dig-style quoting is tolerated."}
		},
		"required":["record"]
	}`),
	Required:  []string{"record"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   emailAuthDecodeHandler,
}

func emailAuthDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	record := strings.TrimSpace(str(p, "record"))
	if record == "" {
		return "", fmt.Errorf("email_auth_decode: 'record' is required")
	}
	res, err := emailauth.Decode(record)
	if err != nil {
		return "", fmt.Errorf("email_auth_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
