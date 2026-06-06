// erspan_decode.go — host-side ERSPAN (Encapsulated Remote SPAN) header
// decoder Spec, delegating to internal/erspan.
//
// Wrap-vs-native: native — the ERSPAN header is a fixed bitfield (Type II
// 8 octets, Type III 12) carried as a GRE payload (proto 0x88BE/0x22EB);
// bit-masking a few words. Pairs with gre_decode. Surfaces the mirrored
// frame + the monitoring topology. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/erspan"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(erspanDecodeSpec)
}

var erspanDecodeSpec = Spec{
	Name: "erspan_decode",
	Description: "Decode the **ERSPAN** (Encapsulated Remote SPAN) header — Cisco's protocol for carrying a " +
		"port-mirror (SPAN) session across a routed network inside a **GRE tunnel**. Seeing ERSPAN in a " +
		"capture is itself a finding: it means traffic on some switch is being **mirrored and shipped " +
		"elsewhere** (lawful intercept, an IDS feed, or an attacker exfiltrating mirrored traffic), and the " +
		"encapsulated payload is the original mirrored Ethernet frame in the clear — so an ERSPAN capture " +
		"both exposes the **monitoring topology** (session id, source VLAN) and lets the mirrored frame be " +
		"**peeled out** for further analysis. Pairs with `gre_decode` (the tunnel that carries it).\n\n" +
		"Decodes the **Type II** (8-octet) and **Type III** (12-octet) headers: version, source **VLAN**, " +
		"class of service, the truncated flag, the **session id**, and (II) the port index / (III) the " +
		"32-bit timestamp. Accepts the ERSPAN header itself, or a **GRE packet** (protocol 0x88BE / 0x22EB) " +
		"whose payload is ERSPAN — the GRE header is stripped. The **mirrored Ethernet frame** is surfaced " +
		"as hex (feed it to the relevant L2/L3 decoder).\n\n" +
		"No confidently-wrong output: the Type III platform-specific sub-header flags beyond the timestamp " +
		"are left in the raw remainder rather than decoded into possibly-wrong fields. No network, no " +
		"device, transmits nothing, so it is Low risk. ':' / '-' / '_' / whitespace separators and a '0x' " +
		"prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (port-mirror / traffic-interception recon). Wrap-vs-native: " +
		"native — fixed bitfield, stdlib only, no new go.mod dep. Verified field-for-field against scapy's " +
		"ERSPAN_II / ERSPAN_III layers.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"An ERSPAN header as hex (Type II 8 octets / Type III 12), or a GRE packet (proto 0x88BE/0x22EB) whose payload is ERSPAN. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   erspanDecodeHandler,
}

func erspanDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("erspan_decode: 'hex' is required")
	}
	res, err := erspan.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("erspan_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
