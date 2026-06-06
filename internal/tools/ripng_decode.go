// ripng_decode.go — host-side RIPng (RFC 2080, IPv6 RIP) decoder Spec,
// delegating to internal/ripng.
//
// Wrap-vs-native: native — a 4-byte header + an array of fixed 20-byte
// route table entries; byte-field reads + an array walk, stdlib only.
// The IPv6 sibling of rip (RIPv1/v2). Surfaces the advertised IPv6
// routes — a routing-recon / route-injection surface. Offline read.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ripng"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ripngDecodeSpec)
}

var ripngDecodeSpec = Spec{
	Name: "ripng_decode",
	Description: "Decode **RIPng** (RFC 2080) — the IPv6 distance-vector routing protocol (UDP 521), the IPv6 " +
		"sibling of the project's `rip` (RIPv1/v2, IPv4). A **routing-reconnaissance and route-injection** " +
		"surface: RIPng carries no authentication, so a captured **Response** reveals every route a router " +
		"advertises (each IPv6 prefix, its route tag and hop-count metric), and because the protocol trusts " +
		"any Response on the segment, an on-link attacker can **inject or blackhole routes** — decoding the " +
		"advertisement is the first step of auditing that exposure.\n\n" +
		"Decodes the 4-byte header (command — **request / response**, version) and the array of 20-byte " +
		"**route table entries** (128-bit prefix, route tag, prefix length, metric), correctly handling the " +
		"two RFC 2080 special entries: the **next-hop RTE** (metric 0xFF — the address field is a gateway, " +
		"not a route) and the **infinity metric** (16 — an unreachable / withdrawn route). The RFC 2080 " +
		"whole-table request (a single `::/0`, metric-16 entry) is flagged.\n\n" +
		"No confidently-wrong output: every byte maps to a defined field; trailing bytes that do not form a " +
		"whole entry are noted, not guessed. No network, no device, transmits nothing, so it is Low risk. " +
		"':' / '-' / '_' / whitespace separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (IPv6 routing-protocol recon). Wrap-vs-native: native — a " +
		"byte-field read + an array walk, stdlib only, no new go.mod dep. Verified field-for-field against " +
		"scapy's RIPng layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The RIPng message (the UDP-521 payload) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ripngDecodeHandler,
}

func ripngDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("ripng_decode: 'hex' is required")
	}
	res, err := ripng.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("ripng_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
