// igmpv3_decode.go — host-side IGMPv3 (RFC 3376, IPv4 multicast
// membership v3) decoder Spec, delegating to internal/igmpv3.
//
// Wrap-vs-native: native — a fixed header + a source list (Query) or a
// list of group records (Report); byte-field reads + two array walks,
// stdlib only. The v3 companion to igmp (v1/v2). Surfaces the multicast
// groups a host has joined + its source filters — multicast recon.
// Checksum-verified. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/igmpv3"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(igmpv3DecodeSpec)
}

var igmpv3DecodeSpec = Spec{
	Name: "igmpv3_decode",
	Description: "Decode **IGMPv3** (RFC 3376) — the IPv4 multicast group-membership protocol, version 3. A " +
		"**network-reconnaissance** source: an IGMPv3 **Membership Report** reveals exactly which multicast " +
		"groups a host has joined and — via the source-filter group records (**INCLUDE / EXCLUDE** mode) — " +
		"which senders it accepts or blocks, exposing the host's multicast-based services (mDNS " +
		"224.0.0.251, SSDP 239.255.255.250, PTP, IPTV / streaming groups); a **Membership Query** reveals " +
		"the active querier and its robustness / query-interval parameters. The v3 companion to the project's " +
		"`igmp` (v1/v2), whose record + source-list structure differs.\n\n" +
		"Decodes the header (type, checksum — **verified**) and, for a **Query**, the Max-Resp-Time, group " +
		"address, S flag, **QRV**, **QQIC** (both Max-Resp and QQIC via the RFC 3376 §4.1 floating-point " +
		"code), the source list and the **query type** (general / group-specific / group-and-source); for a " +
		"**Report**, each **group record** — record type (MODE_IS_INCLUDE / EXCLUDE / CHANGE_TO_* / " +
		"ALLOW_NEW_SOURCES / BLOCK_OLD_SOURCES), the multicast address and its source list.\n\n" +
		"No confidently-wrong output: the 16-bit one's-complement checksum is verified and surfaced as " +
		"checksum_valid (a failure is flagged, not hidden); rare auxiliary record data is surfaced as raw " +
		"hex. No network, no device, transmits nothing, so it is Low risk. ':' / '-' / '_' / whitespace " +
		"separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (IPv4 multicast-membership recon). Wrap-vs-native: native — " +
		"byte-field reads + array walks, stdlib only, no new go.mod dep. Verified field-for-field against " +
		"scapy's IGMPv3 layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The IGMPv3 message (the IGMP payload, after the IPv4 header) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   igmpv3DecodeHandler,
}

func igmpv3DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("igmpv3_decode: 'hex' is required")
	}
	res, err := igmpv3.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("igmpv3_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
