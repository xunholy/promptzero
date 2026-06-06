// mld_decode.go — host-side MLD (Multicast Listener Discovery, RFC 2710 /
// RFC 3810) decoder Spec, delegating to internal/mld.
//
// Wrap-vs-native: native — a small ICMPv6 message: a fixed header + a
// multicast address, and for MLDv2 a source list (Query) or group-record
// array (Report); a byte-field read + two walks, stdlib only. The IPv6
// multicast-membership decoder — surfaces the groups a host has joined (and
// MLDv2 source filters) from a captured ICMPv6 MLD message. Offline read, no
// hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/mld"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(mldDecodeSpec)
}

var mldDecodeSpec = Spec{
	Name: "mld_decode",
	Description: "Decode an **MLD (Multicast Listener Discovery)** message — the IPv6 multicast-group membership " +
		"protocol carried in ICMPv6: **MLDv1** (RFC 2710) and **MLDv2** (RFC 3810). MLD is the IPv6 counterpart " +
		"of IGMP: a host emits an MLD **Report** to tell the on-link router which IPv6 multicast groups it wants " +
		"to receive, and routers emit **Queries** to refresh that state. It is a **network-reconnaissance** " +
		"source — an MLD Report reveals exactly which multicast groups a host has joined (and, via the MLDv2 " +
		"source-filter records, which senders it includes or excludes), exposing the host's multicast-based " +
		"services: **mDNS / Bonjour** (ff02::fb), **LLMNR** (ff02::1:3), SSDP / UPnP, PTP, IPTV / streaming " +
		"groups. An MLD Query reveals the active querier and its robustness / interval parameters. The IPv6 " +
		"companion to `igmp_decode` / `igmpv3_decode` (IPv4 multicast) and the MLD member of the ICMPv6 family " +
		"alongside `ndp_decode`.\n\n" +
		"Decodes the MLDv1 Query / Report / Done (max-response-delay + multicast address, general-query " +
		"detection), the MLDv2 Query (the S / QRV / QQIC fields + the querier source list) and the MLDv2 Report " +
		"group records (record type — MODE_IS_INCLUDE / EXCLUDE / CHANGE_TO_* / ALLOW_NEW_SOURCES / " +
		"BLOCK_OLD_SOURCES — the multicast address and the source list).\n\n" +
		"No confidently-wrong output: the MLDv1 / MLDv2 layouts and the MLDv2 Max-Response-Code + QQIC " +
		"floating-point encodings were verified field-for-field against scapy's MLD layers + RFC 2710 / RFC " +
		"3810 (a 50-row MLDv2-Report differential decoded identically, zero mismatches). A type-130 Query is " +
		"dispatched to MLDv1 vs MLDv2 by length (RFC 3810 §8.1: MLDv2 ≥ 28 bytes); a non-MLD ICMPv6 type is " +
		"rejected. The ICMPv6 checksum is computed over an IPv6 pseudo-header absent from a bare MLD capture, " +
		"so it is surfaced as raw hex without a validity claim (matching `ndp_decode`). No network, no device, " +
		"transmits nothing, so it is Low risk. The input is the ICMPv6 payload (starting at the Type byte). " +
		"':' / '-' / '_' / whitespace separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (IPv6 multicast-membership recon). Wrap-vs-native: native — a " +
		"byte-field read + two walks, stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The MLD message (the ICMPv6 payload, starting at the ICMPv6 Type byte — 130 Query / 131 Report / 132 Done / 143 v2 Report) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   mldDecodeHandler,
}

func mldDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("mld_decode: 'hex' is required")
	}
	res, err := mld.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("mld_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
