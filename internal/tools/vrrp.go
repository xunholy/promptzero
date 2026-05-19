// vrrp.go — host-side VRRP packet decoder Spec.
// Wraps the internal/vrrp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/vrrp"
)

func init() { //nolint:gochecknoinits
	Register(vrrpDecodeSpec)
}

var vrrpDecodeSpec = Spec{
	Name: "vrrp_decode",
	Description: "Decode a Virtual Router Redundancy Protocol (VRRP) packet per RFC " +
		"5798 (v3 — IPv4 + IPv6) and the older RFC 3768 (v2 — IPv4 only, still " +
		"widely deployed). VRRP is the first-hop gateway redundancy protocol used in " +
		"nearly every enterprise + datacenter to give end hosts a virtual default " +
		"gateway that survives the failure of any single router. Pairs with " +
		"`bfd_control_decode` + `bgp_message_decode` + `ospf_packet_decode` for the " +
		"complete routing + redundancy + liveness picture. Decodes:\n\n" +
		"- **8-byte common header**:\n" +
		"  - byte 0: Version (4 bits; 2 or 3) + Type (4 bits; only 1 Advertisement " +
		"is defined).\n" +
		"  - byte 1: **Virtual Router Identifier (VRID)** — 1-255; the per-VLAN " +
		"HA-group identifier.\n" +
		"  - byte 2: **Priority** — 0-255. **Semantic surface**:\n" +
		"    - 0 = withdraw (router signalling 'remove me from this VR / shutting " +
		"down')\n" +
		"    - 100 = default backup priority\n" +
		"    - 255 = IP address owner (highest priority, always Master)\n" +
		"  - byte 3: Count IPvX Addresses.\n" +
		"  - **bytes 4-5 (version-specific)**:\n" +
		"    - **VRRPv2**: byte 4 = AuthType (**3-entry name table**: 0 No " +
		"Authentication, 1 Simple Text Password — deprecated per RFC 5798 §9.3, 2 IP " +
		"Authentication Header — deprecated per RFC 2402); byte 5 = AdverInt " +
		"(seconds, default 1).\n" +
		"    - **VRRPv3**: 4-bit Reserved + 12-bit **Max Adver Interval** (in " +
		"centiseconds; surfaced both as cs and converted to ms; default 100 cs = " +
		"1 second).\n" +
		"  - bytes 6-7: Checksum (uint16 BE, hex-formatted).\n" +
		"- **Virtual Address list** — N × 4 bytes (IPv4) or N × 16 bytes (IPv6). " +
		"Address family inferred by byte arithmetic (remaining bytes ÷ Count); " +
		"surfaced as canonical IP strings.\n" +
		"- **VRRPv2 Authentication Data** (8 bytes, when AuthType 1 = Simple Text) " +
		"— surfaced as decoded UTF-8 with trailing nulls trimmed for readability, " +
		"plus raw hex for verification.\n" +
		"- **Conformance check** — Type != 1 surfaces a Note (only Advertisement is " +
		"defined); Version not in {2, 3} surfaces a Note.\n\n" +
		"Pure offline parser — operators paste VRRP bytes (IP protocol number 112, " +
		"multicast to 224.0.0.18 for IPv4 or ff02::12 for IPv6) from a `tcpdump -X " +
		"proto 112` line, a Wireshark Follow-IP-Stream view, or any VRRP-speaking " +
		"router's tcpdump and get the documented header + per-version body + virtual " +
		"address list.\n\n" +
		"Out of scope (deferred): IP framing (feed bytes after IPv4/IPv6 header " +
		"strip — VRRP runs over IP protocol 112); VRRPv2 IP Authentication Header " +
		"(Auth Type 2 — auth wrapped in the IP header per RFC 2402, not in the VRRP " +
		"frame); Master election simulation (Priority is surfaced; multi-router HA " +
		"election reasoning is higher-level); VRRP cryptographic verification (RFC " +
		"3768 Auth Types are all deprecated; if integrity is needed, run over IPsec).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational gateway-redundancy " +
		"protocol — universal in enterprise + datacenter networks). Wrap-vs-native: " +
		"native — RFC 5798 + RFC 3768 are fully public; wire format is a tight " +
		"8-byte fixed header followed by a list of 4-byte (IPv4) or 16-byte (IPv6) " +
		"virtual addresses; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"VRRP packet bytes (after IPv4/IPv6 header strip; IP protocol number 112). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   vrrpDecodeHandler,
}

func vrrpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("vrrp_decode: 'hex' is required")
	}
	res, err := vrrp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("vrrp_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
