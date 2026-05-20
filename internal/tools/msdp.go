// msdp.go — host-side MSDP packet decoder Spec.
// Wraps the internal/msdp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/msdp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(msdpDecodeSpec)
}

var msdpDecodeSpec = Spec{
	Name: "msdp_decode",
	Description: "Decode an MSDP (Multicast Source Discovery Protocol) packet per RFC " +
		"3618. MSDP is the inter-domain multicast protocol that completes the " +
		"multicast trio alongside IGMP (host↔router, covered by `igmp_decode`) " +
		"and PIM (router↔router intra-domain, covered by `pim_decode`). Each " +
		"PIM-SM domain has its own Rendezvous Points (RPs); MSDP connects RPs " +
		"across domains so that a receiver in one domain can join a multicast " +
		"group whose source is in another. Operationally, every major Internet " +
		"exchange + carrier core that carries multicast traffic (financial-market " +
		"data feeds, IPTV peering, content distribution) runs MSDP between RPs " +
		"over TCP port 639. Decodes:\n\n" +
		"- **3-byte TLV header** (RFC 3618 §3): byte 0 = **Type** with **6-entry " +
		"name table** (1 IPv4 Source-Active / 2 IPv4 SA Request / 3 IPv4 SA " +
		"Response / 4 Keepalive / 6 Notification / 7-8 deprecated traceroute " +
		"pair); bytes 1-2 = Length (uint16 BE; total including this header).\n" +
		"- **IPv4 Source-Active body** (Type 1; RFC 3618 §4.1): Entry Count + " +
		"RP Address (originating Rendezvous Point) + N × 12-byte entry (3-byte " +
		"Reserved + 1-byte Sprefix Length + 4-byte Group Address + 4-byte Source " +
		"Address) + optional encapsulated multicast datagram (typically the first " +
		"packet from a new source, sent to bootstrap MSDP peers that haven't yet " +
		"built (S, G) state).\n" +
		"- **IPv4 SA Request body** (Type 2; RFC 3618 §4.2): Reserved + Group " +
		"Address.\n" +
		"- **IPv4 SA Response body** (Type 3) — same layout as Source-Active.\n" +
		"- **Keepalive body** (Type 4) — empty.\n" +
		"- **Notification body** (Type 6; RFC 3618 §6.1): high-bit **O (Open)** " +
		"flag + 7-bit **Error Code** with **7-entry name table** (1 Message " +
		"Header Error / 2 SA-Request Error / 3 SA-Message/SA-Response Error / 4 " +
		"Hold Timer Expired / 5 Finite State Machine Error / 6 Notification / 7 " +
		"Cease) + Error Subcode + opaque data.\n\n" +
		"Pure offline parser — operators paste MSDP bytes (TCP port 639) from a " +
		"`tcpdump -X tcp port 639` line or a Wireshark Follow-TCP-Stream view " +
		"and get the documented type + body breakdown. A single buffer may " +
		"contain multiple back-to-back TLVs; all are walked and returned.\n\n" +
		"Out of scope (deferred): TCP framing (feed MSDP bytes after the TCP " +
		"payload extraction — MSDP runs on TCP port 639); MSDP state-machine " +
		"reasoning (peer setup, SA cache, hold-timer expiry, mesh-group RPF " +
		"check — higher-level analysis); encapsulated multicast datagram " +
		"dissection (when SA carries a bootstrap data packet, it's surfaced as " +
		"opaque hex; operators can feed it into `ip_packet_decode` to walk the " +
		"inner IP frame).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational inter-domain " +
		"multicast protocol; completes the IGMP + PIM + MSDP multicast trio for " +
		"every Internet exchange + carrier core that carries multicast traffic). " +
		"Wrap-vs-native: native — RFC 3618 is fully public; MSDP messages are " +
		"plain TLVs with a 3-byte common header + per-type body; no crypto, no " +
		"compression.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"MSDP packet bytes (after TCP payload extraction; TCP destination port 639). One or more back-to-back TLVs supported. Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   msdpDecodeHandler,
}

func msdpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("msdp_decode: 'hex' is required")
	}
	res, err := msdp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("msdp_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
