// vlan.go — host-side IEEE 802.1Q / 802.1ad VLAN tag decoder
// Spec. Wraps the internal/vlan walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/vlan"
)

func init() { //nolint:gochecknoinits
	Register(vlanDecodeSpec)
}

var vlanDecodeSpec = Spec{
	Name: "vlan_decode",
	Description: "Decode IEEE 802.1Q (C-tag) and 802.1ad (S-tag, QinQ) VLAN tags per " +
		"IEEE 802.1Q-2018. VLAN tags are inserted between the source MAC and the " +
		"EtherType in every Ethernet frame on a tagged trunk port — every datacenter, " +
		"every enterprise floor switch, every carrier service-provider Ethernet link " +
		"uses them. Pure offline parser; pairs naturally with `arp_decode`, " +
		"`lldp_decode`, `cdp_decode`, and the IP-layer decoders. Decodes:\n\n" +
		"- **Tag walker** — consumes 4-byte tags starting at offset 0 until a " +
		"non-tag EtherType is encountered. Surfaces every tag in the stack plus the " +
		"final inner EtherType for forwarding into a payload decoder.\n" +
		"- **TPID table** (5 entries):\n" +
		"  - 0x8100 IEEE 802.1Q C-tag (Customer VLAN)\n" +
		"  - 0x88A8 IEEE 802.1ad S-tag (Service VLAN, QinQ)\n" +
		"  - 0x9100 / 0x9200 / 0x9300 — Legacy QinQ TPIDs (pre-standardisation)\n" +
		"- **TCI bit breakdown** (16 bits BE):\n" +
		"  - **PCP** (Priority Code Point, 3 bits) — 802.1p priority 0-7 with an " +
		"**8-entry name table**: 0 Background (Best Effort default), 1 Background " +
		"(Lowest), 2 Excellent Effort, 3 Critical Applications, 4 Video (<100ms " +
		"latency), 5 Voice (<10ms latency), 6 Internetwork Control, 7 Network " +
		"Control (Highest).\n" +
		"  - **DEI** (Drop Eligible Indicator, 1 bit) — formerly CFI (Canonical " +
		"Format Indicator); when 1, the frame may be dropped under congestion.\n" +
		"  - **VID** (VLAN Identifier, 12 bits, 0-4095) with special-value " +
		"annotations:\n" +
		"    - 0: priority-tagged frame (no VLAN; only PCP/DEI matter)\n" +
		"    - 1: default native VLAN (often the Cisco 'VLAN 1')\n" +
		"    - 4095: reserved (must not be used per IEEE 802.1Q §9.6)\n" +
		"- **Double-tag (QinQ) detection** — when the first tag's TPID is 0x88A8 " +
		"(or a legacy QinQ TPID) and the second tag's TPID is 0x8100, the frame is " +
		"service-provider tagged: the outer S-tag identifies the customer, the " +
		"inner C-tag identifies the customer's internal VLAN. A Note explains the " +
		"S-tag/C-tag mapping.\n" +
		"- **Triple+ tag flag** — unusual but valid stacks (3+ tags) surface a note " +
		"flagging the depth.\n" +
		"- **Inner EtherType identification** — **10-entry name table** for the " +
		"post-tag EtherType: 0x0800 IPv4 / 0x0806 ARP / 0x86DD IPv6 / 0x8035 RARP / " +
		"0x8847 MPLS unicast / 0x8848 MPLS multicast / 0x8863 PPPoE Discovery / " +
		"0x8864 PPPoE Session / 0x888E EAPOL (802.1X) / 0x88CC LLDP / 0x88E5 MACsec " +
		"(802.1AE). Length-field detection (<0x0600) for 802.3 LLC frames.\n\n" +
		"Pure offline parser — operators paste the tag bytes (starting at the first " +
		"TPID after the Ethernet src MAC) from a `tcpdump -i ethX -X` line, a " +
		"Wireshark Follow-Frame view, or any VLAN-emitting tool and get the " +
		"documented PCP / DEI / VID structure plus inner-EtherType identification.\n\n" +
		"Out of scope (deferred): Ethernet dst MAC + src MAC parsing (feed the bytes " +
		"starting at the first TPID); VLAN translation / TPID rewriting (a separate " +
		"L2-config concern); inner-payload dissection (the inner EtherType is " +
		"surfaced; operators pipe the post-tag bytes to the appropriate decoder); " +
		"MAC-in-MAC (IEEE 802.1ah, PBB — different encapsulation; future Spec).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational L2 tag protocol — " +
		"universal in enterprise and carrier Ethernet). Wrap-vs-native: native — " +
		"IEEE 802.1Q is fully public; each tag is a tight 32-bit field; no crypto, " +
		"no compression, no length prefixes.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"VLAN-tagged bytes starting at the first TPID (after the Ethernet src MAC); must include at least one 4-byte tag plus the final 2-byte EtherType. Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   vlanDecodeHandler,
}

func vlanDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("vlan_decode: 'hex' is required")
	}
	res, err := vlan.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("vlan_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
