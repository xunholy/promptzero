// lldp.go — host-side LLDP packet decoder Spec.
// Wraps the internal/lldp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/lldp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(lldpDecodeSpec)
}

var lldpDecodeSpec = Spec{
	Name: "lldp_decode",
	Description: "Decode a Link Layer Discovery Protocol (LLDP) payload per IEEE " +
		"802.1AB-2009. LLDP is the multi-vendor switch-to-switch and switch-to-host " +
		"topology-discovery protocol every datacenter operator relies on: every " +
		"managed switch advertises its chassis ID, port ID, system name, capabilities, " +
		"and management address on every active link, and every modern NIC / server " +
		"agent (lldpd / lldpctl / Cisco DNA Center / Juniper Junos / Arista EOS) " +
		"consumes them. Natural complement to `arp_decode` and `icmp_packet_decode`. " +
		"Decodes:\n\n" +
		"- **TLV walker** — each TLV is 16 bits of header (7-bit type + 9-bit length, " +
		"big-endian) followed by `length` bytes of body. The walker stops at End of " +
		"LLDPDU (type 0) or at the buffer end.\n" +
		"- **Mandatory TLVs** (must appear in this order at the start of every LLDPDU " +
		"per §8.1.1):\n" +
		"  - **Type 1 Chassis ID** — 1-byte subtype + variable-length ID. Subtypes:\n" +
		"    1 Chassis component / 2 Interface alias / 3 Port component / 4 MAC " +
		"address (formatted as XX:XX:XX:XX:XX:XX) / 5 Network address (1-byte AFI " +
		"+ address) / 6 Interface name / 7 Locally assigned.\n" +
		"  - **Type 2 Port ID** — same TLV shape as Chassis ID. Subtypes:\n" +
		"    1 Interface alias / 2 Port component / 3 MAC address / 4 Network address " +
		"/ 5 Interface name / 6 Agent circuit ID / 7 Locally assigned.\n" +
		"  - **Type 3 Time-To-Live** — uint16 BE seconds; the duration the receiving " +
		"agent should retain the discovered neighbour.\n" +
		"- **Optional standardised TLVs**:\n" +
		"  - **Type 0 End of LLDPDU** — terminates the walker.\n" +
		"  - **Type 4 Port Description** / **Type 5 System Name** / **Type 6 System " +
		"Description** — UTF-8 strings (printable check; falls back to hex).\n" +
		"  - **Type 7 System Capabilities** — 2-byte capability flags + 2-byte enabled " +
		"flags. **11 documented capability bits**: Other / Repeater / MAC Bridge / " +
		"WLAN AP / Router / Telephone / DOCSIS Cable Device / Station Only / C-VLAN " +
		"Component / S-VLAN Component / Two-port MAC Relay.\n" +
		"  - **Type 8 Management Address** — address string length + IANA Address " +
		"Family Number subtype (1 IPv4 / 2 IPv6 / 6 MAC / 16 DNS name) + address " +
		"bytes + interface numbering subtype (1 unknown / 2 ifIndex / 3 " +
		"systemPortNumber) + interface number (uint32 BE) + OID string length + " +
		"OID bytes (BER-encoded; surfaced as hex).\n" +
		"- **Organizationally Specific TLV** (type 127): 3-byte OUI + 1-byte subtype " +
		"+ organisation-defined body. Common OUIs surfaced with canonical names:\n" +
		"  - 00-12-0F IEEE 802.3 (link aggregation, max frame size, power-via-MDI)\n" +
		"  - 00-80-C2 IEEE 802.1 (Port VLAN ID, Protocol VLAN, VLAN Name)\n" +
		"  - 00-12-BB LLDP-MED (TIA TR-41, VoIP/PoE policy)\n" +
		"  - 00-13-1F PROFIBUS (PROFINET)\n" +
		"  - 00-01-42 Cisco Systems\n" +
		"- **Mandatory-TLV ordering check** — surfaces a note if the first three TLVs " +
		"are not Chassis ID + Port ID + TTL in that order per IEEE 802.1AB §8.1.1.\n\n" +
		"Pure offline parser — operators paste LLDP payload bytes (after the Ethernet " +
		"header strip, EtherType 0x88CC) from a `tcpdump -i ethX -X ether proto 0x88CC` " +
		"line, a Wireshark Follow-Frame view, an `lldpctl -f xml` export, or any " +
		"LLDP-emitting tool and inspect every documented field.\n\n" +
		"Out of scope (deferred): Ethernet framing (feed the LLDP payload after the " +
		"dst MAC + src MAC + EtherType bytes); LLDP-MED extension TLV-by-TLV decoding " +
		"(LLDP-MED OUI subtypes surfaced with raw body hex); IEEE 802.1 / 802.3 OUI " +
		"subtypes (VLAN ID / link aggregation / max frame size / power-via-MDI — raw " +
		"body hex); CDP (Cisco Discovery Protocol, proprietary EtherType 0x2000 — a " +
		"sibling Spec).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational datacenter L2 discovery " +
		"protocol). Wrap-vs-native: native — IEEE 802.1AB is fully public; wire format " +
		"is a tight type/length TLV walker over a small documented type catalogue, no " +
		"crypto, no compression, no varints.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"LLDP payload bytes (after the Ethernet header) as hex. Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   lldpDecodeHandler,
}

func lldpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("lldp_decode: 'hex' is required")
	}
	res, err := lldp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("lldp_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
