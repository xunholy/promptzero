// gtp.go — host-side GTP-U packet decoder Spec.
// Wraps the internal/gtp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/gtp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(gtpUDecodeSpec)
}

var gtpUDecodeSpec = Spec{
	Name: "gtp_u_decode",
	Description: "Decode a GPRS Tunneling Protocol User Plane (GTP-U) packet per 3GPP " +
		"TS 29.281. GTP-U is the encapsulation every cellular operator carries on its " +
		"S1-U (4G EPC → eNB), N3 (5G UPF → gNB), and N9 (5G UPF → UPF) interfaces — " +
		"it's the high-volume user-plane wrapping that surrounds the subscriber's IP " +
		"traffic as it crosses the mobile backhaul. Pure offline parser. Pairs with " +
		"`ip_packet_decode` for the inner subscriber IP packet. Decodes:\n\n" +
		"- **8-byte mandatory header** (TS 29.281 §5.1):\n" +
		"  - byte 0: **Flags** — Version (3 bits, GTP-U is version 1) + Protocol Type " +
		"(1 bit, 1 = GTP, 0 = GTP') + Spare + E (Extension Header) + S (Sequence " +
		"Number) + PN (N-PDU Number).\n" +
		"  - byte 1: **Message Type** with **6-entry name table**: 0x01 Echo Request, " +
		"0x02 Echo Response, 0x1A Error Indication, 0x1F Supported Extension Headers " +
		"Notification, 0xFE End Marker, 0xFF G-PDU (user-plane data — the 99.99% " +
		"case).\n" +
		"  - bytes 2-3: **Length** (uint16 BE) — payload length (after the 8-byte " +
		"mandatory header).\n" +
		"  - bytes 4-7: **TEID** (uint32 BE) — Tunnel Endpoint Identifier; the per-" +
		"bearer / per-PDU-session demultiplexer the receiver allocated.\n" +
		"- **Optional 4-byte block** (present iff E|S|PN flag is set):\n" +
		"  - Sequence Number (uint16 BE) + N-PDU Number (uint8) + Next Extension " +
		"Header Type (uint8).\n" +
		"- **Extension header chain** (when E flag set):\n" +
		"  - Per-extension layout: Length (in 4-byte units, including the length byte " +
		"and the trailing Next Type byte) + Body + Next Extension Header Type.\n" +
		"  - **Extension Header Type name table** (TS 29.281 §5.2.1, 9 entries):\n" +
		"    - 0x00 No more extension headers\n" +
		"    - 0x01 MBMS support indication\n" +
		"    - 0x02 MS Info Change Reporting\n" +
		"    - 0x40 Service Class Indicator\n" +
		"    - 0x81 RAN Container\n" +
		"    - 0x82 Long PDCP PDU Number\n" +
		"    - 0x83 Xw RAN Container\n" +
		"    - 0x84 NR RAN Container (5G NG-U)\n" +
		"    - 0x85 PDU Session Container (5G N3 / N9)\n" +
		"- **Inner subscriber IP packet** — for G-PDU (message type 0xFF), the payload " +
		"is the subscriber's IP packet and is **decoded in place** (first-nibble " +
		"version detection 4 → IPv4 / 6 → IPv6; the tunnelled flow's addresses / " +
		"protocol / ports surface directly). A payload that doesn't parse as IP is " +
		"reported with an error and left as hex.\n\n" +
		"Pure offline parser — operators paste UDP-payload bytes (standard outer UDP " +
		"dest port 2152) from a Wireshark Follow-UDP-Stream view, a `tcpdump -X udp " +
		"port 2152` line, an Open5GS / free5GC / Magma debug capture, an Ericsson / " +
		"Nokia / Huawei vendor packet trace, or any GTP-U-emitting tool and get the " +
		"documented header + extension chain + inner protocol identification.\n\n" +
		"Out of scope (deferred): GTP-C (control plane, TS 29.274 — Create Session " +
		"Request / Modify Bearer / etc.; future Spec); GTPv0 / GTPv1' (charging " +
		"variant — older / charging-specific protocols); PDU Session Container deep " +
		"dissection (5G N3 / N9 QFI + RQI bits — surfaced as raw hex); UDP / IP framing " +
		"(feed the UDP payload after the outer IP + UDP headers).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational cellular telco protocol — " +
		"S1-U / N3 / N9 user-plane wrapping). Wrap-vs-native: native — 3GPP TS 29.281 " +
		"is fully public; wire format is a tight 8-byte mandatory header with flag-" +
		"gated optional fields plus a typed extension header chain; no crypto, no " +
		"compression, no varints.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"GTP-U UDP-payload bytes as hex (the 8-byte mandatory header, followed by optional sequence/extension block, followed by extension chain if any, followed by inner payload). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   gtpUDecodeHandler,
}

func gtpUDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("gtp_u_decode: 'hex' is required")
	}
	res, err := gtp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("gtp_u_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
