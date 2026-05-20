// l2tp.go — host-side L2TPv3 packet decoder Spec.
// Wraps the internal/l2tp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/l2tp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(l2tpV3DecodeSpec)
}

var l2tpV3DecodeSpec = Spec{
	Name: "l2tp_v3_decode",
	Description: "Decode an L2TPv3 packet per RFC 3931 (UDP-encapsulated mode, port " +
		"1701). L2TPv3 is the pseudowire encapsulation that pairs with PPPoE " +
		"(covered by `pppoe_decode`) to complete the broadband subscriber-" +
		"management story: PPPoE handles the access-side session from the customer " +
		"modem to the BNG; L2TPv3 handles the backhaul/aggregation tunnel from the " +
		"BNG (LAC) to a Layer-2 VPN concentrator (LNS) in classic deployments. " +
		"L2TPv3 is also the dominant transport for lawful intercept (LI) at every " +
		"ISP (voice + data captures are funnelled through L2TPv3 tunnels from edge " +
		"LACs to a centralised LI mediation function), L2 VPN services (Ethernet / " +
		"ATM / Frame Relay / PPP / HDLC pseudowires across MPLS or IP cores), and " +
		"subscriber backhaul (wholesale broadband resellers tunnel customers from " +
		"CLEC LACs to their LNS for centralised AAA + IP allocation). Decodes:\n\n" +
		"- **16-bit common header** (RFC 3931 §3.2.1): bit 0 = **T** (0 Data / 1 " +
		"Control); bit 1 = L (Length present); bit 4 = S (Ns/Nr present); bits " +
		"12-15 = **Version** (must be 3 for L2TPv3).\n" +
		"- **Control Message** (T=1; RFC 3931 §3.2.2): Length (uint16 BE) + " +
		"Control Connection ID (uint32 BE; peer-end's connection identifier) + Ns " +
		"(send sequence) + Nr (expected receive sequence) + AVP list.\n" +
		"- **AVP walker** (RFC 3931 §5.2): each AVP = 2-byte (M/H/Reserved/Length " +
		"bit-pack) + 2-byte Vendor ID (0 = IETF) + 2-byte Attribute Type + " +
		"(Length-6) byte Value. **~20-entry IETF AVP name table** (when Vendor ID " +
		"= 0): Message Type / Result Code / Protocol Version / Framing " +
		"Capabilities / Bearer Capabilities / Tie Breaker / Firmware Revision / " +
		"Host Name / Vendor Name / Assigned Tunnel ID / Receive Window Size / " +
		"Challenge / Challenge Response / Cause Code / Q.931 Cause Code / Local " +
		"Session ID / Remote Session ID / Assigned Cookie / Random Vector / Proxy " +
		"Authen Type/Name/Challenge/ID/Response + Initial/Last LCP CONFREQs.\n" +
		"- **Message Type AVP** (Attribute 0) — first AVP in every Control " +
		"Message; its 2-byte value names the control message kind via a **15-" +
		"entry name table** (RFC 3931 §5.4): SCCRQ (Start-Control-Connection-" +
		"Request) / SCCRP / SCCCN / StopCCN / HELLO (Keepalive) / OCRQ (Outgoing-" +
		"Call-Request) / OCRP / OCCN / ICRQ (Incoming-Call-Request) / ICRP / " +
		"ICCN / CDN (Call-Disconnect-Notify) / WEN (WAN-Error-Notify) / SLI / ACK.\n" +
		"- **Data Message** (T=0): Session ID (uint32 BE; peer-end's session " +
		"identifier) + L2-Specific Sublayer (varies by encap; default empty) + L2 " +
		"Frame (opaque; surfaced as hex preview).\n" +
		"- **AVP flags decoded** — M (Mandatory; receiver must understand) + H " +
		"(Hidden; AVP value is encrypted per RFC 3931 §4.3). Hidden AVPs surface " +
		"the ciphertext as hex without UTF-8 surfacing.\n\n" +
		"Pure offline parser — operators paste L2TPv3 bytes (UDP destination port " +
		"1701) from a `tcpdump -X udp port 1701` line or a Wireshark Follow-UDP-" +
		"Stream view and get the documented header + per-message-type body " +
		"breakdown.\n\n" +
		"Out of scope (deferred): UDP framing (feed L2TPv3 bytes after the UDP " +
		"header strip — UDP-mode L2TPv3 runs on destination port 1701; IP-mode " +
		"runs as IP protocol 115); IP-mode L2TPv3 (different envelope, no UDP " +
		"header, Session ID 0 indicates a Control Message; could share most " +
		"decoder logic, deferred); per-AVP value type-aware decoding beyond " +
		"Message Type and a few well-known integer/string AVPs (values surfaced " +
		"as hex with plausibly-text UTF-8 surfacing for Host Name / Vendor Name); " +
		"Hidden (encrypted) AVPs (H bit surfaced but decryption requires the " +
		"shared secret + RFC 3931 §4.3 procedure; deferred); PPP / HDLC / " +
		"Ethernet / ATM / FR frame dissection inside Data Message payload " +
		"(operator pulls bytes out of the payload preview and feeds into the " +
		"appropriate L2 decoder).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational pseudowire " +
		"encapsulation; pairs with pppoe_decode for the complete broadband BNG " +
		"+ L2 VPN story; dominant LI / backhaul transport at every ISP). " +
		"Wrap-vs-native: native — RFC 3931 is fully public; L2TPv3 has a tight " +
		"bit-packed common header that dispatches between Control and Data " +
		"messages; Control Messages carry an AVP list with well-defined " +
		"Attribute Types; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"L2TPv3 packet bytes (after UDP header strip; UDP destination port 1701). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."},
			"max_payload_bytes":{"type":"integer","description":"Cap the Data Message payload hex preview (default 256). Zero surfaces the full payload."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   l2tpV3DecodeHandler,
}

func l2tpV3DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("l2tp_v3_decode: 'hex' is required")
	}
	opts := l2tp.DefaultDecodeOpts()
	if v, ok := p["max_payload_bytes"]; ok {
		if n, ok := intArg(v); ok {
			opts.MaxPayloadBytes = n
		}
	}
	res, err := l2tp.Decode(raw, opts)
	if err != nil {
		return "", fmt.Errorf("l2tp_v3_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
