// hsrp.go — host-side HSRP packet decoder Spec.
// Wraps the internal/hsrp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/hsrp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(hsrpDecodeSpec)
}

var hsrpDecodeSpec = Spec{
	Name: "hsrp_decode",
	Description: "Decode a Hot Standby Router Protocol (HSRP) packet per RFC 2281 " +
		"(HSRPv1) and the Cisco HSRPv2 TLV extensions. HSRP is Cisco's proprietary " +
		"first-hop gateway redundancy protocol — the sibling of VRRP (RFC 5798) " +
		"that predates the IETF standard and is still extremely common in Cisco-" +
		"heavy enterprise + datacenter cores. Pairs with `vrrp_decode` for the " +
		"complete gateway-redundancy decode coverage. Decodes:\n\n" +
		"- **Version auto-detection** — byte 0 = 0 implies HSRPv1 (1-byte version, " +
		"19 more bytes); bytes 0-1 forming a plausible (Type, Length) TLV pair " +
		"(Type ∈ {1, 2, 3}, Length ∈ {40, 9, 28}) implies HSRPv2.\n" +
		"- **HSRPv1 fixed 20-byte packet** (RFC 2281 §5):\n" +
		"  - byte 0: Version (0 for v1).\n" +
		"  - byte 1: **Op Code** with **3-entry name table**: 0 Hello, 1 Coup, 2 " +
		"Resign.\n" +
		"  - byte 2: **State** with **6-entry name table**: 0 Initial, 1 Learn, 2 " +
		"Listen, 4 Speak, 8 Standby, 16 Active (sparse 0/1/2/4/8/16 ladder so that " +
		"bit-OR comparisons can express transitions).\n" +
		"  - byte 3: Hellotime (uint8 seconds; default 3).\n" +
		"  - byte 4: Holdtime (uint8 seconds; default 10).\n" +
		"  - byte 5: **Priority** — 0-255 with semantic notes: 0 = withdraw " +
		"(router signalling shutdown), 100 = default Cisco priority, 255 = maximum " +
		"(always wins election).\n" +
		"  - byte 6: Group (uint8 — the HSRP group number on the LAN; 0-255).\n" +
		"  - byte 7: Reserved (0).\n" +
		"  - bytes 8-15: **Authentication Data** — 8 bytes of ASCII; default " +
		"'cisco\\0\\0\\0' (deprecated cleartext auth per RFC 2281 §3.5, kept here " +
		"for plaintext extraction).\n" +
		"  - bytes 16-19: **Virtual IPv4 Address** (the virtual default gateway IP " +
		"that end hosts use).\n" +
		"- **HSRPv2 TLV envelope** — repeated (Type uint8, Length uint8, Value) " +
		"records. **3-entry TLV type table**: 1 Group State (40-byte body with " +
		"Version + Op Code + State + IP Version + uint16 Group + 6-byte MAC " +
		"identifier + uint32 Priority + uint32 Hello Time ms + uint32 Hold Time ms " +
		"+ 16-byte Virtual IP slot supporting both IPv4 padded and IPv6 full); 2 " +
		"Text Authentication (9-byte body: Auth Type + 8-byte ASCII password); 3 " +
		"MD5 Authentication (28-byte body: Algorithm + Padding + Flags + IP + Key " +
		"ID + 16-byte digest).\n\n" +
		"Pure offline parser — operators paste HSRP bytes (UDP port 1985 to " +
		"224.0.0.2 for v1, 224.0.0.102 / FF02::66 for v2, port 1985 / 2029) from " +
		"a `tcpdump -X port 1985` line or a Wireshark Follow-UDP-Stream view and " +
		"get the documented packet breakdown.\n\n" +
		"Out of scope (deferred): UDP framing (feed bytes after the UDP header " +
		"strip — HSRP runs over UDP port 1985 for v1 + v2 IPv4 or 2029 for v2 " +
		"IPv6); HSRP Authentication verification (text passwords are surfaced as " +
		"ASCII; MD5 digests as hex — verifying the digest requires the receiver " +
		"to know the shared key + reconstruct the exact byte sequence the sender " +
		"hashed per RFC 2281 §3.5); HSRP Master/Backup election simulation " +
		"(Priority, Hellotime, Holdtime are surfaced; the multi-router state " +
		"machine reasoning is higher-level).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational gateway-redundancy " +
		"protocol — Cisco-proprietary sibling to vrrp_decode; still extremely " +
		"common in enterprise + datacenter cores where Cisco gear dominates). " +
		"Wrap-vs-native: native — RFC 2281 is fully public; v1 is a tight 20-byte " +
		"fixed structure; HSRPv2 uses an explicit TLV envelope with well-defined " +
		"body sizes for each TLV type; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"HSRP packet bytes (after UDP header strip; UDP destination port 1985 for v1 + v2 IPv4 or 2029 for v2 IPv6). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   hsrpDecodeHandler,
}

func hsrpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("hsrp_decode: 'hex' is required")
	}
	res, err := hsrp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("hsrp_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
