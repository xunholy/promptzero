// stun.go — host-side STUN/TURN packet dissector Spec,
// delegating to the internal/stun package for the walker
// proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/stun"
)

func init() { //nolint:gochecknoinits
	Register(stunPacketDecodeSpec)
}

var stunPacketDecodeSpec = Spec{
	Name: "stun_packet_decode",
	Description: "Decode a STUN (Session Traversal Utilities for NAT) packet per RFC 5389 / " +
		"8489 + TURN extensions per RFC 5766 / 8656. STUN is the NAT-discovery and " +
		"candidate-exchange protocol behind WebRTC, every browser peer-to-peer connection, " +
		"video conferencing systems (Zoom / Teams / Meet / Webex), VoIP softphones, and " +
		"SIP User-Agent NAT traversal. TURN extends STUN with relay allocation for " +
		"symmetric-NAT cases. Decodes:\n\n" +
		"- **20-byte header**: Message Type with the bit-encoded 12-bit method + 2-bit " +
		"class per RFC 5389 §6 broken out into separate fields (Method: Binding / " +
		"Allocate / Refresh / Send / Data / CreatePermission / ChannelBind / Connect; " +
		"Class: Request / Indication / Success Response / Error Response), Length, Magic " +
		"Cookie 0x2112A442 validated (anything else is rejected as not-STUN), 12-byte " +
		"Transaction ID.\n" +
		"- **Attribute TLV walker** with 4-byte boundary padding handling.\n" +
		"- **~30-entry attribute name table** covering STUN (RFC 5389 §15) + TURN (RFC " +
		"5766 / 8656 §14) attributes: MAPPED-ADDRESS (0x0001), RESPONSE-ADDRESS, CHANGE-" +
		"REQUEST, SOURCE-ADDRESS, CHANGED-ADDRESS, USERNAME (0x0006), PASSWORD, " +
		"MESSAGE-INTEGRITY (HMAC-SHA1), ERROR-CODE (0x0009), UNKNOWN-ATTRIBUTES, " +
		"REFLECTED-FROM, CHANNEL-NUMBER (TURN), LIFETIME (TURN), XOR-PEER-ADDRESS (TURN), " +
		"DATA (TURN), REALM (0x0014), NONCE (0x0015), XOR-RELAYED-ADDRESS (TURN), " +
		"REQUESTED-ADDRESS-FAMILY (TURN), EVEN-PORT (TURN), REQUESTED-TRANSPORT (TURN), " +
		"DONT-FRAGMENT (TURN), MESSAGE-INTEGRITY-SHA256, PASSWORD-ALGORITHM, USERHASH, " +
		"XOR-MAPPED-ADDRESS (0x0020), RESERVATION-TOKEN (TURN), PRIORITY (ICE), " +
		"USE-CANDIDATE (ICE), PADDING, RESPONSE-PORT, CONNECTION-ID (TURN-TCP), SOFTWARE " +
		"(0x8022), ALTERNATE-SERVER (0x8023), CACHE-TIMEOUT, FINGERPRINT (CRC-32), " +
		"ICE-CONTROLLED, ICE-CONTROLLING, RESPONSE-ORIGIN, OTHER-ADDRESS, ECN-CHECK, " +
		"THIRD-PARTY-AUTHORIZATION, MOBILITY-TICKET.\n" +
		"- **XOR address un-masking**: XOR-MAPPED-ADDRESS / XOR-PEER-ADDRESS / " +
		"XOR-RELAYED-ADDRESS values are automatically un-XOR'd against the magic cookie " +
		"+ transaction ID per RFC 5389 §15.2 — the operator sees the real client IP + " +
		"port, not the obfuscated wire form. Both IPv4 (family=1) and IPv6 (family=2) " +
		"are supported.\n" +
		"- **ERROR-CODE decode**: class (3 bits, hundreds digit) + number (8 bits, " +
		"tens+units) + reason string, with documented-codes lookup (300 Try Alternate / " +
		"400 Bad Request / 401 Unauthenticated / 403 Forbidden / 420 Unknown Attribute / " +
		"437 Allocation Mismatch / 438 Stale Nonce / 440 Address Family not Supported / " +
		"441 Wrong Credentials / 442 Unsupported Transport / 486 Allocation Quota / 487 " +
		"Role Conflict / 500 Server Error / 508 Insufficient Capacity).\n\n" +
		"Pure offline parser — operators paste a hex blob from Wireshark / tshark / " +
		"tcpdump-of-3478 / a TURN-server log / a WebRTC ICE-trickle capture and inspect " +
		"every documented field without re-sending the request. Pairs with " +
		"ip_packet_decode + sip_message_decode (when shipped) for the complete VoIP / " +
		"WebRTC decode stack: IP/UDP for transport, STUN for NAT discovery, SIP for call " +
		"signaling.\n\n" +
		"Out of scope (deferred to future iterations): MESSAGE-INTEGRITY / FINGERPRINT " +
		"validation (HMAC-SHA1 requires the shared auth key; CRC-32 deferred); TURN " +
		"ChannelData messages (non-STUN framed [channel#][length] surfaced as raw hex if " +
		"the leading byte ≥ 0x40 is detected); long-lived TURN session bookkeeping.\n\n" +
		"Source: docs/catalog/gap-analysis.md (NAT traversal / WebRTC decode space). " +
		"Wrap-vs-native: native — RFC 5389 + 8489 + 5766 + 8656 are fully public, wire " +
		"format is fixed-format header + TLV walker with the magic-cookie + XOR trick.\n\n" +
		"Accepts ':' / '-' / '_' / whitespace separators and a leading '0x' prefix.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded STUN/TURN packet: 20-byte header (Message Type + Length + Magic Cookie 0x2112A442 + 12-byte Transaction ID) + attribute TLV list. Minimum 20 bytes. ':' / '-' / '_' / whitespace separators tolerated; '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   stunPacketDecodeHandler,
}

func stunPacketDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("stun_packet_decode: 'hex' is required")
	}
	res, err := stun.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("stun_packet_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
