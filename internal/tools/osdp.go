// osdp.go — host-side OSDP (access-control reader bus) packet
// decoder Spec, delegating to the internal/osdp package.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/osdp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(osdpPacketDecodeSpec)
}

var osdpPacketDecodeSpec = Spec{
	Name: "osdp_packet_decode",
	Description: "Decode an OSDP (Open Supervised Device Protocol) packet — the SIA / IEC " +
		"60839-11-5 serial protocol that modern physical-access-control readers speak to their " +
		"controllers, the secure successor to Wiegand. An OSDP bus tap / RS-485 capture is a " +
		"stream of these packets; dissecting them shows the poll/reply traffic, the card-read " +
		"replies, the secure-channel handshake and any integrity failures — a staple of an " +
		"access-control pentest. Decodes:\n\n" +
		"- **Frame**: optional 0xFF driver mark + 0x53 start-of-message + address byte (bit 7 = " +
		"reply direction, low 7 bits = PD address, 0x7F = broadcast) + 16-bit length + control " +
		"byte.\n" +
		"- **Control byte**: 2-bit sequence number, CRC-vs-checksum trailer mode, and the " +
		"secure-channel-block (SCB) presence flag.\n" +
		"- **Security control block** (when present): length + type + meaning — the secure-" +
		"channel handshake markers SCS_11..SCS_18.\n" +
		"- **Command (CP→PD)** or **reply (PD→CP)** code with its name (osdp_POLL / osdp_ID / " +
		"osdp_LED / osdp_RAW card-read / osdp_ACK / osdp_NAK / osdp_CCRYPT / …).\n" +
		"- **NAK** replies: the error code with its meaning (bad checksum/CRC, command length, " +
		"unknown command, sequence error, secure-channel not supported, …).\n" +
		"- **Trailer integrity**: the CRC-16/AUG-CCITT (poly 0x1021, init 0x1D0F) or the 1-byte " +
		"two's-complement checksum is recomputed and reported valid / invalid.\n\n" +
		"Input is one packet as hex (a leading 0xFF mark is tolerated; ':' / '-' / '_' / " +
		"whitespace separators and a '0x' prefix are accepted). Verified byte-for-byte against " +
		"the libosdp phy-layer reference test vectors.\n\n" +
		"Out of scope (deferred): per-command/-reply payload field decode (the osdp_RAW " +
		"reader/format/bit-count/card-data layout, osdp_PDID device-ID fields, osdp_LED/BUZ " +
		"parameters) — the data is surfaced as hex and the code name identifies it, since the " +
		"reference ships no byte-exact payload vectors to verify a field decode against; and " +
		"secure-channel-encrypted payloads (SCS_17/18), which need the session keys.\n\n" +
		"Source: docs/catalog/gap-analysis.md (physical access-control decode space). " +
		"Wrap-vs-native: native — the OSDP packet is a fixed little-endian frame decoded by pure " +
		"byte-field extraction plus one standard CRC; the libosdp reference is reimplemented, not " +
		"wrapped. Pairs with wiegand_decode / rfid_pacs_decode for the card-data side.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"One OSDP packet as hex. Optional leading 0xFF driver mark. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   osdpPacketDecodeHandler,
}

func osdpPacketDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("osdp_packet_decode: 'hex' is required")
	}
	res, err := osdp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("osdp_packet_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
