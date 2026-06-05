// meshtastic.go — host-side Meshtastic LoRa-mesh packet-header decoder
// Spec, delegating to the internal/meshtastic package.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/meshtastic"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(meshtasticDecodeSpec)
}

var meshtasticDecodeSpec = Spec{
	Name: "meshtastic_decode",
	Description: "Decode a Meshtastic LoRa-mesh packet header — the 16-byte plaintext header that " +
		"prefixes every Meshtastic packet on the 868 / 915 MHz LoRa channel, before the " +
		"AES-encrypted payload. Meshtastic is the dominant off-grid LoRa mesh-comms project, and " +
		"the header is sent in the clear: decoding it from a Flipper Sub-GHz / SDR LoRa capture " +
		"**enumerates the nodes in mesh range** (source + destination node IDs), reveals the " +
		"**channel hash** (which channel a packet belongs to), and exposes the hop / want-ack / " +
		"via-MQTT routing flags — passive mesh reconnaissance without touching the air. The wire " +
		"layout is the firmware's PacketHeader (RadioInterface.h). Decodes:\n\n" +
		"- **Destination + source node IDs** in the `!xxxxxxxx` form Meshtastic displays " +
		"(0xFFFFFFFF = the `^all` broadcast address).\n" +
		"- The **packet ID**.\n" +
		"- The **flags** byte: hop limit (bits 0-2), want-ack (bit 3), via-MQTT (bit 4) and hop " +
		"start (bits 5-7) — yielding hops-taken = start − limit (mesh-depth tracking).\n" +
		"- The **channel hash** (the per-channel hint byte — same channel name+PSK → same hash, " +
		"so it fingerprints the channel) and the **next-hop / relay-node** ID bytes.\n" +
		"- The encrypted payload, surfaced as hex with its length.\n\n" +
		"Paste the LoRa packet bytes (header + payload) as hex; ':' / '-' / '_' / whitespace " +
		"separators and a '0x' prefix tolerated. Verified against the Meshtastic firmware wire " +
		"layout + flag masks.\n\n" +
		"Out of scope (deferred): the payload is the AES-256-CTR (or PKI, for direct messages) " +
		"encrypted protobuf MeshPacket — decrypting it needs the channel pre-shared key or the " +
		"node key pair, which is not on the wire, so it is surfaced as ciphertext; and the LoRa " +
		"physical layer (CRC / coding rate / preamble), which is upstream.\n\n" +
		"Source: docs/catalog/gap-analysis.md (LoRa mesh decode space). Wrap-vs-native: native — " +
		"the header is a fixed firmware-defined wire structure decoded by byte-field extraction " +
		"and bit-masking; reimplemented from the firmware, not wrapped. Pairs with lorawan_decode " +
		"(the other LoRa-layer protocol) and the subghz_* decoders.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Meshtastic LoRa packet as hex: the 16-byte header followed by the (encrypted) payload. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   meshtasticDecodeHandler,
}

func meshtasticDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("meshtastic_decode: 'hex' is required")
	}
	res, err := meshtastic.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("meshtastic_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
