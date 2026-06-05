// SPDX-License-Identifier: AGPL-3.0-or-later

// Package meshtastic decodes the Meshtastic LoRa-mesh radio packet
// header — the 16-byte plaintext header that prefixes every Meshtastic
// packet on the 868/915 MHz LoRa channel, before the AES-encrypted
// payload. Meshtastic is the dominant off-grid LoRa mesh-comms project,
// and the header is sent in the clear: decoding it from a Flipper
// Sub-GHz / SDR LoRa capture enumerates the nodes in mesh range (source
// and destination node IDs), reveals the channel hash (which channel a
// packet belongs to), and exposes the hop / want-ack / via-MQTT routing
// flags — passive mesh reconnaissance without touching the air.
//
// # Wrap-vs-native judgement
//
//	Native. The header is a fixed wire structure defined by the
//	Meshtastic firmware (RadioInterface.h PacketHeader, "has to exactly
//	match the wire layout when sent over the radio link"): little-endian
//	uint32 destination, uint32 source, uint32 packet ID, then a flags
//	byte, the channel-hash byte, and the next-hop / relay-node bytes.
//	Pure byte-field extraction and bit-masking — reimplemented from the
//	firmware, no new dependency, no shell-out.
//
// # What this covers
//
//   - Destination and source node IDs (the !xxxxxxxx form Meshtastic
//     displays; 0xFFFFFFFF is the broadcast address).
//   - The packet ID.
//   - The flags byte: hop limit (bits 0-2), want-ack (bit 3), via-MQTT
//     (bit 4) and hop start (bits 5-7) — so hops-taken = start − limit.
//   - The channel hash (the per-channel hint byte) and the next-hop /
//     relay-node ID bytes.
//   - The encrypted payload, surfaced as hex with its length.
//
// # Deliberately deferred
//
//	The payload is the AES-256-CTR-encrypted (or, for DMs, PKI-encrypted)
//	protobuf MeshPacket; decrypting it needs the channel pre-shared key
//	(or the node key pair), which is not on the wire, so it is surfaced
//	as ciphertext. The LoRa physical layer (CRC, coding rate, preamble)
//	is upstream — feed the decoded payload bytes.
package meshtastic

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

const headerLen = 16 // MESHTASTIC_HEADER_LENGTH

// Result is the decoded Meshtastic packet header.
type Result struct {
	To            string   `json:"to"`
	ToHex         string   `json:"to_hex"`
	Broadcast     bool     `json:"broadcast"`
	From          string   `json:"from"`
	FromHex       string   `json:"from_hex"`
	PacketID      uint32   `json:"packet_id"`
	HopLimit      int      `json:"hop_limit"`
	HopStart      int      `json:"hop_start"`
	HopsTaken     *int     `json:"hops_taken,omitempty"`
	WantAck       bool     `json:"want_ack"`
	ViaMQTT       bool     `json:"via_mqtt"`
	ChannelHash   string   `json:"channel_hash"`
	NextHop       string   `json:"next_hop"`
	RelayNode     string   `json:"relay_node"`
	PayloadLength int      `json:"payload_length"`
	PayloadHex    string   `json:"payload_hex,omitempty"`
	Notes         []string `json:"notes,omitempty"`
}

// Decode parses a Meshtastic LoRa packet (16-byte header + encrypted
// payload) from hex. ':' / '-' / '_' / whitespace separators and a '0x'
// prefix are tolerated.
func Decode(hexStr string) (*Result, error) {
	b, err := hex.DecodeString(stripSep(hexStr))
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) < headerLen {
		return nil, fmt.Errorf("packet too short (%d bytes; the Meshtastic header is %d)", len(b), headerLen)
	}

	to := binary.LittleEndian.Uint32(b[0:4])
	from := binary.LittleEndian.Uint32(b[4:8])
	flags := b[12]
	r := &Result{
		To:          nodeID(to),
		ToHex:       fmt.Sprintf("0x%08X", to),
		Broadcast:   to == 0xFFFFFFFF,
		From:        nodeID(from),
		FromHex:     fmt.Sprintf("0x%08X", from),
		PacketID:    binary.LittleEndian.Uint32(b[8:12]),
		HopLimit:    int(flags & 0x07),
		WantAck:     flags&0x08 != 0,
		ViaMQTT:     flags&0x10 != 0,
		HopStart:    int(flags>>5) & 0x07,
		ChannelHash: fmt.Sprintf("0x%02X", b[13]),
		NextHop:     fmt.Sprintf("0x%02X", b[14]),
		RelayNode:   fmt.Sprintf("0x%02X", b[15]),
	}
	// hops-taken is meaningful only when hop_start is set (newer firmware).
	if r.HopStart > 0 && r.HopStart >= r.HopLimit {
		ht := r.HopStart - r.HopLimit
		r.HopsTaken = &ht
	}
	payload := b[headerLen:]
	r.PayloadLength = len(payload)
	if len(payload) > 0 {
		r.PayloadHex = strings.ToUpper(hex.EncodeToString(payload))
		r.Notes = append(r.Notes,
			"payload is the AES-256-CTR (or PKI for DMs) encrypted MeshPacket protobuf — decrypting it needs the channel pre-shared key / node key, not on the wire")
	}
	return r, nil
}

// nodeID formats a 32-bit node number the way Meshtastic displays it:
// "!" + 8 lowercase hex digits, or "^all" for the broadcast address.
func nodeID(n uint32) string {
	if n == 0xFFFFFFFF {
		return "^all (broadcast)"
	}
	return fmt.Sprintf("!%08x", n)
}

func stripSep(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r', ',':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
