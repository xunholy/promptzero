// droneid.go — host-side ASTM F3411-22 (drone Remote ID)
// payload dissector Spec, delegating to the internal/droneid
// package for the walker proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/droneid"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(droneRemoteIDDecodeSpec)
}

var droneRemoteIDDecodeSpec = Spec{
	Name: "drone_remote_id_decode",
	Description: "Decode an ASTM F3411-22 drone Remote ID payload — the FAA-mandated (14 CFR " +
		"Part 89) and EU-mandated broadcast beacon that every drone flying since 2023 must " +
		"transmit over BLE 4 Legacy / BLE 5 Long Range / WiFi NAN / WiFi Beacon. Decodes:\n\n" +
		"- **Message envelope**: 1-byte header = (MessageType << 4) | ProtocolVersion. Six " +
		"message types plus the Message Pack container.\n" +
		"- **Type 0x0 Basic ID**: UAS ID (20 chars ASCII), ID Type (Serial Number per " +
		"ANSI/CTA-2063-A / CAA registration / UTM UUID / Session ID), UA Type (16-entry " +
		"table — Aeroplane / Helicopter-Multirotor / Glider / UAV / Rocket / Tethered / etc.).\n" +
		"- **Type 0x1 Location/Vector**: operational status (Undeclared / Ground / Airborne / " +
		"Emergency / Remote ID Failure), height reference (AGL vs Geodetic), lat / lon " +
		"(10^-7 deg signed i32), pressure + geodetic + AGL altitude (0.5 m, -1000 m offset), " +
		"ground track / speed with multiplier-encoded high-speed range, vertical speed " +
		"(signed 0.5 m/s), per-field accuracy nibbles, and 1/10-second timestamp within the " +
		"current hour.\n" +
		"- **Type 0x3 Self-ID**: 23-character free-text flight description + Description Type " +
		"code (Free text / Emergency / Extended Status / Private).\n" +
		"- **Type 0x4 System**: operator-side lat / lon, operator altitude, classification " +
		"region (EU / undeclared), EU class table (C0..C5), swarm-flight area count / " +
		"radius / ceiling / floor, and a System Timestamp expressed as Unix-epoch seconds " +
		"(automatically offset from the spec's 2019-01-01 00:00:00 UTC base).\n" +
		"- **Type 0x5 Operator ID**: 20-character regulatory operator identifier + Operator ID " +
		"Type.\n" +
		"- **Type 0xF Message Pack**: header + message size + message count (1-9) + N × " +
		"25-byte child messages, dispatched individually so a single decode call returns the " +
		"full bundle.\n\n" +
		"Pure offline parser — operators paste the 25-byte payload extracted from a BLE / WiFi " +
		"sniffer capture (the wrapper IDs 0xFA 0xFF 'DRI' / ASTM OUI 0x6A:0x5C:0x35 are out " +
		"of scope; expect callers to feed only the Remote ID payload itself). Pairs with the " +
		"existing ble_* and ieee80211_* coverage — those handle the transport framing, this " +
		"Spec handles the Remote ID payload.\n\n" +
		"Authentication (type 0x2) is recognised but not body-decoded — the variable-length " +
		"signature pages (up to 17 × 23 bytes = 393 bytes) are rare in practice and will land " +
		"as a separate Spec when real-world captures surface.\n\n" +
		"Accepts ':' / '-' / '_' / whitespace separators and a leading '0x' prefix.\n\n" +
		"Source: docs/catalog/gap-analysis.md (aerospace / drone OSINT decode space). " +
		"Wrap-vs-native: native — ASTM F3411-22 is fully public, every message is a fixed " +
		"25-byte frame with simple bit-field dispatch, no cryptography, no handshake.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded ASTM F3411-22 Remote ID payload. Single messages are exactly 25 bytes; Message Pack (type 0xF) is 3 + N×25 bytes (1 ≤ N ≤ 9). ':' / '-' / '_' / whitespace separators tolerated; '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   droneRemoteIDDecodeHandler,
}

func droneRemoteIDDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("drone_remote_id_decode: 'hex' is required")
	}
	res, err := droneid.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("drone_remote_id_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
