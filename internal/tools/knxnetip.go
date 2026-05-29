// knxnetip.go — host-side KNXnet/IP frame dissector Spec,
// delegating to the internal/knxnetip package for the walker proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/knxnetip"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(knxnetIPDecodeSpec)
}

var knxnetIPDecodeSpec = Spec{
	Name: "knxnetip_decode",
	Description: "Decode a KNXnet/IP frame (KNX over IP, UDP/3671, multicast " +
		"224.0.23.12 for routing) — the IP-transport dialect of KNX, the dominant " +
		"European building-automation bus controlling lighting, HVAC, blinds/shutters, " +
		"access control, room controllers, and energy metering. Per the public KNX " +
		"Standard (chapters 3/8/x and the cEMI 3/6/3). This is exactly the traffic a " +
		"pentester captures on a building's BMS / management VLAN. Decodes:\n\n" +
		"- **KNXnet/IP header** (6 bytes): header length (0x06), protocol version " +
		"(0x10 = v1.0), 16-bit service-type identifier with a full catalog across the " +
		"Core / Device-Management / Tunnelling / Routing / KNXnet-IP-Secure families " +
		"(SEARCH_REQUEST, DESCRIPTION_REQUEST, CONNECT_REQUEST/RESPONSE, " +
		"CONNECTIONSTATE_REQUEST, DISCONNECT_REQUEST, DEVICE_CONFIGURATION_REQUEST/ACK, " +
		"TUNNELLING_REQUEST/ACK, ROUTING_INDICATION/LOST_MESSAGE/BUSY, SECURE_WRAPPER, " +
		"SESSION_REQUEST/RESPONSE/AUTHENTICATE/STATUS, TIMER_NOTIFY), and total-length " +
		"validation against the actual buffer.\n" +
		"- **HPAI** (Host Protocol Address Information) blocks for the discovery / " +
		"connection services: host protocol code (IPv4 UDP / IPv4 TCP), IPv4 endpoint, " +
		"and port — the control + data endpoints a gateway is told to call back.\n" +
		"- **Connection header** (4 bytes) for the connection-oriented services: " +
		"communication channel ID, sequence counter, and status — the exact fields an " +
		"attacker forges to hijack, replay, or reset an established tunnel.\n" +
		"- **cEMI telegram** (the actual KNX bus command) for TUNNELLING_REQUEST and " +
		"ROUTING_INDICATION: message code (L_Data.req / .ind / .con plus the M_Prop* " +
		"management codes), additional-info skip, control fields, KNX source individual " +
		"address (area.line.device), destination group or individual address (3-level " +
		"main/middle/sub notation for groups), NPDU length, and the TPCI/APCI " +
		"application command — most importantly A_GroupValue_Read / _Response / _Write " +
		"plus the (possibly 6-bit-packed) payload. A decoded \"GroupValue_Write 1/1/3 = " +
		"01\" reads as \"switch lighting group 1/1/3 on\".\n\n" +
		"Pure offline parser — operators paste a hex frame from Wireshark / a captured " +
		"UDP/3671 dump and inspect every layer without re-attaching to the KNX bus. " +
		"Companion to bacnet_ip_decode and modbus_decode for full OT / " +
		"building-automation decode coverage.\n\n" +
		"Out of scope (deferred): KNXnet/IP Secure encrypted payloads (the " +
		"SECURE_WRAPPER / session services are named and flagged but the AES-CCM body " +
		"is not decrypted), cEMI additional-info field interpretation (skipped by " +
		"length), and Datapoint-Type (DPT) engineering-value mapping of the GroupValue " +
		"payload (raw bytes surfaced).\n\n" +
		"Source: docs/catalog/gap-analysis.md (OT / building-automation decode space — " +
		"KNX is the dominant European BMS bus, companion to BACnet for the full " +
		"OT-pentest workflow). Wrap-vs-native: native — the KNX Standard is public and " +
		"every envelope field is a fixed-format byte stream.\n\n" +
		"Accepts ':' / '-' / '_' / whitespace separators and a leading '0x' prefix.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded KNXnet/IP frame: 6-byte header (06 10 + 16-bit service type + 16-bit total length) followed by the service-specific body (HPAI blocks / connection header + cEMI telegram). ':' / '-' / '_' / whitespace separators tolerated; '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   knxnetIPDecodeHandler,
}

func knxnetIPDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("knxnetip_decode: 'hex' is required")
	}
	res, err := knxnetip.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("knxnetip_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
