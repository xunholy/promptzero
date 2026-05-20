// hartip.go — host-side HART-IP (HART over IP) decoder Spec.
// Wraps the internal/hartip walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/hartip"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(hartIPDecodeSpec)
}

var hartIPDecodeSpec = Spec{
	Name: "hart_ip_decode",
	Description: "Decode a HART-IP (Highway Addressable Remote Transducer over IP) " +
		"message per the HART Foundation specification (HCF_SPEC-085). HART-IP " +
		"encapsulates HART field-instrument messages over IP (UDP or TCP port " +
		"5094 by default), extending the 30-year-old HART industrial-" +
		"instrumentation protocol that originally ran on top of the 4-20 mA " +
		"current loop into modern Ethernet-connected control systems. " +
		"Operationally the wire format on the boundary between modern DCS / " +
		"SCADA layers (Emerson DeltaV, Honeywell Experion, ABB Ability, " +
		"Yokogawa CENTUM, Schneider Foxboro Evo) and HART-capable field " +
		"instruments (pressure transmitters, flow meters, temperature sensors, " +
		"control valves with smart positioners — Rosemount, Endress+Hauser, " +
		"Yokogawa EJX, ABB, Honeywell SmartLine). Interesting to an ICS " +
		"pentester because (i) calibration tampering — a HART command sent over " +
		"HART-IP can re-trim a transmitter's range, shift its zero point, or " +
		"change its damping constant — a subtle process attack that bypasses " +
		"control-system bound checks; (ii) device enumeration — HART command 0 " +
		"(Read Unique Identifier) leaks manufacturer + device type + tag + " +
		"serial number; (iii) configuration disclosure — HART commands 13 + 18 " +
		"reveal Tag + Date + Descriptor + Message fields; (iv) process pentest " +
		"CTFs at DEF CON ICS Village + S4 Symposium + ICSjwt. Decodes:\n\n" +
		"- **HART-IP envelope header** (HCF_SPEC-085, 8 bytes, big-endian): " +
		"Version (= 0x01 current) + Message Type (1-byte request/response/" +
		"publish discriminator) + Message ID (1-byte session-control/payload-" +
		"kind discriminator) + Status Code (1 byte; 0 = success in responses) " +
		"+ Sequence Number (uint16 BE; per-session monotonic counter pairing " +
		"requests + responses) + Byte Count (uint16 BE; HART payload bytes " +
		"following).\n" +
		"- **4-entry Message Type name table** (§6.2.1): 0 Request (host → " +
		"field device) / 1 Response (field device → host) / 2 Publish (field " +
		"device unsolicited burst notification) / 3 NAK (negative " +
		"acknowledgement — request malformed or rejected before reaching the " +
		"HART layer).\n" +
		"- **6-entry Message ID name table** (§6.2.2): 0 Session_Initiate " +
		"(open a HART-IP session) / 1 Session_Close / 2 Keep_Alive (idle-" +
		"timer reset) / 3 HART_PDU (carries a HART command in payload — the " +
		"overwhelmingly common case) / 4 Direct_PDU (direct HART-message " +
		"passthrough) / 128 Publish_Burst_Notify (Publish-direction " +
		"equivalent of HART_PDU).\n" +
		"- **HART payload surfacing** — bytes after the 8-byte envelope " +
		"header are the encapsulated HART command frame; surfaced as " +
		"hart_payload_hex for downstream HART-command-level decoders (per-" +
		"Command-Code decoders for Cmd 0 Read Unique Identifier, Cmd 13/18 " +
		"Read Tag/Descriptor, Cmd 42 Device Reset, Cmd 48 Read Additional " +
		"Device Status, etc.).\n\n" +
		"Pure offline parser — operators paste HART-IP bytes (starting at the " +
		"Version byte 0x01) from a `tcpdump -X port 5094` line or a Wireshark " +
		"HART-IP dissector view and get the documented envelope + Message " +
		"Type/ID breakdown plus the opaque HART payload for downstream " +
		"command-level decoders.\n\n" +
		"Out of scope (deferred): network framing (feed bytes after the UDP-" +
		"datagram or TCP-segment header strip; default UDP/TCP port 5094); " +
		"inner HART command decoders (the HART layer-7 wire format — Frame " +
		"Type + Delimiter + Address (short or long form) + Command Code + " +
		"Byte Count + Response Code + Device Status + Data + Checksum — is a " +
		"separate decoder; surfaced as hart_payload_hex; per-command data " +
		"shapes for the 255 catalogued Command Codes are dataset-specific " +
		"and out of scope for the envelope decoder); WirelessHART IEC 62591 " +
		"(the wireless mesh variant uses a different per-frame format on the " +
		"air interface; gateway-side WirelessHART-over-HART-IP is in scope " +
		"but the wireless-side IEEE 802.15.4 mesh is not); HART-IP Session " +
		"State-Machine (connection setup, keep-alive timer default 5 s, " +
		"session resumption, re-keying are higher-level concerns); per-" +
		"Message-Type Status Code semantics (Status surfaced as a number; " +
		"different meaning in NAK vs Response is out of scope).\n\n" +
		"Source: docs/catalog/gap-analysis.md (process-automation dissector " +
		"— pairs with the existing industrial protocol family modbus_decode " +
		"+ dnp3_decode + iec104_decode + s7comm_decode + enip_decode + " +
		"profinet_dcp_decode + opcua_decode + goose_decode + ptpv2_decode for " +
		"full coverage from field instruments through DCS/SCADA up to MES; " +
		"targets DEF CON ICS Village CTFs + S4 Symposium + Emerson/Honeywell/" +
		"ABB/Yokogawa-shop ICS pentest engagements). Wrap-vs-native: native — " +
		"the HART-IP envelope is a tight 8-byte header with publicly " +
		"documented Message Type + Message ID registries; the encapsulated " +
		"HART payload is a separate decoder; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"HART-IP message bytes starting at the Version byte 0x01 (after the UDP-datagram or TCP-segment header strip; default UDP/TCP port 5094). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   hartIPDecodeHandler,
}

func hartIPDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("hart_ip_decode: 'hex' is required")
	}
	res, err := hartip.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("hart_ip_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
