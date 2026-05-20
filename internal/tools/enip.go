// enip.go — host-side EtherNet/IP + CIP packet decoder Spec.
// Wraps the internal/enip walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/enip"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(enipDecodeSpec)
}

var enipDecodeSpec = Spec{
	Name: "enip_decode",
	Description: "Decode an EtherNet/IP encapsulation packet plus any CIP (Common " +
		"Industrial Protocol) message it carries per ODVA CIP Vol 1 + Vol 2. " +
		"EtherNet/IP is the dominant factory-floor protocol on the North American " +
		"plant floor — the regional counterpart to S7Comm (Siemens, EU/Asia) and " +
		"the third leg of the factory PLC trifecta alongside Modbus (universal). " +
		"Used by Allen-Bradley / Rockwell ControlLogix / CompactLogix / MicroLogix " +
		"PLCs, Omron NJ/NX, Cognex vision systems, and a long tail of CIP-" +
		"compliant I/O modules and drives. Carries Explicit Messaging over TCP/" +
		"44818 (request/reply HMI/SCADA channel calling CIP services like " +
		"Get_Attribute_Single, Read_Tag, Forward_Open) and Implicit Messaging " +
		"over UDP/2222 (high-rate class 1 I/O scans after a Forward_Open " +
		"negotiation). Decodes:\n\n" +
		"- **Encapsulation header** (ODVA CIP Vol 2 §2.3, 24 bytes, little-" +
		"endian): Command (uint16 LE) + Length + 32-bit Session Handle " +
		"(allocated by server on RegisterSession) + 32-bit Status + 8-byte " +
		"Sender Context (opaque correlation cookie) + 32-bit Options " +
		"(reserved).\n" +
		"- **9-entry Command name table**: 0x0000 NOP / 0x0004 ListServices / " +
		"0x0063 ListIdentity / 0x0064 ListInterfaces / 0x0065 RegisterSession / " +
		"0x0066 UnRegisterSession / 0x006F SendRRData (CIP request/reply over " +
		"TCP) / 0x0070 SendUnitData (CIP class 1 connected over UDP) / 0x0072 " +
		"IndicateStatus / 0x0073 Cancel.\n" +
		"- **7-entry Status name table**: 0x0000 Success / 0x0001 " +
		"Invalid_or_Unsupported_Command / 0x0002 Insufficient_Memory / 0x0003 " +
		"Incorrect_Data / 0x0064 Invalid_Session_Handle / 0x0065 Invalid_Length " +
		"/ 0x0069 Unsupported_Protocol_Version.\n" +
		"- **Common Packet Format walker** for SendRRData (0x006F) and " +
		"SendUnitData (0x0070): 4-byte Interface Handle + 2-byte Timeout + " +
		"Item Count + N items of (Type ID + Length + Data).\n" +
		"- **8-entry Common Packet Format item type name table**: 0x0000 Null " +
		"/ 0x000C ListIdentity_item / 0x00A1 Connected_Address / 0x00B1 " +
		"Connected_Data / 0x00B2 Unconnected_Data (CIP message — common shape " +
		"for SendRRData) / 0x0100 ListServices_response / 0x8000 Sockaddr_O2T " +
		"/ 0x8001 Sockaddr_T2O.\n" +
		"- **CIP message decoder** for Unconnected_Data (0x00B2) items: 1-byte " +
		"Service Code (high bit 0x80 = response indicator); per-direction body " +
		"— requests have Request Path Size (in 16-bit words) + EPATH + service-" +
		"specific request data; responses have Reserved + General Status + " +
		"Additional Status Size + Additional Status + response data.\n" +
		"- **30+ entry CIP Service Code name table**: 0x01 Get_Attributes_All / " +
		"0x02 Set_Attributes_All / 0x05 Reset / 0x06 Start / 0x07 Stop / 0x0A " +
		"Multiple_Service_Packet / 0x0E Get_Attribute_Single / 0x10 " +
		"Set_Attribute_Single / 0x4B Execute_PCCC (legacy DH+/SLC) / 0x4C " +
		"Read_Tag (Logix tag-based addressing) / 0x4D Write_Tag / 0x52 " +
		"Read_Tag_Fragmented / 0x53 Write_Tag_Fragmented / 0x54 Forward_Open / " +
		"0x5B Forward_Close / 0x5F Unconnected_Send.\n" +
		"- **20+ entry CIP General Status name table**: 0x00 Success / 0x01 " +
		"Connection_Failure / 0x02 Resource_Unavailable / 0x03 " +
		"Invalid_Parameter_Value / 0x04 Path_Segment_Error / 0x05 " +
		"Path_Destination_Unknown / 0x07 Connection_Lost / 0x08 " +
		"Service_Not_Supported / 0x0E Attribute_Not_Settable / 0x14 " +
		"Attribute_Not_Supported / 0x16 Object_Does_Not_Exist.\n\n" +
		"Pure offline parser — operators paste EtherNet/IP bytes (starting at " +
		"the Command bytes) from a `tcpdump -X port 44818` line, a Wireshark " +
		"EtherNet/IP+CIP dissector view, or a UDP/2222 implicit-messaging " +
		"capture and get the documented encapsulation + CPF + CIP service " +
		"breakdown.\n\n" +
		"Out of scope (deferred): network framing (feed EtherNet/IP bytes after " +
		"the TCP-segment or UDP-datagram header strip — default TCP port 44818 " +
		"explicit + UDP port 2222 implicit/class 1); EPATH segment walker (CIP " +
		"Request Path bytes carry segments — Logical, Symbolic, Network, ANSI " +
		"Extended Symbolic per ODVA CIP Vol 1 §C-1; surfaced as path_hex for " +
		"future per-segment walkers including Class/Instance/Attribute resolver " +
		"and ANSI Extended Symbolic tag-name extraction); per-service request/" +
		"response decoder (Read_Tag / Write_Tag value-type encoding BOOL/SINT/" +
		"INT/DINT/REAL/STRING/UDT, Forward_Open connection parameters incl. " +
		"Connection_Serial_Number + T_O/O_T RPI + Network Connection " +
		"Parameters, Multiple_Service_Packet bundle unpacking — surfaced as " +
		"body_hex for downstream per-service walkers); CIP Security (a separate " +
		"decoder; the encapsulation layer transports it transparently but the " +
		"body is encrypted and authenticated outside this layer); Class 1 " +
		"connection state-machine (Forward_Open negotiates O→T + T→O " +
		"connections subsequently carrying class 1 I/O scans under " +
		"SendUnitData; RPI compliance / COS triggers / timeout multipliers are " +
		"higher-level analysis).\n\n" +
		"Source: docs/catalog/gap-analysis.md (North American factory-floor " +
		"PLC dissector — completes the factory PLC trifecta with modbus_decode " +
		"(universal) + s7comm_decode (Siemens) + enip_decode (Allen-Bradley/" +
		"Rockwell); targets DEF CON ICS Village CTFs + Rockwell-shop ICS " +
		"pentest engagements). Wrap-vs-native: native — ODVA CIP Vol 1 + Vol 2 " +
		"are publicly available; both the EtherNet/IP encapsulation header " +
		"(24 bytes LE) and the Common Packet Format are tight, deterministic " +
		"structures; the CIP service request/response shape is also fixed; no " +
		"crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"EtherNet/IP packet bytes starting at the Command bytes (after TCP-segment or UDP-datagram header strip). Default TCP port 44818 (explicit) / UDP port 2222 (implicit / class 1). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   enipDecodeHandler,
}

func enipDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("enip_decode: 'hex' is required")
	}
	res, err := enip.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("enip_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
