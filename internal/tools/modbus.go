// modbus.go — host-side Modbus RTU / Modbus TCP dissector
// Spec, delegating to the internal/modbus package for the
// walker proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/modbus"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(modbusDecodeSpec)
}

var modbusDecodeSpec = Spec{
	Name: "modbus_decode",
	Description: "Decode a Modbus RTU or Modbus TCP frame — the dominant serial + Ethernet " +
		"industrial-control protocol used by PLCs, RTUs, SCADA gateways, building-automation " +
		"controllers, smart-meters, solar inverters, EV chargers, and almost every legacy " +
		"OT device shipping since 1979. Per Modbus Application Protocol v1.1b3 + Modbus " +
		"Messaging Implementation Guide v1.0b. Decodes:\n\n" +
		"- **Envelope auto-detection**: TCP MBAP header (TransactionID + ProtocolID 0x0000 " +
		"+ Length + UnitID) is recognised by the all-zero ProtocolID and the Length field " +
		"covering the remainder; everything else falls through to RTU ([addr][func][data]" +
		"[CRC-16]).\n" +
		"- **RTU CRC-16/Modbus validation**: polynomial 0xA001 (reflected from 0x8005), " +
		"init 0xFFFF, reflected, no final XOR. Surfaces both the captured CRC and the " +
		"computed expected value in wire-byte order (low byte first, matching how Modbus " +
		"tools and Wireshark present the trailing 2 bytes) for forensic diffing.\n" +
		"- **Function code dispatch** for the well-known operations:\n" +
		"  - 0x01 Read Coils, 0x02 Read Discrete Inputs, 0x03 Read Holding Registers, " +
		"0x04 Read Input Registers — request shape: start + qty; response shape: " +
		"byte_count + N data bytes (bits for coils, 16-bit words for registers).\n" +
		"  - 0x05 Write Single Coil (0xFF00 = ON, 0x0000 = OFF), 0x06 Write Single " +
		"Register — identical request/response shape.\n" +
		"  - 0x0F Write Multiple Coils, 0x10 Write Multiple Registers — request: " +
		"start + qty + byte_count + values; response: start + qty.\n" +
		"  - 0x16 Mask Write Register (AND mask + OR mask).\n" +
		"  - 0x07 Read Exception Status, 0x08 Diagnostic (with sub-function), 0x0B / " +
		"0x0C / 0x11 / 0x14 / 0x15 / 0x17 / 0x18 — named, payload surfaced as raw hex.\n" +
		"  - 0x2B Encapsulated Interface (MEI, incl. 0x0E Read Device Identification) — " +
		"sub-function surfaced.\n" +
		"- **Exception responses** (function code high bit set): exception code 0x01 " +
		"Illegal Function, 0x02 Illegal Data Address, 0x03 Illegal Data Value, 0x04 " +
		"Server Device Failure, 0x05 Acknowledge, 0x06 Server Device Busy, 0x07 Negative " +
		"Acknowledge, 0x08 Memory Parity Error, 0x0A Gateway Path Unavailable, 0x0B " +
		"Gateway Target Device Failed to Respond. FunctionName references the original " +
		"(non-exception) function code so operators see what was being attempted.\n" +
		"- **Request / response disambiguation by payload shape**: for read functions " +
		"(0x01-0x04) where the request is a 4-byte [start][qty] and the response starts " +
		"with a byte_count, both shapes are tried — the one that fits is populated.\n\n" +
		"Pure offline parser — operators paste a hex frame from Wireshark / Modbus Doctor / " +
		"qModBus / a tcpdump of port 502 / a captured serial trace and inspect every field " +
		"without re-attaching to the bus. Complements the existing OT-pentest workflow with " +
		"the missing read-side primitive for the most-deployed ICS protocol.\n\n" +
		"Out of scope (deferred to future iterations): Modbus ASCII envelope (function code " +
		"hex-encoded with LRC; framed by ':' and CRLF), deeper sub-function decode for " +
		"diagnostic (0x08) and MEI (0x2B) payloads, Modbus over UDP, Modbus+ / JBUS " +
		"dialects, multi-frame reassembly.\n\n" +
		"Source: docs/catalog/gap-analysis.md (OT / ICS decode space — Modbus is the most " +
		"deployed industrial protocol, foundational for any SCADA / PLC pentest). " +
		"Wrap-vs-native: native — Modbus is fully public, CRC-16 is a textbook polynomial, " +
		"function-code dispatch is a switch.\n\n" +
		"Accepts ':' / '-' / '_' / whitespace separators and a leading '0x' prefix.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded Modbus frame. RTU: [addr:1][func:1][data:0..252][CRC-16:2] (min 4 bytes). TCP: [txn:2][proto:2][len:2][unit:1][func:1][data:0..252] (min 8 bytes). Auto-detected by MBAP-header presence. ':' / '-' / '_' / whitespace separators tolerated; '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   modbusDecodeHandler,
}

func modbusDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("modbus_decode: 'hex' is required")
	}
	res, err := modbus.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("modbus_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
