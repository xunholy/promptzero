// dnp3.go — host-side DNP3 frame decoder Spec.
// Wraps the internal/dnp3 walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/dnp3"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(dnp3DecodeSpec)
}

var dnp3DecodeSpec = Spec{
	Name: "dnp3_decode",
	Description: "Decode a DNP3 (Distributed Network Protocol 3) frame per IEEE " +
		"1815-2012. DNP3 is the dominant utility-SCADA protocol in North American " +
		"power-grid, water, and oil-and-gas telemetry — the field-bus protocol an " +
		"attacker tapping into a substation, pumping station, or pipeline RTU is " +
		"most likely to see on the wire. Carries master ↔ outstation polls (read " +
		"class 1 events / operate breaker) across leased lines, IP/TCP (default " +
		"port 20000) or IP/UDP between SCADA control centres and field RTUs; " +
		"unsolicited responses from outstations reporting state changes (breaker " +
		"open, transformer over-temperature) without waiting for a poll; time " +
		"synchronisation + freeze-at-time for substation event sequencing (used " +
		"alongside PTP in IEC 61850 deployments where DNP3 still owns the SCADA " +
		"application layer); file transfer for outstation firmware + " +
		"configuration drops (function codes 0x19-0x1E); Secure Authentication " +
		"(IEEE 1815-2012 §7, function codes 0x20 / 0x21 / 0x83 — HMAC-SHA256 " +
		"message authentication). Decodes:\n\n" +
		"- **Data-link layer header** (IEEE 1815-2012 §10.3, 10 bytes; little-" +
		"endian where multi-byte): Start (0x05 0x64 sync) + Length (count of bytes " +
		"following Length excluding CRCs; range 5-255) + **Control field** (bit 7 " +
		"DIR — 1 = master-to-outstation; bit 6 PRM — 1 = primary message, 0 = " +
		"secondary; bit 5 FCB / DFC — frame count bit or data-flow control; bit " +
		"4 FCV / RES — frame count valid or reserved; bits 3-0 primary or " +
		"secondary function code) + Destination address (uint16 LE) + Source " +
		"address (uint16 LE) + Header CRC (uint16 LE).\n" +
		"- **5-entry primary function code name table** (§10.3.3): 0 " +
		"RESET_LINK_STATES / 1 TEST_LINK_STATES / 2 CONFIRMED_USER_DATA / 3 " +
		"UNCONFIRMED_USER_DATA / 9 REQUEST_LINK_STATUS.\n" +
		"- **4-entry secondary function code name table**: 0 ACK / 1 NACK / 11 " +
		"LINK_STATUS / 14 NOT_FUNCTIONING.\n" +
		"- **User-data block walker** (§10.3.2.5): user data following the " +
		"10-byte header is split into blocks of 16 bytes each (last block may be " +
		"shorter) followed by a 2-byte block CRC. The decoder strips the per-" +
		"block CRCs and reconstructs the user-data byte stream for higher-layer " +
		"parsing.\n" +
		"- **Transport function byte** (§8.2, first byte of the reconstructed " +
		"user-data stream): bit 7 FIN (final segment), bit 6 FIR (first segment), " +
		"bits 5-0 sequence number.\n" +
		"- **Application header** (§4.2.2): byte 0 = Application Control (bit 7 " +
		"FIR + bit 6 FIN + bit 5 CON — confirm requested + bit 4 UNS — " +
		"unsolicited + bits 3-0 SEQ); byte 1 = Function Code; for responses " +
		"(function codes 0x81 / 0x82 / 0x83) bytes 2-3 = IIN (Internal " +
		"Indication, 16-bit LE).\n" +
		"- **20+ entry application function code name table** (selected high-" +
		"runners from §6.2): 0x00 CONFIRM / 0x01 READ / 0x02 WRITE / 0x03 SELECT " +
		"/ 0x04 OPERATE / 0x05 DIRECT_OPERATE / 0x06 DIRECT_OPERATE_NR / 0x07 " +
		"IMMED_FREEZE / 0x08 IMMED_FREEZE_NR / 0x09 FREEZE_CLEAR / 0x0A " +
		"FREEZE_CLEAR_NR / 0x0B FREEZE_AT_TIME / 0x0D COLD_RESTART / 0x0E " +
		"WARM_RESTART / 0x14 ENABLE_UNSOLICITED / 0x15 DISABLE_UNSOLICITED / " +
		"0x17 DELAY_MEASURE / 0x18 RECORD_CURRENT_TIME / 0x20 AUTHENTICATE_REQ / " +
		"0x21 AUTH_REQ_NO_ACK / 0x81 RESPONSE / 0x82 UNSOLICITED_RESPONSE / 0x83 " +
		"AUTHENTICATE_RESP.\n" +
		"- **16-entry IIN-bit name set** (§4.2.4; both bytes): IIN1 = BROADCAST / " +
		"CLASS_1_EVENTS / CLASS_2_EVENTS / CLASS_3_EVENTS / NEED_TIME / " +
		"LOCAL_CONTROL / DEVICE_TROUBLE / DEVICE_RESTART; IIN2 = " +
		"NO_FUNC_CODE_SUPPORT / OBJECT_UNKNOWN / PARAMETER_ERROR / " +
		"EVENT_BUFFER_OVERFLOW / ALREADY_EXECUTING / CONFIG_CORRUPT. The decoded " +
		"comma-separated set is surfaced alongside the raw 16-bit hex.\n\n" +
		"Pure offline parser — operators paste DNP3 bytes from a `tcpdump -X " +
		"port 20000` line, a Wireshark DNP3 dissector view, or a serial-line " +
		"capture and get the documented header + transport + application layer " +
		"breakdown plus the reconstructed user-data byte stream (post-CRC strip) " +
		"for downstream object walkers.\n\n" +
		"Out of scope (deferred): transport framing (IP/TCP port 20000 default, " +
		"UDP/20000, or serial RS-232/422/485 — feed DNP3 bytes after the " +
		"transport-header strip); CRC verification (the data-link header CRC and " +
		"per-block CRCs are surfaced as hex but not re-computed against IEEE " +
		"1815-2012 §E CRC-16-DNP polynomial 0x3D65); object header walker (past " +
		"the application header DNP3 carries a stream of Object headers — Group " +
		"+ Variation + Qualifier + Range + count + objects — whose per-group " +
		"decoder set is large and dataset-specific; remaining bytes are surfaced " +
		"as `object_data_hex` for future per-group walkers); Secure " +
		"Authentication payload (HMAC-SHA256-protected blocks per §7 are " +
		"surfaced as hex); multi-fragment reassembly (transport FIN/FIR + " +
		"sequence number identify multi-segment fragments but the decoder does " +
		"not reassemble across input frames); state-machine reasoning (primary/" +
		"secondary frame-count-bit logic, ENABLE_UNSOLICITED timer state, " +
		"freeze-counter semantics — higher-level analysis).\n\n" +
		"Source: docs/catalog/gap-analysis.md (utility-SCADA dissector — pairs " +
		"with `modbus_decode` for full industrial-protocol coverage; complements " +
		"the PTPv2 / IEC 61850 substation positioning; the de-facto wire format " +
		"in DEF CON ICS Village CTFs + power-grid pentest engagements). Wrap-vs-" +
		"native: native — IEEE 1815-2012 is fully public; DNP3 has a tight 10-" +
		"byte data-link header + transport byte + 2-or-4-byte application " +
		"header; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"DNP3 frame bytes starting at the 0x05 0x64 sync (after TCP/UDP/serial transport-header strip). Default TCP port 20000. Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   dnp3DecodeHandler,
}

func dnp3DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("dnp3_decode: 'hex' is required")
	}
	res, err := dnp3.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("dnp3_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
