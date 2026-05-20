// s7comm.go — host-side S7Comm PDU decoder Spec.
// Wraps the internal/s7comm walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/s7comm"
)

func init() { //nolint:gochecknoinits
	Register(s7commDecodeSpec)
}

var s7commDecodeSpec = Spec{
	Name: "s7comm_decode",
	Description: "Decode a classic S7Comm PDU per the Siemens S7-300/400/1200/1500 PLC " +
		"protocol that rides on ISO-on-TCP (RFC 1006, default TCP port 102). " +
		"S7Comm is the dominant factory-floor PLC protocol in European and Asian " +
		"manufacturing — and the canonical Stuxnet target — used by Siemens TIA " +
		"Portal, libnodave, snap7, and a long tail of HMI/SCADA stacks talking " +
		"to S7 PLCs. Operationally, S7Comm carries Variable Read/Write (the " +
		"most common traffic; HMIs pull live I/O, DB, M, T, C values and write " +
		"setpoints), Setup Communication (the three-way negotiation that opens " +
		"a session), PLC Control (Run/Stop/Resume/MemoryReset + block upload/" +
		"download = firmware programming, the dangerous functions a pentester " +
		"targets), and Userdata (diagnostics + time + security + alarms). " +
		"Decodes:\n\n" +
		"- **TPKT header** (RFC 2126 / RFC 1006, 4 bytes, big-endian): Version " +
		"(= 3) + Reserved + Length (uint16 BE; total bytes of the TPKT packet " +
		"including this 4-byte header).\n" +
		"- **COTP header** (ISO 8073 §13.4, variable length; minimum 3 bytes " +
		"for the common DT data PDU): Length Indicator (LI; header bytes " +
		"excluding the LI byte itself) + PDU Type (high nibble; 0xE CR / 0xD " +
		"CC / 0x8 DR / 0xC DC / 0xF DT / 0x7 ED / 0x2 EA / 0x6 RJ / 0x1 ER). " +
		"For DT data PDUs, byte 2 contains the TPDU Number (bit 7 EOT — end-of-" +
		"TSDU; bits 0-6 TPDU number).\n" +
		"- **9-entry COTP PDU type name table**: 0xE0 CR (Connection Request) / " +
		"0xD0 CC (Connection Confirm) / 0xF0 DT (Data) / 0x80 DR (Disconnect " +
		"Request) / 0xC0 DC (Disconnect Confirm) / 0x70 ED (Expedited Data) / " +
		"0x20 EA (Expedited Ack) / 0x60 RJ (Reject) / 0x10 ER (TPDU Error).\n" +
		"- **S7 header** (10 or 12 bytes, big-endian): Protocol ID (= 0x32) + " +
		"ROSCTR (Remote Operating Service Control) + 2-byte Reserved + 2-byte " +
		"PDU Reference (correlation ID pairing request and response) + 2-byte " +
		"Parameter Length + 2-byte Data Length + (ROSCTR 0x02 / 0x03 only) " +
		"1-byte Error Class + 1-byte Error Code.\n" +
		"- **4-entry ROSCTR name table**: 0x01 Job_Request (request) / 0x02 " +
		"Ack (acknowledge without data) / 0x03 Ack_Data (acknowledge with " +
		"response data) / 0x07 Userdata (diagnostics + time + security + " +
		"alarms — richer subfunction tree surfaced as parameters_hex).\n" +
		"- **15-entry function code name table** (first byte of the parameter " +
		"block for Job_Request + Ack_Data ROSCTRs): 0x00 CPU_services / 0x04 " +
		"Read_Var / 0x05 Write_Var / 0x1A Request_Download / 0x1B " +
		"Download_Block / 0x1C Download_Ended / 0x1D Start_Upload / 0x1E " +
		"Upload / 0x1F End_Upload / 0x28 PLC_Control / 0x29 PLC_Stop / 0xF0 " +
		"Setup_Communication.\n" +
		"- **9-entry Error Class name table** (Ack / Ack_Data ROSCTRs only): " +
		"0x00 No_Error / 0x81 Application_Relationship / 0x82 Object_Definition " +
		"/ 0x83 No_Resources_Available / 0x84 Error_On_Service_Processing / " +
		"0x85 Error_On_Supplies / 0x87 Access_Error.\n" +
		"- **Parameter + data block surfacing** — the per-function parameter " +
		"shape (Read_Var ItemSpec records, Write_Var Data Item records, " +
		"PLC_Control filename strings, Setup_Communication PDU-Length " +
		"negotiation) is dataset-specific and surfaced as parameters_hex + " +
		"data_hex for downstream per-function walkers.\n\n" +
		"Pure offline parser — operators paste S7Comm bytes (starting at the " +
		"TPKT version byte 0x03) from a `tcpdump -X port 102` line or a " +
		"Wireshark S7Comm dissector view and get the documented TPKT + COTP + " +
		"S7 header + per-ROSCTR function-code breakdown.\n\n" +
		"Out of scope (deferred): network framing (feed S7Comm bytes after the " +
		"TCP-segment-header strip; TPKT can span segments in pathological " +
		"cases that this decoder does not reassemble); COTP CR/CC parameter " +
		"walker (Calling/Called TSAP + TPDU size — out of scope unless we " +
		"need the TSAP for risk gating); per-function parameter walkers " +
		"(Read_Var ItemSpec records with Variable Specification + Transport " +
		"Size + Length + DB number + Area + Address bit string, Write_Var " +
		"Data Item records, PLC_Control filename strings, " +
		"Setup_Communication PDU-Length negotiation — all surfaced as " +
		"parameters_hex for future per-function decoders); Userdata " +
		"subfunction tree (ROSCTR 0x07 carries an additional parameter sub-" +
		"block with function group + subfunction code — Programmer Commands " +
		"/ Cyclic Services / Block Functions / CPU Functions / Security " +
		"Functions / Time Functions / NC Programming; surfaced as " +
		"parameters_hex + data_hex); **S7Comm-Plus** (the integrity-protected " +
		"wire format used by S7-1500 and S7-1200 v4+ is a separate decoder; " +
		"protocol ID is 0x72 not 0x32; this Spec specifically targets classic " +
		"S7Comm = 0x32); state-machine reasoning (session setup, PDU-Length " +
		"negotiation, upload/download multi-PDU sequencing — higher-level " +
		"analysis).\n\n" +
		"Source: docs/catalog/gap-analysis.md (factory-floor PLC dissector — " +
		"pairs with dnp3_decode + iec104_decode + modbus_decode for full " +
		"industrial-protocol coverage; targets DEF CON ICS Village CTFs, " +
		"Stuxnet historical re-analysis, and Siemens-shop ICS pentest " +
		"engagements). Wrap-vs-native: native — the wire format is fully " +
		"reverse-engineered and stable (libnodave, snap7, Wireshark s7comm " +
		"dissector); no crypto at the parse layer for classic S7Comm.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"S7Comm PDU bytes starting at the TPKT version byte (0x03) after the TCP-segment-header strip. Default TCP port 102. Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   s7commDecodeHandler,
}

func s7commDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("s7comm_decode: 'hex' is required")
	}
	res, err := s7comm.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("s7comm_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
