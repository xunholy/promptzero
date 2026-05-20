// Package s7comm decodes classic S7Comm PDUs — the Siemens S7-
// 300 / S7-400 / S7-1200 / S7-1500 PLC protocol that rides on
// ISO-on-TCP (RFC 1006, default TCP port 102). S7Comm is the
// dominant factory-floor PLC protocol in European and Asian
// manufacturing — and the canonical Stuxnet target — used by
// Siemens TIA Portal, libnodave, snap7, and a long tail of HMI/
// SCADA stacks talking to S7 PLCs.
//
// Operationally, S7Comm carries:
//
//   - **Variable Read/Write** — by far the most common traffic;
//     HMIs and supervisory layers pull live I/O, DB, M, T, C
//     values out of the PLC and write setpoints back.
//   - **Setup Communication** — the three-way negotiation (CR/CC
//     COTP handshake + Setup Communication PDU) that opens a
//     session and exchanges PDU-Length / Max-Calling-AMQP.
//   - **PLC Control** — Run/Stop/Resume/MemoryReset and block
//     upload/download (firmware programming) — the dangerous
//     functions a pentester / red-teamer targets.
//   - **Userdata** (ROSCTR 0x07) — diagnostics, time-of-day get/
//     set, security, alarms; a richer per-subfunction tree the
//     decoder surfaces as raw `parameters_hex` for downstream
//     walkers.
//
// Wrap-vs-native judgement
//
//	Native. The wire format is fully reverse-engineered and
//	stable (libnodave, snap7, Wireshark s7comm dissector). The
//	transport stack is tight: 4-byte TPKT header (RFC 2126) +
//	variable-length COTP header (ISO 8073 §13.4) + 10-or-12-
//	byte S7 header + parameter block + data block. No crypto
//	at the parse layer for classic S7Comm; the newer S7Comm-
//	Plus (S7-1500) uses an integrity-protected variant which
//	is out of scope for this decoder.
//
// What this package covers
//
//   - **TPKT header** (RFC 2126 / RFC 1006, 4 bytes; big-endian):
//
//   - byte 0: Version (= 3 for S7Comm).
//
//   - byte 1: Reserved (= 0).
//
//   - bytes 2-3: Length (uint16 BE; total bytes of the TPKT
//     packet including this 4-byte header).
//
//   - **COTP header** (ISO 8073 §13.4, variable length; minimum
//     3 bytes for the common DT data PDU):
//
//   - byte 0: Length Indicator (LI; count of header bytes
//     EXCLUDING the LI byte itself — so total COTP header
//     = LI + 1).
//
//   - byte 1: PDU Type (high nibble; classic values are 0xE
//     CR / 0xD CC / 0x8 DR / 0xC DC / 0xF0 DT / 0x7 ED /
//     0x2 EA / 0x6 RJ / 0x1 ER).
//
//   - bytes 2+: PDU-type-specific. For the DT (data) PDU
//     that carries every S7Comm PDU, byte 2 contains the
//     TPDU Number (bit 7 EOT — end-of-TSDU; bits 0-6 = TPDU
//     number).
//
//   - **9-entry COTP PDU type name table**: 0xE0 CR (Connection
//     Request) / 0xD0 CC (Connection Confirm) / 0xF0 DT (Data)
//     / 0x80 DR (Disconnect Request) / 0xC0 DC (Disconnect
//     Confirm) / 0x70 ED (Expedited Data) / 0x20 EA (Expedited
//     Ack) / 0x60 RJ (Reject) / 0x10 ER (TPDU Error).
//
//   - **S7 header** (10 or 12 bytes; big-endian):
//
//   - byte 0: Protocol ID (= 0x32).
//
//   - byte 1: ROSCTR (Remote Operating Service Control).
//
//   - bytes 2-3: Reserved (= 0x0000).
//
//   - bytes 4-5: PDU Reference (uint16 BE; correlation ID
//     pairing request and response).
//
//   - bytes 6-7: Parameter Length (uint16 BE).
//
//   - bytes 8-9: Data Length (uint16 BE).
//
//   - bytes 10-11 (ROSCTR 0x02 / 0x03 only): Error Class +
//     Error Code. The decoder surfaces both as integers and
//     decodes the Error Class against the documented name
//     table.
//
//   - **4-entry ROSCTR name table** (S7Comm wiki / Wireshark):
//     0x01 `Job_Request` (request) / 0x02 `Ack` (acknowledge
//     without data) / 0x03 `Ack_Data` (acknowledge with
//     response data) / 0x07 `Userdata` (diagnostics + time +
//     security + alarms — richer subfunction tree surfaced as
//     raw `parameters_hex`).
//
//   - **First-byte function code from the parameter block**
//     (per-Job_Request / Ack_Data only, since Userdata uses a
//     different per-subfunction header):
//
//   - **15-entry function code name table**: 0x00 `CPU_services`
//     / 0x04 `Read_Var` / 0x05 `Write_Var` / 0x1A
//     `Request_Download` / 0x1B `Download_Block` / 0x1C
//     `Download_Ended` / 0x1D `Start_Upload` / 0x1E `Upload`
//     / 0x1F `End_Upload` / 0x28 `PLC_Control` / 0x29
//     `PLC_Stop` / 0xF0 `Setup_Communication`.
//
//   - **9-entry Error Class name table** (ROSCTR 0x02 / 0x03
//     only): 0x00 `No_Error` / 0x81 `Application_Relationship`
//     / 0x82 `Object_Definition` / 0x83 `No_Resources_Available`
//     / 0x84 `Error_On_Service_Processing` / 0x85
//     `Error_On_Supplies` / 0x87 `Access_Error`.
//
//   - **Parameter + data block surfacing** — the per-function
//     parameter shape (Read_Var carries a count of Items
//     followed by per-Item ItemSpec records with Variable
//     Specification + length + DB number + Address; Write_Var
//     adds a data block with Data Item records) is dataset-
//     specific and surfaced as `parameters_hex` and
//     `data_hex` for downstream per-function walkers.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Network framing** — feed S7Comm bytes after the TCP-
//     segment-header strip (default TCP port 102 with one
//     TPKT-encapsulated COTP-encapsulated S7 PDU per TCP
//     segment in the well-behaved case; TPKT can span segments
//     in pathological cases that this decoder does not
//     reassemble).
//   - **COTP CR / CC parameter walker** — the Connection Request
//     / Confirm PDUs carry parameter blocks (Calling/Called
//     TSAP, TPDU size) that influence the S7Comm session
//     parameters; the decoder identifies the PDU type via the
//     name table but does not parse the parameter blocks (out
//     of scope unless we need the TSAP for risk gating).
//   - **Per-function parameter walkers** — Read_Var ItemSpec
//     records (Variable Specification + Transport Size + Length
//   - DB number + Area + Address bit string), Write_Var Data
//     Item records, PLC_Control filename strings, Setup_Communication
//     PDU-Length negotiation — all surfaced as `parameters_hex`
//     for future per-function decoders.
//   - **Userdata subfunction tree** — ROSCTR 0x07 carries an
//     additional parameter sub-block with a function group
//     (Programmer Commands / Cyclic Services / Block Functions /
//     CPU Functions / Security Functions / Time Functions /
//     NC Programming) and subfunction code (e.g. 0x01 Read SZL,
//     0x02 Read Diagnostic List, 0x82 Set Clock). All surfaced
//     as `parameters_hex` and `data_hex`.
//   - **S7Comm-Plus** — the integrity-protected wire format
//     used by S7-1500 (and optionally S7-1200 v4+) is a separate
//     decoder; protocol ID is 0x72 not 0x32. This package
//     specifically targets classic S7Comm (0x32).
//   - **State-machine reasoning** — session setup, PDU-Length
//     negotiation, upload/download multi-PDU sequencing; higher-
//     level analysis.
package s7comm

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the structured decode of an S7Comm PDU (TPKT + COTP
// + S7 header + opaque parameter + data).
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// TPKT (RFC 2126)
	TPKTVersion int `json:"tpkt_version"`
	TPKTLength  int `json:"tpkt_length"`

	// COTP (ISO 8073)
	COTPLengthIndicator int    `json:"cotp_length_indicator"`
	COTPPDUType         int    `json:"cotp_pdu_type"`
	COTPPDUTypeName     string `json:"cotp_pdu_type_name"`
	COTPTPDUNumber      int    `json:"cotp_tpdu_number,omitempty"`
	COTPEndOfTSDU       bool   `json:"cotp_end_of_tsdu,omitempty"`

	// S7 header
	S7ProtocolID    int    `json:"s7_protocol_id,omitempty"`
	ROSCTR          int    `json:"rosctr,omitempty"`
	ROSCTRName      string `json:"rosctr_name,omitempty"`
	PDUReference    int    `json:"pdu_reference,omitempty"`
	ParameterLength int    `json:"parameter_length,omitempty"`
	DataLength      int    `json:"data_length,omitempty"`

	// Ack / Ack_Data only
	ErrorClass     int    `json:"error_class,omitempty"`
	ErrorClassName string `json:"error_class_name,omitempty"`
	ErrorCode      int    `json:"error_code,omitempty"`

	// Function code (first byte of parameter block; Job_Request +
	// Ack_Data only).
	FunctionCode int    `json:"function_code,omitempty"`
	FunctionName string `json:"function_name,omitempty"`

	// Opaque payload bytes (surfaced for downstream walkers).
	ParametersHex string `json:"parameters_hex,omitempty"`
	DataHex       string `json:"data_hex,omitempty"`
}

// Decode parses an S7Comm PDU (starting at the TPKT version byte)
// from a hex string. Separators (':' '-' '_' whitespace) are
// tolerated; a leading '0x' prefix is stripped.
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if len(clean) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex (%d nibbles)", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	// Min frame = 4 TPKT + 3 COTP (LI=2 + type + payload byte) = 7.
	if len(b) < 7 {
		return nil, fmt.Errorf("S7Comm frame truncated (%d bytes; need ≥7 for TPKT + minimum COTP)",
			len(b))
	}
	if b[0] != 0x03 {
		return nil, fmt.Errorf("missing TPKT version 0x03 (got 0x%02X)", b[0])
	}

	r := &Result{
		TotalBytes:          len(b),
		TPKTVersion:         int(b[0]),
		TPKTLength:          int(binary.BigEndian.Uint16(b[2:4])),
		COTPLengthIndicator: int(b[4]),
		COTPPDUType:         int(b[5]),
	}
	r.COTPPDUTypeName = cotpPDUTypeName(r.COTPPDUType)

	// COTP header total bytes = LI + 1.
	cotpHeaderEnd := 4 + r.COTPLengthIndicator + 1
	if cotpHeaderEnd > len(b) {
		return r, nil
	}

	// For DT (data) PDUs, byte 6 is the TPDU number + EOT bit.
	if r.COTPPDUType == 0xF0 && len(b) > 6 {
		r.COTPTPDUNumber = int(b[6] & 0x7F)
		r.COTPEndOfTSDU = b[6]&0x80 != 0
	}

	// S7 header starts right after the COTP header.
	if cotpHeaderEnd+10 > len(b) || b[cotpHeaderEnd] != 0x32 {
		return r, nil
	}
	s7 := b[cotpHeaderEnd:]
	r.S7ProtocolID = int(s7[0])
	r.ROSCTR = int(s7[1])
	r.ROSCTRName = rosctrName(r.ROSCTR)
	r.PDUReference = int(binary.BigEndian.Uint16(s7[4:6]))
	r.ParameterLength = int(binary.BigEndian.Uint16(s7[6:8]))
	r.DataLength = int(binary.BigEndian.Uint16(s7[8:10]))

	headerEnd := 10
	if r.ROSCTR == 0x02 || r.ROSCTR == 0x03 {
		if len(s7) < 12 {
			return r, nil
		}
		r.ErrorClass = int(s7[10])
		r.ErrorClassName = errorClassName(r.ErrorClass)
		r.ErrorCode = int(s7[11])
		headerEnd = 12
	}

	// Parameter block.
	paramEnd := headerEnd + r.ParameterLength
	if paramEnd > len(s7) {
		return r, nil
	}
	if r.ParameterLength > 0 {
		params := s7[headerEnd:paramEnd]
		r.ParametersHex = strings.ToUpper(hex.EncodeToString(params))
		// First byte = function code for Job_Request +
		// Ack_Data.
		if r.ROSCTR == 0x01 || r.ROSCTR == 0x03 {
			r.FunctionCode = int(params[0])
			r.FunctionName = functionName(r.FunctionCode)
		}
	}

	// Data block.
	dataEnd := paramEnd + r.DataLength
	if dataEnd > len(s7) {
		return r, nil
	}
	if r.DataLength > 0 {
		r.DataHex = strings.ToUpper(hex.EncodeToString(s7[paramEnd:dataEnd]))
	}
	return r, nil
}

func cotpPDUTypeName(t int) string {
	switch t {
	case 0xE0:
		return "CR (Connection Request)"
	case 0xD0:
		return "CC (Connection Confirm)"
	case 0xF0:
		return "DT (Data)"
	case 0x80:
		return "DR (Disconnect Request)"
	case 0xC0:
		return "DC (Disconnect Confirm)"
	case 0x70:
		return "ED (Expedited Data)"
	case 0x20:
		return "EA (Expedited Ack)"
	case 0x60:
		return "RJ (Reject)"
	case 0x10:
		return "ER (TPDU Error)"
	}
	return fmt.Sprintf("uncatalogued COTP PDU type 0x%02X", t)
}

func rosctrName(r int) string {
	switch r {
	case 0x01:
		return "Job_Request"
	case 0x02:
		return "Ack"
	case 0x03:
		return "Ack_Data"
	case 0x07:
		return "Userdata"
	}
	return fmt.Sprintf("uncatalogued ROSCTR 0x%02X", r)
}

func functionName(f int) string {
	switch f {
	case 0x00:
		return "CPU_services"
	case 0x04:
		return "Read_Var"
	case 0x05:
		return "Write_Var"
	case 0x1A:
		return "Request_Download"
	case 0x1B:
		return "Download_Block"
	case 0x1C:
		return "Download_Ended"
	case 0x1D:
		return "Start_Upload"
	case 0x1E:
		return "Upload"
	case 0x1F:
		return "End_Upload"
	case 0x28:
		return "PLC_Control"
	case 0x29:
		return "PLC_Stop"
	case 0xF0:
		return "Setup_Communication"
	}
	return fmt.Sprintf("uncatalogued function 0x%02X", f)
}

func errorClassName(e int) string {
	switch e {
	case 0x00:
		return "No_Error"
	case 0x81:
		return "Application_Relationship"
	case 0x82:
		return "Object_Definition"
	case 0x83:
		return "No_Resources_Available"
	case 0x84:
		return "Error_On_Service_Processing"
	case 0x85:
		return "Error_On_Supplies"
	case 0x87:
		return "Access_Error"
	}
	return fmt.Sprintf("uncatalogued error class 0x%02X", e)
}

func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', ':', '-', '_':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
