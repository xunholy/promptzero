// Package iec104 decodes IEC 60870-5-104 APDUs — the European /
// Asian utility-SCADA telecontrol protocol that runs over TCP/IP.
// IEC 104 is the IP-borne sibling of IEC 60870-5-101 (serial) and
// the de-facto counterpart to North American DNP3.
//
// Operationally, IEC 104 is the wire format on the substation /
// control-centre boundary in European and Asian power-grid
// operators (TenneT, Amprion, Statnett, State Grid, etc.) and in
// rail / district-heat / water-utility operators worldwide. It
// is the dominant target an attacker tapping into an EU
// substation Ethernet link sees on the wire — the IEC 61850
// process-bus side carries GOOSE/MMS, but the station-bus side
// carrying telecontrol to the SCADA master almost always speaks
// IEC 104 (TCP port 2404).
//
// Wrap-vs-native judgement
//
//	Native. The IEC 60870-5-104 spec is fully public (IEC TC57
//	publication). APDUs have a tight 6-byte APCI (0x68 start +
//	Length + 4-byte Control field) plus, for Information frames,
//	an ASDU with Type ID + Variable Structure Qualifier + Cause
//	of Transmission + Common Address followed by Information
//	Objects. The Information-Object payload is type-dependent
//	(M_SP_NA_1 single-point boolean, M_ME_NC_1 short float,
//	C_SC_NA_1 single command, ...); the per-type body decoder
//	set is large and dataset-specific — surfaced as
//	`information_objects_hex` for future per-TI walkers. No
//	crypto at the parse layer; IEC 62351 secures the transport,
//	not the IEC-104 frame itself.
//
// What this package covers
//
//   - **APCI** (Application Protocol Control Information, 6
//     bytes; little-endian where multi-byte):
//
//   - byte 0: Start = 0x68 (sync).
//
//   - byte 1: APDU Length (1-253, count of bytes that follow
//     this byte — i.e. 4-byte Control field + optional ASDU).
//
//   - bytes 2-5: **Control field** — three frame formats
//     discriminated by the low 2 bits of byte 2:
//
//   - **I-format** (Information; bit 0 of byte 2 = 0):
//     carries an ASDU. The 4-byte Control field encodes
//     a 15-bit Send Sequence Number N(S) (bits 1-15 of
//     bytes 2-3, LE) and a 15-bit Receive Sequence
//     Number N(R) (bits 1-15 of bytes 4-5, LE).
//
//   - **S-format** (Supervisory; bits 0-1 of byte 2 =
//     01): carries no ASDU; bytes 2-3 are reserved, the
//     N(R) sits in bits 1-15 of bytes 4-5. Used for pure
//     acknowledgements without piggyback I-frames.
//
//   - **U-format** (Unnumbered; bits 0-1 of byte 2 =
//     11): carries no ASDU; bits 2-7 of byte 2 encode
//     **STARTDT** (start data transfer), **STOPDT**
//     (stop data transfer), and **TESTFR** (test frame)
//     as paired *act* + *con* commands. Used for link
//     control (open/close the data path).
//
//   - **U-format function-bit name set** (bits in byte 2): 0x04
//     `STARTDT_act` / 0x08 `STARTDT_con` / 0x10 `STOPDT_act` /
//     0x20 `STOPDT_con` / 0x40 `TESTFR_act` / 0x80 `TESTFR_con`.
//
//   - **ASDU** (Application Service Data Unit, present for
//     I-format only):
//
//   - byte 0: **Type Identification** (1 byte).
//
//   - byte 1: **Variable Structure Qualifier** — bit 7 SQ
//     (1 = single object with sequence of elements;
//     0 = sequence of objects each with own address);
//     bits 0-6 = Number of elements / objects (0-127).
//
//   - bytes 2-3: **Cause of Transmission** — byte 0 has 6-
//     bit cause + bit 6 P/N (Positive/Negative confirm)
//
//   - bit 7 T (Test indicator); byte 1 = Originator
//     Address (0 = no originator).
//
//   - bytes 4-5: **Common Address of ASDU** (uint16 LE;
//     0xFFFF = broadcast).
//
//   - then: **Information Objects** — per-TI body bytes
//     surfaced as `information_objects_hex`.
//
//   - **40+ entry Type Identification name table** (IEC
//     60870-5-104 §7.4.6 — selected high-runners across
//     monitor-direction, control-direction, and file-transfer
//     traffic): 1 `M_SP_NA_1` / 3 `M_DP_NA_1` / 5 `M_ST_NA_1` /
//     7 `M_BO_NA_1` / 9 `M_ME_NA_1` / 11 `M_ME_NB_1` / 13
//     `M_ME_NC_1` / 15 `M_IT_NA_1` / 30 `M_SP_TB_1` / 31
//     `M_DP_TB_1` / 35 `M_ME_TD_1` / 36 `M_ME_TE_1` / 37
//     `M_ME_TF_1` / 38 `M_EP_TD_1` / 45 `C_SC_NA_1` / 46
//     `C_DC_NA_1` / 47 `C_RC_NA_1` / 48 `C_SE_NA_1` / 49
//     `C_SE_NB_1` / 50 `C_SE_NC_1` / 51 `C_BO_NA_1` / 58
//     `C_SC_TA_1` / 59 `C_DC_TA_1` / 70 `M_EI_NA_1` / 100
//     `C_IC_NA_1` / 101 `C_CI_NA_1` / 102 `C_RD_NA_1` / 103
//     `C_CS_NA_1` / 104 `C_TS_NA_1` / 105 `C_RP_NA_1` / 106
//     `C_CD_NA_1` / 107 `C_TS_TA_1` / 110 `P_ME_NA_1` / 111
//     `P_ME_NB_1` / 112 `P_ME_NC_1` / 113 `P_AC_NA_1` / 120
//     `F_FR_NA_1` / 121 `F_SR_NA_1` / 122 `F_SC_NA_1` / 123
//     `F_LS_NA_1` / 124 `F_AF_NA_1` / 125 `F_SG_NA_1` / 126
//     `F_DR_TA_1`.
//
//   - **20-entry Cause of Transmission name table** (IEC
//     60870-5-104 §7.4.4): 1 `per/cyc` / 2 `back` / 3 `spont`
//     / 4 `init` / 5 `req` / 6 `act` / 7 `actcon` / 8 `deact`
//     / 9 `deactcon` / 10 `actterm` / 11 `retrem` / 12 `retloc`
//     / 13 `file` / 20 `inrogen` (general interrogation) / 21
//     `inro1` / 22 `inro2` / 37 `reqcogen` (counter
//     interrogation) / 44 `unknown_type` / 45 `unknown_cause`
//     / 46 `unknown_addr` / 47 `unknown_ioa`. The P/N and T
//     bits in byte 0 of the COT are surfaced as derived
//     `cot_negative_confirm` and `cot_test` fields.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Transport framing** — IEC 104 sits over TCP port 2404
//     by default; feed APDU bytes (starting at the 0x68 sync)
//     after the TCP-segment-header strip. IEC 62351-3
//     authentication / IEC 62351-5 application-layer security
//     are higher-layer concerns.
//   - **Per-TI Information-Object decoders** — the per-Type
//     payload for the 60+ catalogued Type IDs (M_SP_NA_1
//     single-point, M_ME_NC_1 short float, C_SC_NA_1 single
//     command with QU select/execute bits, C_CS_NA_1 clock
//     sync with CP56Time2a, F_SG_NA_1 file segment, ...) is
//     dataset-specific; the Information-Object bytes are
//     surfaced as `information_objects_hex` for future per-TI
//     walkers.
//   - **Multi-frame reassembly** — IEC 104 has no transport-
//     layer fragmentation; the per-APDU N(S)/N(R) sequencing
//     is surfaced as raw integers but state-machine reasoning
//     (k/w window enforcement, t0/t1/t2/t3 timer logic) is
//     higher-level.
//   - **CP56Time2a clock-sync decoding** — when a TI carries a
//     CP56Time2a 7-byte time tag (TIs 30-40, 58-59, 107,
//     126), the bytes appear inside `information_objects_hex`
//     and are not pre-parsed.
package iec104

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// FrameFormat enumerates the three IEC 104 frame formats.
type FrameFormat string

const (
	FrameI FrameFormat = "I"
	FrameS FrameFormat = "S"
	FrameU FrameFormat = "U"
)

// Result is the structured decode of an IEC 60870-5-104 APDU.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// APCI
	StartHex    string      `json:"start_hex"`
	APDULength  int         `json:"apdu_length"`
	ControlHex  string      `json:"control_hex"`
	FrameFormat FrameFormat `json:"frame_format"`

	// I-format sequence numbers
	SendSeq    *int `json:"send_seq,omitempty"`
	ReceiveSeq *int `json:"receive_seq,omitempty"`

	// U-format function bits
	UFunctionBits string `json:"u_function_bits,omitempty"`

	// ASDU (I-format only)
	TypeID                int    `json:"type_id,omitempty"`
	TypeName              string `json:"type_name,omitempty"`
	SQ                    bool   `json:"vsq_sq_sequence_of_elements,omitempty"`
	NumElements           int    `json:"vsq_num_elements,omitempty"`
	COT                   int    `json:"cot_cause,omitempty"`
	COTName               string `json:"cot_name,omitempty"`
	COTNegativeConfirm    bool   `json:"cot_negative_confirm,omitempty"`
	COTTest               bool   `json:"cot_test,omitempty"`
	OriginatorAddress     int    `json:"originator_address,omitempty"`
	CommonAddress         int    `json:"common_address,omitempty"`
	InformationObjectsHex string `json:"information_objects_hex,omitempty"`
}

// Decode parses an IEC 60870-5-104 APDU from a hex string.
// Separators (':' '-' '_' whitespace) are tolerated; a leading
// '0x' prefix is stripped.
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
	if len(b) < 6 {
		return nil, fmt.Errorf("IEC 104 APDU truncated (%d bytes; need ≥6 for APCI)",
			len(b))
	}
	if b[0] != 0x68 {
		return nil, fmt.Errorf("missing IEC 104 sync 0x68 (got 0x%02X)", b[0])
	}

	r := &Result{
		TotalBytes: len(b),
		StartHex:   "0x68",
		APDULength: int(b[1]),
		ControlHex: fmt.Sprintf("0x%02X%02X%02X%02X",
			b[2], b[3], b[4], b[5]),
	}

	// Frame format dispatch (low 2 bits of control byte 0).
	ctl0 := b[2]
	switch {
	case ctl0&0x01 == 0:
		// I-format: bit 0 = 0.
		r.FrameFormat = FrameI
		ns := int(binary.LittleEndian.Uint16(b[2:4]) >> 1)
		nr := int(binary.LittleEndian.Uint16(b[4:6]) >> 1)
		r.SendSeq = &ns
		r.ReceiveSeq = &nr
		// Decode ASDU if present.
		if len(b) >= 6+6 {
			r.decodeASDU(b[6:])
		}
	case ctl0&0x03 == 0x01:
		// S-format: bits 0-1 = 01.
		r.FrameFormat = FrameS
		nr := int(binary.LittleEndian.Uint16(b[4:6]) >> 1)
		r.ReceiveSeq = &nr
	case ctl0&0x03 == 0x03:
		// U-format: bits 0-1 = 11.
		r.FrameFormat = FrameU
		r.UFunctionBits = uFunctionBitNames(ctl0)
	}

	return r, nil
}

// decodeASDU parses the 6-byte ASDU header + opaque Information
// Objects body.
func (r *Result) decodeASDU(b []byte) {
	if len(b) < 6 {
		return
	}
	r.TypeID = int(b[0])
	r.TypeName = typeName(r.TypeID)
	r.SQ = b[1]&0x80 != 0
	r.NumElements = int(b[1] & 0x7F)
	r.COT = int(b[2] & 0x3F)
	r.COTName = cotName(r.COT)
	r.COTNegativeConfirm = b[2]&0x40 != 0
	r.COTTest = b[2]&0x80 != 0
	r.OriginatorAddress = int(b[3])
	r.CommonAddress = int(binary.LittleEndian.Uint16(b[4:6]))
	if len(b) > 6 {
		r.InformationObjectsHex = strings.ToUpper(hex.EncodeToString(b[6:]))
	}
}

// uFunctionBitNames decodes the 6 U-format function bits in byte
// 2 of the Control field.
func uFunctionBitNames(b byte) string {
	var names []string
	if b&0x04 != 0 {
		names = append(names, "STARTDT_act")
	}
	if b&0x08 != 0 {
		names = append(names, "STARTDT_con")
	}
	if b&0x10 != 0 {
		names = append(names, "STOPDT_act")
	}
	if b&0x20 != 0 {
		names = append(names, "STOPDT_con")
	}
	if b&0x40 != 0 {
		names = append(names, "TESTFR_act")
	}
	if b&0x80 != 0 {
		names = append(names, "TESTFR_con")
	}
	return strings.Join(names, ",")
}

func typeName(t int) string {
	switch t {
	case 1:
		return "M_SP_NA_1"
	case 3:
		return "M_DP_NA_1"
	case 5:
		return "M_ST_NA_1"
	case 7:
		return "M_BO_NA_1"
	case 9:
		return "M_ME_NA_1"
	case 11:
		return "M_ME_NB_1"
	case 13:
		return "M_ME_NC_1"
	case 15:
		return "M_IT_NA_1"
	case 30:
		return "M_SP_TB_1"
	case 31:
		return "M_DP_TB_1"
	case 35:
		return "M_ME_TD_1"
	case 36:
		return "M_ME_TE_1"
	case 37:
		return "M_ME_TF_1"
	case 38:
		return "M_EP_TD_1"
	case 45:
		return "C_SC_NA_1"
	case 46:
		return "C_DC_NA_1"
	case 47:
		return "C_RC_NA_1"
	case 48:
		return "C_SE_NA_1"
	case 49:
		return "C_SE_NB_1"
	case 50:
		return "C_SE_NC_1"
	case 51:
		return "C_BO_NA_1"
	case 58:
		return "C_SC_TA_1"
	case 59:
		return "C_DC_TA_1"
	case 70:
		return "M_EI_NA_1"
	case 100:
		return "C_IC_NA_1"
	case 101:
		return "C_CI_NA_1"
	case 102:
		return "C_RD_NA_1"
	case 103:
		return "C_CS_NA_1"
	case 104:
		return "C_TS_NA_1"
	case 105:
		return "C_RP_NA_1"
	case 106:
		return "C_CD_NA_1"
	case 107:
		return "C_TS_TA_1"
	case 110:
		return "P_ME_NA_1"
	case 111:
		return "P_ME_NB_1"
	case 112:
		return "P_ME_NC_1"
	case 113:
		return "P_AC_NA_1"
	case 120:
		return "F_FR_NA_1"
	case 121:
		return "F_SR_NA_1"
	case 122:
		return "F_SC_NA_1"
	case 123:
		return "F_LS_NA_1"
	case 124:
		return "F_AF_NA_1"
	case 125:
		return "F_SG_NA_1"
	case 126:
		return "F_DR_TA_1"
	}
	return fmt.Sprintf("uncatalogued type ID %d", t)
}

func cotName(c int) string {
	switch c {
	case 1:
		return "per/cyc"
	case 2:
		return "back"
	case 3:
		return "spont"
	case 4:
		return "init"
	case 5:
		return "req"
	case 6:
		return "act"
	case 7:
		return "actcon"
	case 8:
		return "deact"
	case 9:
		return "deactcon"
	case 10:
		return "actterm"
	case 11:
		return "retrem"
	case 12:
		return "retloc"
	case 13:
		return "file"
	case 20:
		return "inrogen"
	case 21:
		return "inro1"
	case 22:
		return "inro2"
	case 37:
		return "reqcogen"
	case 44:
		return "unknown_type"
	case 45:
		return "unknown_cause"
	case 46:
		return "unknown_addr"
	case 47:
		return "unknown_ioa"
	}
	return fmt.Sprintf("uncatalogued cause %d", c)
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
