// Package enip decodes EtherNet/IP encapsulation packets and the
// CIP (Common Industrial Protocol) messages they carry — the ODVA
// factory-automation protocol family used by Allen-Bradley /
// Rockwell ControlLogix / CompactLogix / MicroLogix PLCs, Omron
// NJ/NX, Cognex vision systems, and a long tail of CIP-compliant
// I/O modules and drives.
//
// EtherNet/IP is the dominant factory-floor protocol on the
// **North American** plant floor — the regional counterpart to
// S7Comm (Siemens, EU/Asia) and the third leg of the factory PLC
// trifecta alongside Modbus (universal). Operationally, EtherNet/
// IP carries:
//
//   - **Explicit Messaging** over TCP/44818 — the request/reply
//     channel used by HMIs and SCADA layers to call CIP services
//     (Get_Attribute_Single, Set_Attribute_Single, Read_Tag,
//     Write_Tag, Forward_Open, ...).
//   - **Implicit Messaging** over UDP/2222 — the high-rate I/O
//     channel that delivers process data (input I/O scans,
//     output I/O writes) at sub-millisecond cadences. Carried in
//     Class 1 connected packets after a Forward_Open negotiates
//     the connection.
//   - **CIP service requests** that map onto a target object's
//     class / instance / attribute address (the EPATH). Logix-
//     family PLCs additionally accept tag-based addressing via
//     services 0x4C `Read_Tag` / 0x4D `Write_Tag`.
//
// Wrap-vs-native judgement
//
//	Native. The ODVA CIP specification (Vol 1 + Vol 2) is
//	publicly available; both the EtherNet/IP encapsulation
//	header (24 bytes LE) and the Common Packet Format are
//	tight, deterministic structures. The CIP service request /
//	response shape is also fixed: 1-byte service code (high
//	bit = response indicator) + per-direction body. No crypto
//	at the parse layer; CIP Security is a separate decoder.
//
// What this package covers
//
//   - **EtherNet/IP encapsulation header** (ODVA CIP Vol 2 §2.3,
//     24 bytes, little-endian):
//
//   - bytes 0-1: **Command** (uint16 LE).
//
//   - bytes 2-3: Length (uint16 LE; bytes of data following
//     this 24-byte header).
//
//   - bytes 4-7: Session Handle (uint32 LE; allocated by
//     server on RegisterSession; 0 on commands that don't
//     require a session).
//
//   - bytes 8-11: Status (uint32 LE; per-Command decode).
//
//   - bytes 12-19: Sender Context (8 bytes; opaque
//     correlation cookie the originator can use to pair
//     requests and responses).
//
//   - bytes 20-23: Options (uint32 LE; reserved = 0).
//
//   - **9-entry Command name table** (ODVA CIP Vol 2 §2.3.2):
//     0x0000 `NOP` / 0x0004 `ListServices` / 0x0063 `ListIdentity`
//     / 0x0064 `ListInterfaces` / 0x0065 `RegisterSession` /
//     0x0066 `UnRegisterSession` / 0x006F `SendRRData` (CIP
//     request/reply over TCP) / 0x0070 `SendUnitData` (CIP class
//     1 connected over UDP) / 0x0072 `IndicateStatus` / 0x0073
//     `Cancel`.
//
//   - **7-entry Status name table**: 0x0000 `Success` / 0x0001
//     `Invalid_or_Unsupported_Command` / 0x0002
//     `Insufficient_Memory` / 0x0003 `Incorrect_Data` / 0x0064
//     `Invalid_Session_Handle` / 0x0065 `Invalid_Length` /
//     0x0069 `Unsupported_Protocol_Version`.
//
//   - **Common Packet Format walker** for `SendRRData` (0x006F)
//     and `SendUnitData` (0x0070): after the encapsulation
//     header these commands carry a 6-byte Interface Handle +
//     Timeout preamble, then `Item Count` (uint16 LE) followed
//     by `Item Count` items. Each item is laid out as `Type ID`
//     (uint16 LE) + `Length` (uint16 LE) + `Length` bytes of
//     data.
//
//   - **8-entry Common Packet Format item type name table**:
//     0x0000 `Null` / 0x000C `ListIdentity_item` / 0x00A1
//     `Connected_Address` (carries 4-byte Connection ID) /
//     0x00B1 `Connected_Data` (CIP message under a connection)
//     / 0x00B2 `Unconnected_Data` (CIP message without a
//     connection — the common shape for SendRRData) / 0x0100
//     `ListServices_response` / 0x8000 `Sockaddr_O2T` (target-
//     to-originator address) / 0x8001 `Sockaddr_T2O`
//     (originator-to-target address).
//
//   - **CIP message decoder** for `Unconnected_Data` (0x00B2)
//     items (ODVA CIP Vol 1 §2-4):
//
//   - byte 0: Service Code (the high bit 0x80 indicates a
//     response; the low 7 bits hold the original service
//     code).
//
//   - For requests: byte 1 = Request Path Size in 16-bit
//     words; bytes 2.. = EPATH (segments); remainder =
//     service-specific request data.
//
//   - For responses: byte 1 = Reserved (= 0); byte 2 =
//     General Status; byte 3 = Additional Status Size in
//     16-bit words; bytes 4.. = Additional Status; remainder
//     = service-specific response data.
//
//   - **30+ entry CIP Service Code name table** (selected
//     high-runners from ODVA CIP Vol 1 §Appendix A): 0x01
//     `Get_Attributes_All` / 0x02 `Set_Attributes_All` / 0x03
//     `Get_Attribute_List` / 0x04 `Set_Attribute_List` / 0x05
//     `Reset` / 0x06 `Start` / 0x07 `Stop` / 0x08 `Create` /
//     0x09 `Delete` / 0x0A `Multiple_Service_Packet` / 0x0D
//     `Apply_Attributes` / 0x0E `Get_Attribute_Single` / 0x10
//     `Set_Attribute_Single` / 0x11 `Find_Next_Object_Instance`
//     / 0x4B `Execute_PCCC` (legacy DH+/SLC) / 0x4C `Read_Tag`
//     (Logix tag-based addressing) / 0x4D `Write_Tag` / 0x4E
//     `Read_Modify_Write_Tag` / 0x52 `Read_Tag_Fragmented` /
//     0x53 `Write_Tag_Fragmented` / 0x54 `Forward_Open` /
//     0x5B `Forward_Close` / 0x5F `Unconnected_Send`.
//
//   - **20+ entry CIP General Status name table** (ODVA CIP
//     Vol 1 §Appendix B): 0x00 `Success` / 0x01
//     `Connection_Failure` / 0x02 `Resource_Unavailable` /
//     0x03 `Invalid_Parameter_Value` / 0x04 `Path_Segment_Error`
//     / 0x05 `Path_Destination_Unknown` / 0x06 `Partial_Transfer`
//     / 0x07 `Connection_Lost` / 0x08 `Service_Not_Supported` /
//     0x09 `Invalid_Attribute_Value` / 0x0A
//     `Attribute_List_Error` / 0x0B `Already_In_Requested_Mode`
//     / 0x0C `Object_State_Conflict` / 0x0D `Object_Already_Exists`
//     / 0x0E `Attribute_Not_Settable` / 0x0F `Privilege_Violation`
//     / 0x10 `Device_State_Conflict` / 0x11 `Reply_Data_Too_Large`
//     / 0x13 `Not_Enough_Data` / 0x14 `Attribute_Not_Supported`
//     / 0x15 `Too_Much_Data` / 0x16 `Object_Does_Not_Exist`.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Network framing** — feed EtherNet/IP bytes after the
//     TCP-segment or UDP-datagram header strip (default TCP
//     port 44818 explicit, UDP 2222 implicit / class 1).
//   - **EPATH segment walker** — the Request Path bytes inside
//     CIP requests carry segments (Logical, Symbolic, Network,
//     ANSI Extended Symbolic) per ODVA CIP Vol 1 §C-1; the
//     decoder surfaces the EPATH bytes via `cip_path_hex` for
//     future per-segment walkers (Class/Instance/Attribute
//     resolver, ANSI Extended Symbolic tag-name extraction).
//   - **Per-service request/response decoder** — Read_Tag /
//     Write_Tag value-type encoding (BOOL/SINT/INT/DINT/REAL/
//     STRING/UDT), Forward_Open connection parameters
//     (Connection_Serial_Number, T_O / O_T RPI, Network
//     Connection Parameters), Multiple_Service_Packet bundle
//     unpacking; surfaced as `cip_body_hex` for downstream
//     per-service walkers.
//   - **CIP Security** — ODVA CIP Security is a separate
//     decoder; the encapsulation layer transports it
//     transparently but the body is encrypted and
//     authenticated outside this layer.
//   - **Class 1 connection state-machine** — Forward_Open
//     negotiates an O→T and T→O connection that subsequently
//     carries class 1 I/O scans under the SendUnitData command;
//     reasoning about the connection state (RPI compliance,
//     COS triggers, timeout multipliers) is higher-level.
package enip

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the structured decode of an EtherNet/IP encapsulation
// packet plus any per-Command body interpretation.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// Encapsulation header (24 bytes LE)
	Command          int    `json:"command"`
	CommandName      string `json:"command_name"`
	Length           int    `json:"length"`
	SessionHandle    uint32 `json:"session_handle"`
	Status           uint32 `json:"status"`
	StatusName       string `json:"status_name"`
	SenderContextHex string `json:"sender_context_hex"`
	Options          uint32 `json:"options"`

	// SendRRData / SendUnitData common preamble (6 bytes)
	InterfaceHandle uint32 `json:"interface_handle,omitempty"`
	Timeout         int    `json:"timeout,omitempty"`

	// Common Packet Format
	ItemCount int    `json:"item_count,omitempty"`
	Items     []Item `json:"items,omitempty"`

	// Raw bytes past the parsed structure (for downstream
	// per-Command / per-Service walkers).
	PayloadHex string `json:"payload_hex,omitempty"`
}

// Item is one entry in the Common Packet Format item list.
type Item struct {
	TypeID   int    `json:"type_id"`
	TypeName string `json:"type_name"`
	Length   int    `json:"length"`
	DataHex  string `json:"data_hex,omitempty"`

	// CIP message decode (Unconnected_Data 0x00B2 only).
	CIP *CIPMessage `json:"cip,omitempty"`
}

// CIPMessage is the per-Unconnected_Data CIP request / response.
type CIPMessage struct {
	ServiceCode        int    `json:"service_code"`
	ServiceName        string `json:"service_name"`
	IsResponse         bool   `json:"is_response"`
	PathSizeWords      int    `json:"path_size_words,omitempty"`
	PathHex            string `json:"path_hex,omitempty"`
	GeneralStatus      int    `json:"general_status,omitempty"`
	GeneralStatusName  string `json:"general_status_name,omitempty"`
	AddStatusSizeWords int    `json:"additional_status_size_words,omitempty"`
	AddStatusHex       string `json:"additional_status_hex,omitempty"`
	BodyHex            string `json:"body_hex,omitempty"`
}

// Decode parses an EtherNet/IP encapsulation packet (starting at
// the Command bytes) from a hex string. Separators (':' '-' '_'
// whitespace) are tolerated; a leading '0x' prefix is stripped.
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
	if len(b) < 24 {
		return nil, fmt.Errorf("EtherNet/IP packet truncated (%d bytes; need ≥24 for encapsulation header)",
			len(b))
	}

	r := &Result{
		TotalBytes:       len(b),
		Command:          int(binary.LittleEndian.Uint16(b[0:2])),
		Length:           int(binary.LittleEndian.Uint16(b[2:4])),
		SessionHandle:    binary.LittleEndian.Uint32(b[4:8]),
		Status:           binary.LittleEndian.Uint32(b[8:12]),
		SenderContextHex: strings.ToUpper(hex.EncodeToString(b[12:20])),
		Options:          binary.LittleEndian.Uint32(b[20:24]),
	}
	r.CommandName = commandName(r.Command)
	r.StatusName = statusName(r.Status)

	body := b[24:]
	switch r.Command {
	case 0x006F, 0x0070:
		// SendRRData / SendUnitData: 4-byte Interface Handle +
		// 2-byte Timeout + CPF.
		if len(body) < 6 {
			r.PayloadHex = strings.ToUpper(hex.EncodeToString(body))
			return r, nil
		}
		r.InterfaceHandle = binary.LittleEndian.Uint32(body[0:4])
		r.Timeout = int(binary.LittleEndian.Uint16(body[4:6]))
		cpf := body[6:]
		if len(cpf) < 2 {
			return r, nil
		}
		r.ItemCount = int(binary.LittleEndian.Uint16(cpf[0:2]))
		off := 2
		for i := 0; i < r.ItemCount && off+4 <= len(cpf); i++ {
			typeID := int(binary.LittleEndian.Uint16(cpf[off : off+2]))
			itemLen := int(binary.LittleEndian.Uint16(cpf[off+2 : off+4]))
			if off+4+itemLen > len(cpf) {
				break
			}
			itemData := cpf[off+4 : off+4+itemLen]
			it := Item{
				TypeID:   typeID,
				TypeName: itemTypeName(typeID),
				Length:   itemLen,
				DataHex:  strings.ToUpper(hex.EncodeToString(itemData)),
			}
			if typeID == 0x00B2 && itemLen > 0 {
				it.CIP = decodeCIPMessage(itemData)
			}
			r.Items = append(r.Items, it)
			off += 4 + itemLen
		}
	default:
		if len(body) > 0 {
			r.PayloadHex = strings.ToUpper(hex.EncodeToString(body))
		}
	}
	return r, nil
}

// decodeCIPMessage parses a single CIP message body (the Data
// bytes of an Unconnected_Data item).
func decodeCIPMessage(b []byte) *CIPMessage {
	if len(b) < 1 {
		return nil
	}
	m := &CIPMessage{
		ServiceCode: int(b[0] & 0x7F),
		IsResponse:  b[0]&0x80 != 0,
	}
	m.ServiceName = cipServiceName(m.ServiceCode)
	if m.IsResponse {
		if len(b) < 4 {
			return m
		}
		// b[1] = Reserved
		m.GeneralStatus = int(b[2])
		m.GeneralStatusName = cipGeneralStatusName(m.GeneralStatus)
		m.AddStatusSizeWords = int(b[3])
		addEnd := 4 + m.AddStatusSizeWords*2
		if addEnd > len(b) {
			return m
		}
		if m.AddStatusSizeWords > 0 {
			m.AddStatusHex = strings.ToUpper(hex.EncodeToString(b[4:addEnd]))
		}
		if addEnd < len(b) {
			m.BodyHex = strings.ToUpper(hex.EncodeToString(b[addEnd:]))
		}
		return m
	}
	// Request shape.
	if len(b) < 2 {
		return m
	}
	m.PathSizeWords = int(b[1])
	pathEnd := 2 + m.PathSizeWords*2
	if pathEnd > len(b) {
		return m
	}
	if m.PathSizeWords > 0 {
		m.PathHex = strings.ToUpper(hex.EncodeToString(b[2:pathEnd]))
	}
	if pathEnd < len(b) {
		m.BodyHex = strings.ToUpper(hex.EncodeToString(b[pathEnd:]))
	}
	return m
}

func commandName(c int) string {
	switch c {
	case 0x0000:
		return "NOP"
	case 0x0004:
		return "ListServices"
	case 0x0063:
		return "ListIdentity"
	case 0x0064:
		return "ListInterfaces"
	case 0x0065:
		return "RegisterSession"
	case 0x0066:
		return "UnRegisterSession"
	case 0x006F:
		return "SendRRData"
	case 0x0070:
		return "SendUnitData"
	case 0x0072:
		return "IndicateStatus"
	case 0x0073:
		return "Cancel"
	}
	return fmt.Sprintf("uncatalogued command 0x%04X", c)
}

func statusName(s uint32) string {
	switch s {
	case 0x0000:
		return "Success"
	case 0x0001:
		return "Invalid_or_Unsupported_Command"
	case 0x0002:
		return "Insufficient_Memory"
	case 0x0003:
		return "Incorrect_Data"
	case 0x0064:
		return "Invalid_Session_Handle"
	case 0x0065:
		return "Invalid_Length"
	case 0x0069:
		return "Unsupported_Protocol_Version"
	}
	return fmt.Sprintf("uncatalogued status 0x%08X", s)
}

func itemTypeName(t int) string {
	switch t {
	case 0x0000:
		return "Null"
	case 0x000C:
		return "ListIdentity_item"
	case 0x00A1:
		return "Connected_Address"
	case 0x00B1:
		return "Connected_Data"
	case 0x00B2:
		return "Unconnected_Data"
	case 0x0100:
		return "ListServices_response"
	case 0x8000:
		return "Sockaddr_O2T"
	case 0x8001:
		return "Sockaddr_T2O"
	}
	return fmt.Sprintf("uncatalogued item type 0x%04X", t)
}

func cipServiceName(s int) string {
	switch s {
	case 0x01:
		return "Get_Attributes_All"
	case 0x02:
		return "Set_Attributes_All"
	case 0x03:
		return "Get_Attribute_List"
	case 0x04:
		return "Set_Attribute_List"
	case 0x05:
		return "Reset"
	case 0x06:
		return "Start"
	case 0x07:
		return "Stop"
	case 0x08:
		return "Create"
	case 0x09:
		return "Delete"
	case 0x0A:
		return "Multiple_Service_Packet"
	case 0x0D:
		return "Apply_Attributes"
	case 0x0E:
		return "Get_Attribute_Single"
	case 0x10:
		return "Set_Attribute_Single"
	case 0x11:
		return "Find_Next_Object_Instance"
	case 0x4B:
		return "Execute_PCCC"
	case 0x4C:
		return "Read_Tag"
	case 0x4D:
		return "Write_Tag"
	case 0x4E:
		return "Read_Modify_Write_Tag"
	case 0x52:
		return "Read_Tag_Fragmented"
	case 0x53:
		return "Write_Tag_Fragmented"
	case 0x54:
		return "Forward_Open"
	case 0x5B:
		return "Forward_Close"
	case 0x5F:
		return "Unconnected_Send"
	}
	return fmt.Sprintf("uncatalogued service 0x%02X", s)
}

func cipGeneralStatusName(s int) string {
	switch s {
	case 0x00:
		return "Success"
	case 0x01:
		return "Connection_Failure"
	case 0x02:
		return "Resource_Unavailable"
	case 0x03:
		return "Invalid_Parameter_Value"
	case 0x04:
		return "Path_Segment_Error"
	case 0x05:
		return "Path_Destination_Unknown"
	case 0x06:
		return "Partial_Transfer"
	case 0x07:
		return "Connection_Lost"
	case 0x08:
		return "Service_Not_Supported"
	case 0x09:
		return "Invalid_Attribute_Value"
	case 0x0A:
		return "Attribute_List_Error"
	case 0x0B:
		return "Already_In_Requested_Mode"
	case 0x0C:
		return "Object_State_Conflict"
	case 0x0D:
		return "Object_Already_Exists"
	case 0x0E:
		return "Attribute_Not_Settable"
	case 0x0F:
		return "Privilege_Violation"
	case 0x10:
		return "Device_State_Conflict"
	case 0x11:
		return "Reply_Data_Too_Large"
	case 0x13:
		return "Not_Enough_Data"
	case 0x14:
		return "Attribute_Not_Supported"
	case 0x15:
		return "Too_Much_Data"
	case 0x16:
		return "Object_Does_Not_Exist"
	}
	return fmt.Sprintf("uncatalogued status 0x%02X", s)
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
