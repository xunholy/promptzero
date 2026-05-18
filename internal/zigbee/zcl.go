package zigbee

// zcl.go — Zigbee Cluster Library (ZCL) frame dissector. ZCL is
// the application layer that sits on top of APS in the Zigbee
// stack: MAC (IEEE 802.15.4) → NWK → APS → ZCL. This is where
// real application commands live — On/Off, Level Control,
// Temperature Measurement, Battery, Identify, etc.
//
// Wrap-vs-native judgement: same as the rest of the Zigbee
// stack — public spec (Zigbee Cluster Library Specification
// 07-5123-08), bit-level walker, pure offline decode.
// Operators chain ieee802154_decode → zigbee_nwk_decode →
// zigbee_aps_decode → zigbee_zcl_decode for full Zigbee frame
// analysis from the radio bytes up to the cluster command.

import (
	"encoding/binary"
	"fmt"
)

// ZCLFrameType is the 2-bit frame-type field at bits 1..0 of
// the ZCL frame control byte.
type ZCLFrameType int

const (
	// ZCLFrameTypeProfileWide — profile-wide commands (Read
	// Attributes / Report Attributes / Default Response / etc.).
	// These commands apply to any cluster.
	ZCLFrameTypeProfileWide ZCLFrameType = 0
	// ZCLFrameTypeClusterSpecific — commands defined by the
	// specific cluster (On/Off has Toggle / On / Off; Level
	// Control has Move To Level; etc.).
	ZCLFrameTypeClusterSpecific ZCLFrameType = 1
)

func (t ZCLFrameType) String() string {
	switch t {
	case ZCLFrameTypeProfileWide:
		return "Profile-wide"
	case ZCLFrameTypeClusterSpecific:
		return "Cluster-specific"
	}
	return "Reserved"
}

// ZCLFrameControl is the decoded 8-bit ZCL Frame Control byte.
type ZCLFrameControl struct {
	Raw int `json:"raw"`
	// FrameType (bits 1..0).
	FrameType     int    `json:"frame_type"`
	FrameTypeName string `json:"frame_type_name"`
	// ManufacturerSpecific (bit 2) — when set, a 2-byte
	// manufacturer code follows the frame control.
	ManufacturerSpecific bool `json:"manufacturer_specific"`
	// Direction (bit 3) — 0 = client→server, 1 = server→client.
	// The "server" is typically the endpoint hosting the cluster
	// attributes; the "client" is the one issuing commands.
	Direction     int    `json:"direction"`
	DirectionName string `json:"direction_name"`
	// DisableDefaultResponse (bit 4) — when set, the recipient
	// suppresses the automatic Default Response that would
	// otherwise be sent for unrecognised / errored commands.
	DisableDefaultResponse bool `json:"disable_default_response"`
}

// ZCLFrame is the top-level decoded ZCL frame.
type ZCLFrame struct {
	FrameControl ZCLFrameControl `json:"frame_control"`
	// ManufacturerCode is populated when the Manufacturer
	// Specific flag is set (2 bytes after the frame control).
	ManufacturerCode    string `json:"manufacturer_code,omitempty"`
	ManufacturerCodeRaw int    `json:"manufacturer_code_raw,omitempty"`
	// TransactionSequenceNumber is the 1-byte sequence number
	// (links request → response across the ZCL exchange).
	TransactionSequenceNumber int `json:"transaction_sequence_number"`
	// CommandID is the 1-byte command identifier.
	CommandID    int    `json:"command_id"`
	CommandIDHex string `json:"command_id_hex"`
	// CommandName is the canonical command name from the
	// profile-wide table (when FrameType=Profile-wide and the
	// command is documented). Empty for cluster-specific
	// commands (those need the cluster ID for context, which
	// lives in the APS layer).
	CommandName string `json:"command_name,omitempty"`
	// PayloadHex is the command payload bytes (uppercase hex).
	PayloadHex string `json:"payload_hex,omitempty"`
}

// DecodeZCL parses a hex-encoded ZCL frame. Tolerates ':' /
// '-' / '_' / whitespace separators.
func DecodeZCL(hexBlob string) (ZCLFrame, error) {
	cleaned := stripSeparators(hexBlob)
	if cleaned == "" {
		return ZCLFrame{}, fmt.Errorf("zigbee: empty ZCL input")
	}
	b, err := hexDecode(cleaned)
	if err != nil {
		return ZCLFrame{}, fmt.Errorf("zigbee: invalid hex: %w", err)
	}
	return DecodeZCLBytes(b)
}

// DecodeZCLBytes is the byte-slice variant of DecodeZCL.
func DecodeZCLBytes(b []byte) (ZCLFrame, error) {
	const minLen = 3 // FC(1) + TSN(1) + CommandID(1)
	if len(b) < minLen {
		return ZCLFrame{}, fmt.Errorf("zigbee: ZCL frame %d bytes < %d-byte minimum",
			len(b), minLen)
	}
	fc := decodeZCLFrameControl(b[0])
	out := ZCLFrame{FrameControl: fc}
	off := 1
	if fc.ManufacturerSpecific {
		if off+2 > len(b) {
			return out, fmt.Errorf("zigbee: ZCL manufacturer code truncated")
		}
		mc := binary.LittleEndian.Uint16(b[off : off+2])
		out.ManufacturerCode = fmt.Sprintf("%04X", mc)
		out.ManufacturerCodeRaw = int(mc)
		off += 2
	}
	if off >= len(b) {
		return out, fmt.Errorf("zigbee: ZCL transaction sequence number truncated")
	}
	out.TransactionSequenceNumber = int(b[off])
	off++
	if off >= len(b) {
		return out, fmt.Errorf("zigbee: ZCL command ID truncated")
	}
	cid := b[off]
	out.CommandID = int(cid)
	out.CommandIDHex = fmt.Sprintf("%02X", cid)
	off++
	// Profile-wide commands have a documented catalog; cluster-
	// specific commands need the cluster ID for context (which
	// lives in the APS layer — operators chain the two).
	if ZCLFrameType(fc.FrameType) == ZCLFrameTypeProfileWide {
		if name, ok := profileWideCommands[cid]; ok {
			out.CommandName = name
		}
	}
	if off < len(b) {
		out.PayloadHex = hexString(b[off:])
	}
	return out, nil
}

// decodeZCLFrameControl unpacks the 8-bit ZCL Frame Control byte.
func decodeZCLFrameControl(b byte) ZCLFrameControl {
	ft := int(b & 0x03)
	dir := int((b >> 3) & 0x01)
	dirName := "Client → Server"
	if dir == 1 {
		dirName = "Server → Client"
	}
	return ZCLFrameControl{
		Raw:                    int(b),
		FrameType:              ft,
		FrameTypeName:          ZCLFrameType(ft).String(),
		ManufacturerSpecific:   b&0x04 != 0,
		Direction:              dir,
		DirectionName:          dirName,
		DisableDefaultResponse: b&0x10 != 0,
	}
}

// profileWideCommands maps the documented ZCL profile-wide
// command IDs to their canonical names per ZCL Specification
// 07-5123-08 Table 2-3.
var profileWideCommands = map[byte]string{
	0x00: "Read Attributes",
	0x01: "Read Attributes Response",
	0x02: "Write Attributes",
	0x03: "Write Attributes Undivided",
	0x04: "Write Attributes Response",
	0x05: "Write Attributes No Response",
	0x06: "Configure Reporting",
	0x07: "Configure Reporting Response",
	0x08: "Read Reporting Configuration",
	0x09: "Read Reporting Configuration Response",
	0x0A: "Report Attributes",
	0x0B: "Default Response",
	0x0C: "Discover Attributes",
	0x0D: "Discover Attributes Response",
	0x0E: "Read Attributes Structured",
	0x0F: "Write Attributes Structured",
	0x10: "Write Attributes Structured Response",
	0x11: "Discover Commands Received",
	0x12: "Discover Commands Received Response",
	0x13: "Discover Commands Generated",
	0x14: "Discover Commands Generated Response",
	0x15: "Discover Attributes Extended",
	0x16: "Discover Attributes Extended Response",
}
