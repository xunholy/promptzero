// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ethercat decodes EtherCAT (Ethernet for Control Automation
// Technology, IEC 61158) frames — the real-time industrial Ethernet
// fieldbus dominating factory automation, motion control, and robotics
// (Beckhoff TwinCAT, and the many EtherCAT-slave drives, I/O terminals,
// and servo controllers built on the ET1100/ET1200 ESC ASICs).
//
// EtherCAT runs directly on Ethernet (EtherType 0x88A4) or, less
// commonly, tunnelled in UDP/34980. A master emits one Ethernet frame
// containing an EtherCAT header and a chain of datagrams; each datagram
// is processed on-the-fly by every slave as the frame passes through
// the daisy-chain, and the working counter is incremented by each slave
// that handled it. There is no authentication or encryption on the wire
// — a capture reveals the full process image and addressing, which is
// exactly what an OT pentester inspects.
//
// # Wrap-vs-native judgement
//
// Native. The EtherCAT data-link encoding is publicly documented (IEC
// 61158 / ETG.1000). The frame is a 2-byte EtherCAT header (11-bit
// length + 4-bit type) followed by one or more fixed-format datagrams,
// each a 10-byte header (command, index, address, length+flags, IRQ),
// a length-counted data block, and a 2-byte working counter. Command
// and addressing dispatch is a set of small lookup tables.
//
// # What this package covers
//
//   - EtherCAT header: 11-bit Length, 4-bit Type (1 = command/DLPDU,
//     4 = network variables, 5 = mailbox) with a name table.
//   - Datagram chain walk: per-datagram Command (16-entry table:
//     NOP / APRD / APWR / APRW / FPRD / FPWR / FPRW / BRD / BWR / BRW
//     / LRD / LWR / LRW / ARMW / FRMW), Index, addressing decode
//     (position+offset ADP/ADO for auto-increment & configured-address
//     commands, 32-bit logical address for the logical commands),
//     11-bit data length with the Circulating and More-follows (M)
//     flags, IRQ, the data block (surfaced as hex), and the Working
//     Counter.
//   - The "more datagrams follow" (M) bit chains the walk and is
//     validated against the remaining buffer.
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - The Ethernet / UDP framing: feed the EtherCAT payload (the bytes
//     after EtherType 0x88A4, or the UDP/34980 payload).
//   - Mailbox (Type 5) protocol contents — CoE (CANopen over EtherCAT),
//     EoE, FoE, SoE: the datagram data block is surfaced as hex; the
//     mailbox sub-protocols are a separate walker.
//   - Process-data interpretation: the data block is the raw process
//     image / register payload; mapping it to objects needs the slave's
//     ESI/object dictionary and is out of scope.
package ethercat

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Frame is the decoded view of an EtherCAT frame.
type Frame struct {
	HexInput    string      `json:"hex_input"`
	Length      int         `json:"length"`
	Type        int         `json:"type"`
	TypeName    string      `json:"type_name"`
	Datagrams   []*Datagram `json:"datagrams,omitempty"`
	DatagramHex string      `json:"undecoded_body_hex,omitempty"`
	Notes       []string    `json:"notes,omitempty"`
}

// Datagram is one EtherCAT command datagram.
type Datagram struct {
	Index          int     `json:"index"`
	Command        int     `json:"command"`
	CommandName    string  `json:"command_name"`
	WorkingCmdIdx  int     `json:"datagram_index"`
	AddressMode    string  `json:"address_mode"`
	ADP            *int    `json:"adp,omitempty"`
	ADO            *int    `json:"ado,omitempty"`
	LogicalAddress *uint32 `json:"logical_address,omitempty"`
	DataLength     int     `json:"data_length"`
	Circulating    bool    `json:"circulating,omitempty"`
	MoreFollows    bool    `json:"more_follows,omitempty"`
	IRQ            int     `json:"irq"`
	DataHex        string  `json:"data_hex,omitempty"`
	WorkingCounter int     `json:"working_counter"`
}

// Decode parses a hex-encoded EtherCAT frame.
func Decode(hexBlob string) (*Frame, error) {
	b, err := parseHex(hexBlob)
	if err != nil {
		return nil, err
	}
	return DecodeBytes(b)
}

// DecodeBytes parses a raw EtherCAT frame (the payload after EtherType
// 0x88A4, or the UDP/34980 payload).
func DecodeBytes(b []byte) (*Frame, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("ethercat: frame too short (%d bytes) — the header alone is 2 bytes", len(b))
	}
	hdr := binary.LittleEndian.Uint16(b[0:2])
	length := int(hdr & 0x07FF) // bits 0-10
	typ := int((hdr >> 12) & 0x0F)
	f := &Frame{
		HexInput: strings.ToUpper(hex.EncodeToString(b)),
		Length:   length,
		Type:     typ,
		TypeName: headerTypeName(typ),
	}

	body := b[2:]
	// The header Length counts the bytes of the datagram area. A length
	// exceeding the buffer is a truncation/garbage marker — clamp the
	// walk to what is actually present and note it.
	if length > len(body) {
		f.Notes = append(f.Notes,
			fmt.Sprintf("header length %d exceeds %d available body bytes; walking available only",
				length, len(body)))
	} else if length < len(body) {
		// Trailing bytes beyond the declared length (e.g. Ethernet
		// padding to the 60-byte minimum) — ignore them in the walk.
		body = body[:length]
	}

	// Only Type 1 (command/DLPDU) carries the datagram chain we decode.
	if typ != 1 {
		if len(body) > 0 {
			f.DatagramHex = strings.ToUpper(hex.EncodeToString(body))
		}
		return f, nil
	}

	off := 0
	idx := 0
	for off+10 <= len(body) {
		dg, used, more := decodeDatagram(body[off:], idx)
		if dg == nil {
			break
		}
		f.Datagrams = append(f.Datagrams, dg)
		off += used
		idx++
		if !more {
			break
		}
	}
	if off < len(body) {
		f.DatagramHex = strings.ToUpper(hex.EncodeToString(body[off:]))
	}
	return f, nil
}

// decodeDatagram decodes one datagram at the front of b and returns it,
// the number of bytes consumed, and whether the More-follows bit is
// set. Returns (nil, 0, false) when the datagram cannot fit.
func decodeDatagram(b []byte, index int) (*Datagram, int, bool) {
	// Header: Cmd(1) Idx(1) Address(4) LenFlags(2) IRQ(2) = 10 bytes.
	if len(b) < 10 {
		return nil, 0, false
	}
	cmd := int(b[0])
	lenFlags := binary.LittleEndian.Uint16(b[6:8])
	dataLen := int(lenFlags & 0x07FF) // bits 0-10
	circulating := lenFlags&0x4000 != 0
	more := lenFlags&0x8000 != 0
	irq := int(binary.LittleEndian.Uint16(b[8:10]))

	// Total datagram size = 10 (header) + dataLen + 2 (working counter).
	total := 10 + dataLen + 2
	if total > len(b) {
		// Truncated — cannot safely read the data block + WKC.
		return nil, 0, false
	}

	dg := &Datagram{
		Index:         index,
		Command:       cmd,
		CommandName:   commandName(cmd),
		WorkingCmdIdx: int(b[1]),
		DataLength:    dataLen,
		Circulating:   circulating,
		MoreFollows:   more,
		IRQ:           irq,
	}

	// Address interpretation depends on the command family.
	switch cmd {
	case 10, 11, 12: // LRD, LWR, LRW — 32-bit logical address.
		la := binary.LittleEndian.Uint32(b[2:6])
		dg.AddressMode = "logical (32-bit)"
		dg.LogicalAddress = &la
	default:
		// Position / configured addressing: ADP (16-bit) + ADO (16-bit).
		adp := int(binary.LittleEndian.Uint16(b[2:4]))
		ado := int(binary.LittleEndian.Uint16(b[4:6]))
		dg.AddressMode = "position+offset (ADP/ADO)"
		dg.ADP = &adp
		dg.ADO = &ado
	}

	if dataLen > 0 {
		dg.DataHex = strings.ToUpper(hex.EncodeToString(b[10 : 10+dataLen]))
	}
	dg.WorkingCounter = int(binary.LittleEndian.Uint16(b[10+dataLen : 10+dataLen+2]))

	return dg, total, more
}

func parseHex(s string) ([]byte, error) {
	s = stripSeparators(s)
	if s == "" {
		return nil, fmt.Errorf("ethercat: empty hex input")
	}
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("ethercat: invalid hex: %w", err)
	}
	return b, nil
}

func stripSeparators(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', ':', '-', '_':
			continue
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
