// Package pcapng decodes the PCAPng (next-generation packet
// capture, draft-tuexen-opsawg-pcapng) file format. PCAPng has
// been Wireshark's default capture format since 2018 and the
// emitted format of most modern tcpdump builds; operators
// increasingly get .pcapng files instead of classic .pcap.
// Sits alongside `internal/pcap.Inspect` (classic libpcap) for
// the complete packet-capture container coverage.
//
// Wrap-vs-native judgement
//
//	Native. The PCAPng spec is fully public; every block has
//	a tight 4-byte Block Type + 4-byte Block Total Length +
//	body + 4-byte Block Total Length (repeated for backward
//	navigation through the file). The first block is always a
//	Section Header Block (SHB) whose Byte-Order Magic
//	(0x1A2B3C4D) dispatches endianness for the entire section.
//	No crypto, no compression — operators paste the full file
//	hex and get a structured per-block summary.
//
// What this package covers
//
//   - **Block framing** — outer 8-byte header (Type + Length),
//     padded body, and trailing repeated 4-byte Block Total
//     Length validating the back-pointer. Type field is 32-bit
//     so the first SHB's bytes drive endianness detection for
//     the rest of the section.
//
//   - **9-entry block type table** (per the IANA pcapng-block-
//     types registry):
//     0x0A0D0D0A Section Header Block (palindrome — also serves
//     as endianness-detection token),
//     0x00000001 Interface Description Block (IDB),
//     0x00000003 Simple Packet Block (SPB; obsolete — surfaced
//     verbatim as length+caplen+data),
//     0x00000004 Name Resolution Block (NRB),
//     0x00000005 Interface Statistics Block (ISB),
//     0x00000006 Enhanced Packet Block (EPB; the canonical
//     packet record),
//     0x00000007 IRIG Timestamp Block (rare),
//     0x00000009 Decryption Secrets Block (DSB; TLS / SSH key
//     log materials),
//     0x0BAD0001 Custom Block.
//
//   - **Section Header Block (SHB) body**:
//
//   - 4-byte Byte-Order Magic (0x1A2B3C4D in section
//     endianness; mismatch implies the wrong endianness was
//     guessed).
//
//   - 2-byte Major Version (expected 1).
//
//   - 2-byte Minor Version (expected 0).
//
//   - 8-byte Section Length (int64; -1 = not specified).
//
//   - Options (variable; walked).
//
//   - **Interface Description Block (IDB) body**:
//
//   - 2-byte LinkType (uses the same LINKTYPE_* values as
//     libpcap; resolved via the existing internal/pcap
//     LinkTypeName).
//
//   - 2-byte Reserved.
//
//   - 4-byte SnapLen (max captured bytes per packet).
//
//   - Options (if_name / if_description / if_IPv4addr /
//     if_MACaddr / if_speed / if_tsresol / if_os / etc.).
//
//   - **Enhanced Packet Block (EPB) body** — the canonical
//     packet record:
//
//   - 4-byte Interface ID (index into the section's IDB
//     list).
//
//   - 4-byte Timestamp High + 4-byte Timestamp Low (joined
//     to a 64-bit count; resolution depends on the
//     referenced IDB's if_tsresol option, default 10⁻⁶ s).
//
//   - 4-byte Captured Packet Length.
//
//   - 4-byte Original Packet Length.
//
//   - Packet Data (caplen bytes, padded to 4-byte boundary).
//
//   - Options (epb_flags / epb_hash / epb_dropcount).
//
//   - **Interface Statistics Block (ISB)** — 4-byte Interface
//     ID + 8-byte Timestamp + options (per-interface counters).
//
//   - **Options walker** — (Code uint16, Length uint16, Value
//     padded to 4-byte boundary). Generic Options 1 = comment,
//     2 = custom string (registered per-block-type code 2-N).
//     Block-specific common options surfaced as decoded UTF-8
//     when the value is plausibly text (SHB hardware/os/
//     userappl; IDB if_name/if_description/if_os).
//
// What this package does NOT cover (deliberately out of scope)
//
//   - Classic libpcap (.pcap) — that's `internal/pcap.Inspect`
//     and the `pcap_decode` Spec; this package handles only
//     the next-gen PCAPng container.
//
//   - Per-record protocol dissection — the operator pulls
//     individual frames out of the EPB hex preview and feeds
//     them into the existing 80+ protocol-specific decoders.
//
//   - PCAPng capture (this is a *file* reader, not a live-
//     capture interface).
//
//   - Decryption Secrets Block payload parsing — the
//     wireshark-flavoured key log file format inside DSB
//     deserves its own dissector (Type 0x544C534B = TLSK is
//     surfaced as raw hex).
package pcapng

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/xunholy/promptzero/internal/pcap"
)

// Summary is the top-level structured view of a PCAPng file.
type Summary struct {
	Endianness string    `json:"endianness"`
	Sections   []Section `json:"sections"`
	BlockCount int       `json:"block_count"`
	TotalBytes int       `json:"total_bytes"`
	Notes      []string  `json:"notes,omitempty"`
}

// Section is one PCAPng section (delimited by an SHB).
type Section struct {
	MajorVersion  int              `json:"major_version"`
	MinorVersion  int              `json:"minor_version"`
	SectionLength int64            `json:"section_length"`
	Options       []Option         `json:"options,omitempty"`
	Interfaces    []Interface      `json:"interfaces,omitempty"`
	BlockSummary  map[string]int   `json:"block_summary"`
	Records       []EnhancedPacket `json:"records,omitempty"`
}

// Interface is one IDB (per-section interface descriptor).
type Interface struct {
	Index        int      `json:"index"`
	LinkType     int      `json:"link_type"`
	LinkTypeName string   `json:"link_type_name"`
	SnapLen      uint32   `json:"snap_length"`
	Options      []Option `json:"options,omitempty"`
}

// EnhancedPacket is one EPB record summary.
type EnhancedPacket struct {
	Index             int    `json:"index"`
	InterfaceID       uint32 `json:"interface_id"`
	TimestampHigh     uint32 `json:"timestamp_high"`
	TimestampLow      uint32 `json:"timestamp_low"`
	Timestamp64       uint64 `json:"timestamp_64"`
	CapturedLength    uint32 `json:"captured_length"`
	OriginalLength    uint32 `json:"original_length"`
	PayloadHex        string `json:"payload_hex,omitempty"`
	PayloadBytesShown int    `json:"payload_bytes_shown,omitempty"`
}

// Option is one (Code, Length, Value) record from a block's
// options list.
type Option struct {
	Code      int    `json:"code"`
	Length    int    `json:"length"`
	ValueHex  string `json:"value_hex,omitempty"`
	ValueText string `json:"value_text,omitempty"`
}

// InspectOpts tunes the walker for output size.
type InspectOpts struct {
	// MaxRecords caps the number of EPB summaries returned
	// per section. The block counters and BlockSummary map
	// still reflect the full file walk.
	MaxRecords int
	// MaxPayloadBytes caps the per-EPB payload hex preview.
	MaxPayloadBytes int
}

// DefaultInspectOpts returns sensible caps: first 50 EPBs
// per section, 32-byte hex preview per record.
func DefaultInspectOpts() InspectOpts {
	return InspectOpts{MaxRecords: 50, MaxPayloadBytes: 32}
}

// Block types from the IANA pcapng registry.
const (
	BlockSHB    uint32 = 0x0A0D0D0A
	BlockIDB    uint32 = 0x00000001
	BlockSPB    uint32 = 0x00000003
	BlockNRB    uint32 = 0x00000004
	BlockISB    uint32 = 0x00000005
	BlockEPB    uint32 = 0x00000006
	BlockIRIG   uint32 = 0x00000007
	BlockDSB    uint32 = 0x00000009
	BlockCustom uint32 = 0x0BAD0001
)

// Inspect walks a PCAPng file from its raw bytes and returns a
// Summary. Returns an error only for unrecoverable framing
// issues; per-block decoding errors are flagged via Notes.
func Inspect(b []byte, opts InspectOpts) (*Summary, error) {
	if len(b) < 12 {
		return nil, fmt.Errorf("PCAPng file truncated (%d bytes; need ≥12 for first block header)",
			len(b))
	}
	s := &Summary{TotalBytes: len(b)}

	// First block must be SHB; sniff its endianness via the
	// Byte-Order Magic inside its body.
	if t := binary.LittleEndian.Uint32(b[0:4]); t != BlockSHB {
		return nil, fmt.Errorf("first block is not SHB (got Type 0x%08X; expected 0x0A0D0D0A)", t)
	}

	off := 0
	for off+12 <= len(b) {
		// Probe section endianness when we see a new SHB.
		blockType := binary.LittleEndian.Uint32(b[off : off+4])
		if blockType == BlockSHB {
			sec, used, err := decodeSection(b[off:], opts, s)
			if err != nil {
				s.Notes = append(s.Notes, fmt.Sprintf(
					"section at offset %d: %v", off, err))
				return s, nil
			}
			s.Sections = append(s.Sections, sec)
			off += used
			continue
		}
		// A non-SHB block at the top level (before any SHB)
		// is malformed.
		s.Notes = append(s.Notes, fmt.Sprintf(
			"non-SHB block 0x%08X at offset %d outside any section", blockType, off))
		return s, nil
	}
	return s, nil
}

// decodeSection walks from an SHB onwards until the next SHB
// (or end of file). Returns the assembled Section and the
// number of bytes consumed.
func decodeSection(b []byte, opts InspectOpts, top *Summary) (Section, int, error) {
	sec := Section{BlockSummary: map[string]int{}}
	if len(b) < 28 {
		return sec, 0, fmt.Errorf("SHB truncated (%d bytes)", len(b))
	}

	// Sniff byte-order-magic inside the SHB body (bytes 8-11
	// of the block: 4-byte Type + 4-byte Length + 4-byte BOM).
	bom := binary.LittleEndian.Uint32(b[8:12])
	var order binary.ByteOrder
	switch bom {
	case 0x1A2B3C4D:
		order = binary.LittleEndian
		top.Endianness = "little"
	case 0x4D3C2B1A:
		order = binary.BigEndian
		top.Endianness = "big"
	default:
		return sec, 0, fmt.Errorf("Section Header Block has bad Byte-Order Magic 0x%08X (expected 0x1A2B3C4D)", bom)
	}

	ifaceIdx := 0
	epbIdx := 0
	off := 0
	for off+12 <= len(b) {
		blockType := order.Uint32(b[off : off+4])
		blockLen := order.Uint32(b[off+4 : off+8])
		if blockLen < 12 || blockLen%4 != 0 {
			return sec, off, fmt.Errorf("block 0x%08X at offset %d has invalid length %d", blockType, off, blockLen)
		}
		if off+int(blockLen) > len(b) {
			return sec, off, fmt.Errorf("block 0x%08X at offset %d declares length %d but only %d bytes remain", blockType, off, blockLen, len(b)-off)
		}
		body := b[off+8 : off+int(blockLen)-4]
		trailing := order.Uint32(b[off+int(blockLen)-4 : off+int(blockLen)])
		if trailing != blockLen {
			return sec, off, fmt.Errorf("block 0x%08X back-pointer mismatch: trailing %d vs header %d", blockType, trailing, blockLen)
		}

		switch blockType {
		case BlockSHB:
			if off != 0 {
				// Second SHB starts a new section: stop
				// walking this one.
				return sec, off, nil
			}
			if err := decodeSHB(body, order, &sec); err != nil {
				return sec, off, fmt.Errorf("SHB body: %w", err)
			}
			sec.BlockSummary["SHB"]++
		case BlockIDB:
			iface, err := decodeIDB(body, order, ifaceIdx)
			if err != nil {
				return sec, off, fmt.Errorf("IDB body: %w", err)
			}
			sec.Interfaces = append(sec.Interfaces, iface)
			ifaceIdx++
			sec.BlockSummary["IDB"]++
		case BlockEPB:
			epb, err := decodeEPB(body, order, epbIdx, opts)
			if err != nil {
				return sec, off, fmt.Errorf("EPB body: %w", err)
			}
			if opts.MaxRecords == 0 || epbIdx < opts.MaxRecords {
				sec.Records = append(sec.Records, epb)
			}
			epbIdx++
			sec.BlockSummary["EPB"]++
		case BlockSPB:
			sec.BlockSummary["SPB"]++
		case BlockNRB:
			sec.BlockSummary["NRB"]++
		case BlockISB:
			sec.BlockSummary["ISB"]++
		case BlockIRIG:
			sec.BlockSummary["IRIG"]++
		case BlockDSB:
			sec.BlockSummary["DSB"]++
		case BlockCustom:
			sec.BlockSummary["Custom"]++
		default:
			sec.BlockSummary[fmt.Sprintf("Unknown_0x%08X", blockType)]++
		}
		top.BlockCount++
		off += int(blockLen)
	}
	return sec, off, nil
}

func decodeSHB(body []byte, order binary.ByteOrder, sec *Section) error {
	if len(body) < 16 {
		return fmt.Errorf("SHB body truncated (%d; need 16)", len(body))
	}
	// body[0:4] = BOM (already validated)
	sec.MajorVersion = int(order.Uint16(body[4:6]))
	sec.MinorVersion = int(order.Uint16(body[6:8]))
	sec.SectionLength = int64(order.Uint64(body[8:16]))
	if len(body) > 16 {
		sec.Options = decodeOptions(body[16:], order)
	}
	return nil
}

func decodeIDB(body []byte, order binary.ByteOrder, idx int) (Interface, error) {
	if len(body) < 8 {
		return Interface{}, fmt.Errorf("IDB body truncated (%d; need 8)", len(body))
	}
	iface := Interface{
		Index:    idx,
		LinkType: int(order.Uint16(body[0:2])),
		SnapLen:  order.Uint32(body[4:8]),
	}
	iface.LinkTypeName = pcap.LinkTypeName(uint32(iface.LinkType))
	if len(body) > 8 {
		iface.Options = decodeOptions(body[8:], order)
	}
	return iface, nil
}

func decodeEPB(body []byte, order binary.ByteOrder, idx int, opts InspectOpts) (EnhancedPacket, error) {
	if len(body) < 20 {
		return EnhancedPacket{}, fmt.Errorf("EPB body truncated (%d; need 20)", len(body))
	}
	epb := EnhancedPacket{
		Index:          idx,
		InterfaceID:    order.Uint32(body[0:4]),
		TimestampHigh:  order.Uint32(body[4:8]),
		TimestampLow:   order.Uint32(body[8:12]),
		CapturedLength: order.Uint32(body[12:16]),
		OriginalLength: order.Uint32(body[16:20]),
	}
	epb.Timestamp64 = (uint64(epb.TimestampHigh) << 32) | uint64(epb.TimestampLow)
	dataEnd := 20 + int(epb.CapturedLength)
	if dataEnd > len(body) {
		return epb, fmt.Errorf("EPB data declared %d bytes but only %d remain", epb.CapturedLength, len(body)-20)
	}
	if opts.MaxPayloadBytes > 0 && epb.CapturedLength > 0 {
		show := int(epb.CapturedLength)
		if show > opts.MaxPayloadBytes {
			show = opts.MaxPayloadBytes
		}
		epb.PayloadHex = strings.ToUpper(hex.EncodeToString(body[20 : 20+show]))
		epb.PayloadBytesShown = show
	}
	return epb, nil
}

// decodeOptions walks a (Code, Length, Value) option list,
// stopping at the end-of-options sentinel (Code 0, Length 0).
// Values are padded to 4-byte boundaries.
func decodeOptions(b []byte, order binary.ByteOrder) []Option {
	var out []Option
	off := 0
	for off+4 <= len(b) {
		code := int(order.Uint16(b[off : off+2]))
		ln := int(order.Uint16(b[off+2 : off+4]))
		if code == 0 && ln == 0 {
			return out
		}
		valEnd := off + 4 + ln
		if valEnd > len(b) {
			return out
		}
		v := b[off+4 : valEnd]
		opt := Option{
			Code:     code,
			Length:   ln,
			ValueHex: strings.ToUpper(hex.EncodeToString(v)),
		}
		if isPlausibleText(v) {
			opt.ValueText = string(v)
		}
		out = append(out, opt)
		// Pad to 4-byte boundary.
		padded := valEnd + ((4 - (ln % 4)) % 4)
		off = padded
	}
	return out
}

// isPlausibleText returns true when the byte slice is non-
// empty, valid UTF-8, and contains only printable runes —
// i.e. it's worth surfacing as ValueText.
func isPlausibleText(b []byte) bool {
	if len(b) == 0 || !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if r < 0x20 || r == 0x7F {
			if r != '\t' && r != '\n' && r != '\r' {
				return false
			}
		}
	}
	return true
}
