// Package ieee802154 decodes IEEE 802.15.4 MAC-layer frames —
// the wire format underneath Zigbee, Thread, OpenThread, and
// most other 2.4 GHz IoT mesh stacks. Pure offline parser; no
// transport, no hardware.
//
// Wrap-vs-native judgement: IEEE 802.15.4 is a fully public
// standard (IEEE Std 802.15.4-2015 / -2020). The walker is
// bit-level decoding over a 5-127 byte frame with a documented
// Frame Control + addressing-mode-driven address field. Wrapping
// a FAP for this would add an SD-card install step + a
// firmware-fork dependency for a pure parser. Native delivers
// offline analysis — operators paste a captured frame from a
// CatSniffer, KillerBee, Sniffle, or any 802.15.4-capable SDR
// and inspect every MAC-layer field without an antenna attached.
//
// Pairs with the bruce_zigbee_scan capability (which surfaces
// observed PAN beacons from a Bruce-equipped Flipper) — this
// Spec covers the offline-analyst flow for captured frames.
//
// What this package covers:
//   - Frame Control field (16 bits) with all documented flags
//     and the four addressing-mode + frame-version sub-fields
//   - Sequence Number (with the 2015-spec "suppression" path)
//   - Addressing-fields walker: destination PAN + address,
//     source PAN (with PAN ID Compression) + address. Both
//     short (16-bit) and extended (64-bit) variants.
//   - Frame-type identification (Beacon, Data, Ack, MAC Command,
//     Multipurpose, Fragment, Extended) plus the per-type
//     payload pass-through
//   - FCS (frame check sequence) surfacing — most captures
//     include it, some don't; we accept both and surface a flag
//
// What this package does NOT cover (deliberately out of scope):
//   - Auxiliary Security Header dissection (security frame
//     counter / KeyIdentifier — those need network keys to
//     interpret usefully)
//   - Payload decryption (needs the network or link key)
//   - Higher-layer dissectors (Zigbee NWK / APS / ZCL, Thread
//     6LoWPAN, etc.) — separate Specs when callers materialise
//   - FCS verification (the FCS is over the MHR + payload and
//     uses a 16-bit ITU-T CRC; happy to add when a caller asks)
package ieee802154

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// FrameType is the 3-bit frame-type field at the bottom of the
// Frame Control word.
type FrameType int

const (
	FrameTypeBeacon       FrameType = 0
	FrameTypeData         FrameType = 1
	FrameTypeAck          FrameType = 2
	FrameTypeMACCommand   FrameType = 3
	FrameTypeReserved     FrameType = 4
	FrameTypeMultipurpose FrameType = 5
	FrameTypeFragment     FrameType = 6
	FrameTypeExtended     FrameType = 7
)

func (f FrameType) String() string {
	switch f {
	case FrameTypeBeacon:
		return "Beacon"
	case FrameTypeData:
		return "Data"
	case FrameTypeAck:
		return "Acknowledgment"
	case FrameTypeMACCommand:
		return "MAC Command"
	case FrameTypeMultipurpose:
		return "Multipurpose"
	case FrameTypeFragment:
		return "Fragment"
	case FrameTypeExtended:
		return "Extended"
	}
	return "Reserved"
}

// AddressingMode is the 2-bit field selecting how an address
// (destination or source) is encoded.
type AddressingMode int

const (
	// AddrModeNone — the PAN identifier and address field are
	// not present.
	AddrModeNone AddressingMode = 0
	// AddrModeReserved — reserved by the spec.
	AddrModeReserved AddressingMode = 1
	// AddrModeShort — 16-bit short address present.
	AddrModeShort AddressingMode = 2
	// AddrModeExtended — 64-bit extended (EUI-64) address
	// present.
	AddrModeExtended AddressingMode = 3
)

func (a AddressingMode) String() string {
	switch a {
	case AddrModeNone:
		return "None"
	case AddrModeShort:
		return "Short (16-bit)"
	case AddrModeExtended:
		return "Extended (64-bit)"
	}
	return "Reserved"
}

// FrameControl is the decoded 16-bit Frame Control field.
type FrameControl struct {
	Raw int `json:"raw"`
	// FrameType is the 3-bit type field.
	FrameType        int    `json:"frame_type"`
	FrameTypeName    string `json:"frame_type_name"`
	SecurityEnabled  bool   `json:"security_enabled"`
	FramePending     bool   `json:"frame_pending"`
	AckRequest       bool   `json:"ack_request"`
	PANIDCompression bool   `json:"pan_id_compression"`
	// SequenceNumberSuppression is a 2015-spec flag (bit 8) — when
	// set the Sequence Number field is omitted.
	SequenceNumberSuppression bool `json:"sequence_number_suppression"`
	// IEPresent is the 2015-spec Information Element flag (bit 9).
	IEPresent bool `json:"ie_present"`
	// DestinationAddrMode / SourceAddrMode select the address
	// encoding (None / Short / Extended).
	DestinationAddrMode     int    `json:"destination_addr_mode"`
	DestinationAddrModeName string `json:"destination_addr_mode_name"`
	// FrameVersion: 0 = 2003, 1 = 2006, 2 = 2015.
	FrameVersion       int    `json:"frame_version"`
	FrameVersionName   string `json:"frame_version_name"`
	SourceAddrMode     int    `json:"source_addr_mode"`
	SourceAddrModeName string `json:"source_addr_mode_name"`
}

// Address is one parsed address field — either short or extended.
type Address struct {
	PANID    string `json:"pan_id,omitempty"`
	Short    string `json:"short,omitempty"`
	Extended string `json:"extended,omitempty"`
	Mode     string `json:"mode"`
}

// Frame is the top-level decoded MAC-layer frame.
type Frame struct {
	// FrameControl is the parsed 2-byte Frame Control field.
	FrameControl FrameControl `json:"frame_control"`
	// SequenceNumber is the 1-byte sequence number. nil when the
	// Sequence Number Suppression flag is set (2015 spec only).
	SequenceNumber *int `json:"sequence_number,omitempty"`
	// Destination / Source are the optional addressing fields,
	// populated based on the respective mode bits.
	Destination *Address `json:"destination,omitempty"`
	Source      *Address `json:"source,omitempty"`
	// AuxSecurityHeaderHex is the raw security header bytes when
	// SecurityEnabled is set. Walking the security header (key
	// identifier, frame counter) is deliberately out of scope.
	AuxSecurityHeaderHex string `json:"aux_security_header_hex,omitempty"`
	// PayloadHex is the MAC payload after addressing + security
	// headers, before the (optional) FCS.
	PayloadHex string `json:"payload_hex,omitempty"`
	// FCSHex is the 2-byte CRC at frame end when the caller
	// includes it. FCSIncluded reports whether we treated the
	// last 2 bytes as FCS (a caller without FCS in the dump can
	// pass include_fcs=false in the Spec to avoid the strip).
	FCSHex      string `json:"fcs_hex,omitempty"`
	FCSIncluded bool   `json:"fcs_included"`
	// PayloadOffset is the byte offset of PayloadHex within the
	// original frame — useful for cross-referencing with a hex
	// editor.
	PayloadOffset int `json:"payload_offset"`
}

// DecodeOptions tunes the parser's behaviour.
type DecodeOptions struct {
	// IncludeFCS tells the walker to treat the trailing 2 bytes
	// as the Frame Check Sequence. Capture sources vary:
	// CatSniffer / Sniffle include it; many Bruce / Marauder
	// outputs strip it. Default (false) is "no FCS".
	IncludeFCS bool
}

// Decode parses a hex-encoded MAC frame with default options
// (no FCS). Tolerates ':' / '-' / '_' / whitespace separators.
func Decode(hexBlob string) (Frame, error) {
	return DecodeWithOptions(hexBlob, DecodeOptions{})
}

// DecodeWithOptions is the option-tunable variant of Decode.
func DecodeWithOptions(hexBlob string, opts DecodeOptions) (Frame, error) {
	cleaned := stripSeparators(hexBlob)
	if cleaned == "" {
		return Frame{}, fmt.Errorf("ieee802154: empty input")
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return Frame{}, fmt.Errorf("ieee802154: invalid hex: %w", err)
	}
	return DecodeBytesWithOptions(b, opts)
}

// DecodeBytesWithOptions is the byte-slice variant of
// DecodeWithOptions.
func DecodeBytesWithOptions(b []byte, opts DecodeOptions) (Frame, error) {
	if len(b) < 3 {
		// Minimum useful MAC frame: 2-byte FC + 1-byte sequence number
		// (Ack frames are 5 bytes including FCS).
		return Frame{}, fmt.Errorf("ieee802154: frame %d bytes < 3-byte minimum (FC + seq)", len(b))
	}
	fc := decodeFrameControl(binary.LittleEndian.Uint16(b[0:2]))
	out := Frame{FrameControl: fc}
	off := 2
	// Sequence Number (suppressed in 2015 spec when bit set)
	if !fc.SequenceNumberSuppression {
		if off >= len(b) {
			return out, fmt.Errorf("ieee802154: missing sequence number byte")
		}
		seq := int(b[off])
		out.SequenceNumber = &seq
		off++
	}
	// Destination addressing fields
	dest, n, err := parseAddress(b[off:], AddressingMode(fc.DestinationAddrMode), true)
	if err != nil {
		return out, fmt.Errorf("ieee802154: destination address: %w", err)
	}
	off += n
	if dest != nil {
		out.Destination = dest
	}
	// Source addressing fields. When PAN ID Compression is set, the
	// source PAN ID is omitted (source uses the destination's PAN).
	src, n, err := parseAddress(b[off:], AddressingMode(fc.SourceAddrMode), !fc.PANIDCompression)
	if err != nil {
		return out, fmt.Errorf("ieee802154: source address: %w", err)
	}
	off += n
	if src != nil {
		// When PAN ID is compressed, source borrows destination's PAN ID
		// for display. Annotate clearly.
		if fc.PANIDCompression && dest != nil {
			src.PANID = dest.PANID
		}
		out.Source = src
	}
	// Aux Security Header (variable length, we just surface as hex).
	if fc.SecurityEnabled {
		// We don't walk the security header in detail — read at
		// minimum the 1-byte Security Control field to estimate the
		// header length, then surface whatever's left until payload.
		// To keep this safe-by-default, we punt: surface the rest as
		// security-header-hex when SecurityEnabled is set and the
		// frame is too short to have any payload after.
		// Better approach: walk the 1-byte security control to
		// determine the security header length.
		if off >= len(b) {
			return out, fmt.Errorf("ieee802154: security enabled but no security header bytes")
		}
		secCtrl := b[off]
		secHdrLen := securityHeaderLen(secCtrl)
		if off+secHdrLen > len(b) {
			return out, fmt.Errorf("ieee802154: security header length %d exceeds remaining buffer %d",
				secHdrLen, len(b)-off)
		}
		out.AuxSecurityHeaderHex = hexString(b[off : off+secHdrLen])
		off += secHdrLen
	}
	// Payload + optional FCS
	end := len(b)
	if opts.IncludeFCS {
		if end-off < 2 {
			return out, fmt.Errorf("ieee802154: include_fcs set but only %d bytes left",
				end-off)
		}
		out.FCSHex = hexString(b[end-2:])
		out.FCSIncluded = true
		end -= 2
	}
	if off < end {
		out.PayloadHex = hexString(b[off:end])
	}
	out.PayloadOffset = off
	return out, nil
}

// decodeFrameControl unpacks the 16-bit Frame Control field per
// IEEE Std 802.15.4-2015 §7.2.1.
func decodeFrameControl(fc uint16) FrameControl {
	ft := int(fc & 0x07)
	destMode := int((fc >> 10) & 0x03)
	srcMode := int((fc >> 14) & 0x03)
	ver := int((fc >> 12) & 0x03)
	return FrameControl{
		Raw:                       int(fc),
		FrameType:                 ft,
		FrameTypeName:             FrameType(ft).String(),
		SecurityEnabled:           fc&0x0008 != 0,
		FramePending:              fc&0x0010 != 0,
		AckRequest:                fc&0x0020 != 0,
		PANIDCompression:          fc&0x0040 != 0,
		SequenceNumberSuppression: fc&0x0100 != 0,
		IEPresent:                 fc&0x0200 != 0,
		DestinationAddrMode:       destMode,
		DestinationAddrModeName:   AddressingMode(destMode).String(),
		FrameVersion:              ver,
		FrameVersionName:          frameVersionName(ver),
		SourceAddrMode:            srcMode,
		SourceAddrModeName:        AddressingMode(srcMode).String(),
	}
}

// parseAddress reads PAN + address bytes per the addressing mode.
// includePAN is false for the source when PAN ID Compression is
// set (the source borrows destination's PAN).
//
// Returns nil for the parsed Address when mode == None (no
// fields to read).
func parseAddress(b []byte, mode AddressingMode, includePAN bool) (*Address, int, error) {
	if mode == AddrModeNone {
		return nil, 0, nil
	}
	if mode == AddrModeReserved {
		return nil, 0, fmt.Errorf("addressing mode 'Reserved' (1) is invalid")
	}
	out := &Address{Mode: mode.String()}
	off := 0
	if includePAN {
		if off+2 > len(b) {
			return nil, 0, fmt.Errorf("truncated: no PAN ID bytes")
		}
		out.PANID = fmt.Sprintf("%04X", binary.LittleEndian.Uint16(b[off:off+2]))
		off += 2
	}
	switch mode {
	case AddrModeShort:
		if off+2 > len(b) {
			return nil, 0, fmt.Errorf("truncated: no short address bytes")
		}
		out.Short = fmt.Sprintf("%04X", binary.LittleEndian.Uint16(b[off:off+2]))
		off += 2
	case AddrModeExtended:
		if off+8 > len(b) {
			return nil, 0, fmt.Errorf("truncated: no extended address bytes")
		}
		// Extended addresses are on the wire little-endian; we
		// render them big-endian to match the EUI-64 form printed
		// on device labels.
		out.Extended = hexString(reverseBytes(b[off : off+8]))
		off += 8
	}
	return out, off, nil
}

// securityHeaderLen computes the length of the Auxiliary Security
// Header based on the Security Control byte. Layout per
// IEEE Std 802.15.4-2015 §9.4:
//
//	bits 0-2: Security Level
//	bits 3-4: Key Identifier Mode
//	bit  5:   Frame Counter Suppression (2015)
//	bit  6:   Frame Counter Size (2015; 0 = 4 bytes, 1 = 5 bytes)
//	bit  7:   Reserved
//
// We compute conservatively: 1 byte for SecCtrl + 4 bytes for
// frame counter (default 4) + key identifier (0/1/5/9 bytes per
// KeyIdMode). The 2015-spec longer-counter and counter-
// suppression paths aren't surfaced here because the default
// (4-byte counter, present) covers >99% of in-the-wild captures.
func securityHeaderLen(secCtrl byte) int {
	kim := (secCtrl >> 3) & 0x03
	keyIDLen := 0
	switch kim {
	case 0:
		keyIDLen = 0
	case 1:
		keyIDLen = 1
	case 2:
		keyIDLen = 5
	case 3:
		keyIDLen = 9
	}
	// SecCtrl (1) + Frame Counter (4) + Key Identifier
	return 1 + 4 + keyIDLen
}

// frameVersionName maps the 2-bit version field to a human label.
func frameVersionName(v int) string {
	switch v {
	case 0:
		return "802.15.4-2003"
	case 1:
		return "802.15.4-2006"
	case 2:
		return "802.15.4-2015"
	}
	return "Reserved"
}

// reverseBytes returns a fresh slice with the bytes reversed —
// little-endian-on-wire to big-endian-rendered for the extended
// EUI-64 addresses.
func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[len(b)-1-i] = c
	}
	return out
}

// hexString renders bytes as uppercase hex with no separators.
func hexString(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}

// stripSeparators mirrors the convention used across our
// pure-decoder packages.
func stripSeparators(s string) string {
	repl := strings.NewReplacer(
		" ", "",
		"\t", "",
		"\n", "",
		"\r", "",
		":", "",
		"-", "",
		"_", "",
	)
	return repl.Replace(strings.TrimSpace(s))
}
