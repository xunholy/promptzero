// Package ieee80211 decodes IEEE 802.11 management frames —
// the beacon / probe / authentication / association /
// deauthentication / disassociation frames captured by every
// WiFi sniffer (Marauder, hcxdumptool, aircrack-ng, Wireshark).
// Pure offline parser; no transport, no hardware.
//
// Wrap-vs-native judgement: IEEE 802.11 is a fully public
// standard. The walker is bit-level decoding over a 24-byte
// MAC header + per-subtype body + Information Element loop.
// Wrapping a FAP for this would add an SD-card install step +
// a firmware-fork dependency for a pure parser. Native delivers
// offline analysis — operators paste a captured frame and
// inspect every MAC-layer field without a WiFi adapter
// attached.
//
// Pairs with the existing wifi_eapol_decode (which handles the
// EAPOL data frames inside the 4-way handshake) — together
// they cover the WiFi management + key-exchange surface.
//
// What this package covers:
//   - Frame Control (16 bits): Protocol Version / Type / Subtype
//     / To DS / From DS / More Frag / Retry / Power Mgt / More
//     Data / Protected Frame / Order flags
//   - 24-byte MAC header (addresses + duration + sequence
//     control)
//   - Per-subtype body decode:
//   - Beacon (subtype 8): timestamp + beacon interval +
//     capability info + Information Elements
//   - Probe Response (5): same as Beacon
//   - Probe Request (4): Information Elements only
//   - Authentication (11): auth algorithm + sequence +
//     status code + IEs
//   - Association Request (0) / Response (1): capability +
//     IEs
//   - Disassociation (10) / Deauthentication (12): reason
//     code lookup
//   - Information Element walker for the common types: SSID
//     (0), Supported Rates (1), DS Parameter Set (3), TIM (5),
//     Country (7), RSN (48 = WPA2/WPA3), Vendor Specific (221
//     — WPA1, WPS, Microsoft, etc.)
//
// What this package does NOT cover (deliberately out of scope):
//   - Data frames (Type=2) — wifi_eapol_decode handles the
//     EAPOL data frames, the rest are typically encrypted
//   - Control frames (Type=1) — RTS / CTS / ACK / Block Ack,
//     mostly opaque single-frame protocols
//   - QoS Data subtype fields past the basic header (those
//     need the QoS Control / HT Control bytes — happy to add
//     when a caller materialises)
//   - HT / VHT / HE Capabilities IE field-decoding (just the
//     IE walker surfaces them as hex; full decode is a
//     follow-on Spec)
//   - FCS validation (the trailing 4-byte CRC, often stripped
//     by capture tools)
package ieee80211

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// FrameType is the 2-bit type field at bits 3..2 of byte 0.
type FrameType int

const (
	FrameTypeManagement FrameType = 0
	FrameTypeControl    FrameType = 1
	FrameTypeData       FrameType = 2
	FrameTypeExtension  FrameType = 3
)

func (t FrameType) String() string {
	switch t {
	case FrameTypeManagement:
		return "Management"
	case FrameTypeControl:
		return "Control"
	case FrameTypeData:
		return "Data"
	case FrameTypeExtension:
		return "Extension"
	}
	return "Unknown"
}

// FrameControl is the decoded 16-bit Frame Control field.
type FrameControl struct {
	Raw int `json:"raw"`
	// Protocol Version (bits 1..0) — always 0 in current spec.
	ProtocolVersion int `json:"protocol_version"`
	// Type (bits 3..2) — Management / Control / Data / Extension.
	Type     int    `json:"type"`
	TypeName string `json:"type_name"`
	// Subtype (bits 7..4) — type-specific.
	Subtype         int    `json:"subtype"`
	SubtypeName     string `json:"subtype_name"`
	ToDS            bool   `json:"to_ds"`
	FromDS          bool   `json:"from_ds"`
	MoreFragments   bool   `json:"more_fragments"`
	Retry           bool   `json:"retry"`
	PowerManagement bool   `json:"power_management"`
	MoreData        bool   `json:"more_data"`
	ProtectedFrame  bool   `json:"protected_frame"`
	Order           bool   `json:"order"`
}

// CapabilityInfo is the decoded 16-bit Capability Info field
// (present in Beacon / Probe Response / Association
// Request/Response).
type CapabilityInfo struct {
	Raw           int  `json:"raw"`
	ESS           bool `json:"ess"`
	IBSS          bool `json:"ibss"`
	Privacy       bool `json:"privacy"`
	ShortPreamble bool `json:"short_preamble"`
	ShortSlotTime bool `json:"short_slot_time"`
	SpectrumMgmt  bool `json:"spectrum_mgmt"`
	QoS           bool `json:"qos"`
}

// InformationElement is one IE in a beacon / probe response /
// association frame.
type InformationElement struct {
	ID      int    `json:"id"`
	IDHex   string `json:"id_hex"`
	Name    string `json:"name"`
	Length  int    `json:"length"`
	DataHex string `json:"data_hex"`
	// Decoded carries per-IE field decode. Populated for the
	// common types we dissect (SSID, Rates, DS, RSN, Vendor
	// Specific). nil for IEs we leave as raw hex.
	Decoded map[string]any `json:"decoded,omitempty"`
}

// Frame is the top-level decoded management frame.
type Frame struct {
	FrameControl FrameControl `json:"frame_control"`
	// Duration is the 2-byte duration field (microseconds or
	// AID, context-dependent).
	Duration int `json:"duration"`
	// DA is the Destination Address (Address 1).
	DA string `json:"destination_address"`
	// SA is the Source Address (Address 2).
	SA string `json:"source_address"`
	// BSSID is the BSSID (Address 3).
	BSSID string `json:"bssid"`
	// SequenceNumber (12 bits) and FragmentNumber (4 bits)
	// from the Sequence Control field.
	SequenceNumber int `json:"sequence_number"`
	FragmentNumber int `json:"fragment_number"`
	// Body fields populated per subtype.
	Timestamp           *uint64              `json:"timestamp,omitempty"`
	BeaconInterval      *int                 `json:"beacon_interval,omitempty"`
	Capabilities        *CapabilityInfo      `json:"capabilities,omitempty"`
	AuthAlgorithm       *int                 `json:"auth_algorithm,omitempty"`
	AuthSequence        *int                 `json:"auth_sequence,omitempty"`
	StatusCode          *int                 `json:"status_code,omitempty"`
	ReasonCode          *int                 `json:"reason_code,omitempty"`
	ReasonCodeName      string               `json:"reason_code_name,omitempty"`
	ListenInterval      *int                 `json:"listen_interval,omitempty"`
	InformationElements []InformationElement `json:"information_elements,omitempty"`
	// PayloadHex is the raw input for callers that want to
	// cross-reference with the original.
	PayloadHex string `json:"payload_hex"`
}

// Decode parses a hex-encoded 802.11 management frame.
// Tolerates ':' / '-' / '_' / whitespace separators.
func Decode(hexBlob string) (Frame, error) {
	cleaned := stripSeparators(hexBlob)
	if cleaned == "" {
		return Frame{}, fmt.Errorf("ieee80211: empty input")
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return Frame{}, fmt.Errorf("ieee80211: invalid hex: %w", err)
	}
	return DecodeBytes(b)
}

// DecodeBytes is the byte-slice variant of Decode.
func DecodeBytes(b []byte) (Frame, error) {
	const macHeaderLen = 24
	if len(b) < macHeaderLen {
		return Frame{}, fmt.Errorf("ieee80211: frame %d bytes < %d-byte MAC header",
			len(b), macHeaderLen)
	}
	fc := decodeFrameControl(binary.LittleEndian.Uint16(b[0:2]))
	out := Frame{
		FrameControl:   fc,
		Duration:       int(binary.LittleEndian.Uint16(b[2:4])),
		DA:             formatMAC(b[4:10]),
		SA:             formatMAC(b[10:16]),
		BSSID:          formatMAC(b[16:22]),
		SequenceNumber: int(binary.LittleEndian.Uint16(b[22:24]) >> 4),
		FragmentNumber: int(binary.LittleEndian.Uint16(b[22:24]) & 0x0F),
		PayloadHex:     hexString(b),
	}
	if FrameType(fc.Type) != FrameTypeManagement {
		// Non-management frames decode the header only; we don't
		// walk the body because most data frames are encrypted
		// and control frames have specialised shapes.
		return out, nil
	}
	body := b[macHeaderLen:]
	switch fc.Subtype {
	case 8: // Beacon
		err := decodeBeaconOrProbeResp(&out, body)
		if err != nil {
			return out, err
		}
	case 5: // Probe Response (same body shape as Beacon)
		err := decodeBeaconOrProbeResp(&out, body)
		if err != nil {
			return out, err
		}
	case 4: // Probe Request — body is IEs only
		out.InformationElements = parseIEs(body)
	case 0: // Association Request
		if len(body) < 4 {
			return out, fmt.Errorf("ieee80211: assoc request body %d < 4 bytes", len(body))
		}
		caps := decodeCapability(binary.LittleEndian.Uint16(body[0:2]))
		out.Capabilities = &caps
		li := int(binary.LittleEndian.Uint16(body[2:4]))
		out.ListenInterval = &li
		out.InformationElements = parseIEs(body[4:])
	case 1: // Association Response
		if len(body) < 6 {
			return out, fmt.Errorf("ieee80211: assoc response body %d < 6 bytes", len(body))
		}
		caps := decodeCapability(binary.LittleEndian.Uint16(body[0:2]))
		out.Capabilities = &caps
		sc := int(binary.LittleEndian.Uint16(body[2:4]))
		out.StatusCode = &sc
		// AID at body[4:6] (not surfaced separately for brevity)
		out.InformationElements = parseIEs(body[6:])
	case 11: // Authentication
		if len(body) < 6 {
			return out, fmt.Errorf("ieee80211: auth body %d < 6 bytes", len(body))
		}
		alg := int(binary.LittleEndian.Uint16(body[0:2]))
		seq := int(binary.LittleEndian.Uint16(body[2:4]))
		sc := int(binary.LittleEndian.Uint16(body[4:6]))
		out.AuthAlgorithm = &alg
		out.AuthSequence = &seq
		out.StatusCode = &sc
		if len(body) > 6 {
			out.InformationElements = parseIEs(body[6:])
		}
	case 10, 12: // Disassociation (10), Deauthentication (12)
		if len(body) < 2 {
			return out, fmt.Errorf("ieee80211: deauth/disassoc body %d < 2 bytes", len(body))
		}
		rc := int(binary.LittleEndian.Uint16(body[0:2]))
		out.ReasonCode = &rc
		out.ReasonCodeName = reasonCodeName(rc)
	}
	return out, nil
}

// decodeBeaconOrProbeResp parses the Beacon / Probe Response
// body — timestamp + beacon interval + capabilities + IEs.
func decodeBeaconOrProbeResp(out *Frame, body []byte) error {
	if len(body) < 12 {
		return fmt.Errorf("ieee80211: beacon body %d < 12 bytes (TS+Interval+Caps)", len(body))
	}
	ts := binary.LittleEndian.Uint64(body[0:8])
	bi := int(binary.LittleEndian.Uint16(body[8:10]))
	caps := decodeCapability(binary.LittleEndian.Uint16(body[10:12]))
	out.Timestamp = &ts
	out.BeaconInterval = &bi
	out.Capabilities = &caps
	out.InformationElements = parseIEs(body[12:])
	return nil
}

// decodeFrameControl unpacks the 16-bit Frame Control field.
func decodeFrameControl(fc uint16) FrameControl {
	pv := int(fc & 0x03)
	t := int((fc >> 2) & 0x03)
	st := int((fc >> 4) & 0x0F)
	out := FrameControl{
		Raw:             int(fc),
		ProtocolVersion: pv,
		Type:            t,
		TypeName:        FrameType(t).String(),
		Subtype:         st,
		SubtypeName:     subtypeName(t, st),
		ToDS:            fc&0x0100 != 0,
		FromDS:          fc&0x0200 != 0,
		MoreFragments:   fc&0x0400 != 0,
		Retry:           fc&0x0800 != 0,
		PowerManagement: fc&0x1000 != 0,
		MoreData:        fc&0x2000 != 0,
		ProtectedFrame:  fc&0x4000 != 0,
		Order:           fc&0x8000 != 0,
	}
	return out
}

// decodeCapability unpacks the 16-bit Capability Info field.
func decodeCapability(c uint16) CapabilityInfo {
	return CapabilityInfo{
		Raw:           int(c),
		ESS:           c&0x0001 != 0,
		IBSS:          c&0x0002 != 0,
		Privacy:       c&0x0010 != 0,
		ShortPreamble: c&0x0020 != 0,
		ShortSlotTime: c&0x0400 != 0,
		SpectrumMgmt:  c&0x0100 != 0,
		QoS:           c&0x0200 != 0,
	}
}

// parseIEs walks a tagged-parameter sequence into a list of
// Information Elements. Each IE: 1-byte ID + 1-byte length +
// length bytes of data. Stops when the buffer is exhausted or
// a declared length exceeds the remaining buffer.
func parseIEs(b []byte) []InformationElement {
	var out []InformationElement
	off := 0
	for off+2 <= len(b) {
		id := b[off]
		l := int(b[off+1])
		if off+2+l > len(b) {
			break
		}
		data := b[off+2 : off+2+l]
		ie := InformationElement{
			ID:      int(id),
			IDHex:   fmt.Sprintf("%02X", id),
			Name:    ieName(id),
			Length:  l,
			DataHex: hexString(data),
			Decoded: decodeIE(id, data),
		}
		out = append(out, ie)
		off += 2 + l
	}
	return out
}

// decodeIE dispatches per-IE-ID field decoders. Returns nil for
// IEs we leave as raw hex.
func decodeIE(id byte, data []byte) map[string]any {
	switch id {
	case 0: // SSID
		return map[string]any{"ssid": string(data)}
	case 1, 50: // Supported Rates / Extended Supported Rates
		return decodeRates(data)
	case 3: // DS Parameter Set
		if len(data) >= 1 {
			return map[string]any{"channel": int(data[0])}
		}
	case 7: // Country
		if len(data) >= 3 {
			return map[string]any{"country_code": string(data[:2]), "environment": fmt.Sprintf("%c", data[2])}
		}
	case 48: // RSN
		return decodeRSN(data)
	case 221: // Vendor Specific
		return decodeVendor(data)
	}
	return nil
}

// decodeRates surfaces the supported rates list. Each byte:
// bit 7 = basic-rate flag; bits 6..0 = rate in 500 kbps units.
func decodeRates(b []byte) map[string]any {
	var rates []string
	for _, c := range b {
		rate := float64(c&0x7F) / 2.0
		marker := ""
		if c&0x80 != 0 {
			marker = "*"
		}
		rates = append(rates, fmt.Sprintf("%.1f%s Mbps", rate, marker))
	}
	return map[string]any{
		"rates": rates,
	}
}

// decodeRSN parses the RSN (WPA2/WPA3) Information Element.
// Layout: version(2) + group cipher (4) + pairwise count (2) +
// pairwise ciphers (4 × count) + AKM count (2) + AKM suites
// (4 × count) + RSN capabilities (2). We surface counts +
// suite OUI/type forms; full suite-name lookup is left to
// follow-on Specs.
func decodeRSN(b []byte) map[string]any {
	if len(b) < 8 {
		return map[string]any{"error": "RSN payload too short"}
	}
	out := map[string]any{
		"version":      int(binary.LittleEndian.Uint16(b[0:2])),
		"group_cipher": fmt.Sprintf("%02X%02X%02X-%02X", b[2], b[3], b[4], b[5]),
	}
	off := 6
	if off+2 <= len(b) {
		pc := int(binary.LittleEndian.Uint16(b[off : off+2]))
		out["pairwise_count"] = pc
		off += 2
		var pairwise []string
		for i := 0; i < pc && off+4 <= len(b); i++ {
			pairwise = append(pairwise,
				fmt.Sprintf("%02X%02X%02X-%02X", b[off], b[off+1], b[off+2], b[off+3]))
			off += 4
		}
		out["pairwise_ciphers"] = pairwise
	}
	if off+2 <= len(b) {
		ac := int(binary.LittleEndian.Uint16(b[off : off+2]))
		out["akm_count"] = ac
		off += 2
		var akm []string
		for i := 0; i < ac && off+4 <= len(b); i++ {
			akm = append(akm,
				fmt.Sprintf("%02X%02X%02X-%02X", b[off], b[off+1], b[off+2], b[off+3]))
			off += 4
		}
		out["akm_suites"] = akm
	}
	return out
}

// decodeVendor parses a Vendor Specific IE — 3-byte OUI + 1-byte
// type + opaque data. We surface the OUI + the most well-known
// vendor names (Microsoft WPA1, WPA, WPS, Apple, Cisco).
func decodeVendor(b []byte) map[string]any {
	if len(b) < 4 {
		return map[string]any{"error": "vendor IE < 4 bytes"}
	}
	oui := fmt.Sprintf("%02X-%02X-%02X", b[0], b[1], b[2])
	vendorType := int(b[3])
	out := map[string]any{
		"oui":         oui,
		"vendor_type": vendorType,
		"data_hex":    hexString(b[4:]),
	}
	if name, ok := wellKnownVendors[ouiKey(b[0], b[1], b[2])]; ok {
		out["vendor"] = name
	}
	// Microsoft WPA1 IE: OUI 00-50-F2, type 1 = WPA1
	// Microsoft WPS IE:  OUI 00-50-F2, type 4 = WPS
	if b[0] == 0x00 && b[1] == 0x50 && b[2] == 0xF2 {
		switch vendorType {
		case 1:
			out["microsoft_subtype"] = "WPA1"
		case 4:
			out["microsoft_subtype"] = "WPS"
		}
	}
	return out
}

// ouiKey packs 3 bytes into a uint32 for the wellKnownVendors
// map key.
func ouiKey(a, b, c byte) uint32 {
	return uint32(a)<<16 | uint32(b)<<8 | uint32(c)
}

// formatMAC renders 6 bytes as a colon-separated uppercase MAC
// address.
func formatMAC(b []byte) string {
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
		b[0], b[1], b[2], b[3], b[4], b[5])
}

// hexString renders bytes as uppercase no-separator hex.
func hexString(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}

// stripSeparators mirrors the convention across our pure-decoder
// packages.
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
