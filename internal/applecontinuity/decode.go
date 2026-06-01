// Package applecontinuity decodes Apple Continuity BLE
// advertisement payloads — the Manufacturer-Specific-Data
// blob Apple devices broadcast for Handoff, AirDrop, Nearby
// Info / Action, AirPods proximity pairing, iBeacon, Hey
// Siri, and the other ad-hoc connectivity primitives that
// make the Apple ecosystem feel "magical" on a sniffer.
//
// Wrap-vs-native judgement
//
//	Native. The Continuity protocol is undocumented by Apple
//	but has been extensively reverse-engineered: Mertens et
//	al. (furiousMAC, 2019), Stute et al. (TU Darmstadt 2019-
//	2024), AppleJuice, hexway/apple_bleee, and the
//	Wireshark dissectors all converge on the same TLV
//	structure and the same per-type field semantics. The
//	wire format is a tight Type/Length/Value walker — no
//	crypto, no variable-length integers, no compression at
//	this layer. Operators paste the Manufacturer Specific
//	Data bytes (post-Apple-Company-ID 0x004C) from a
//	Wireshark BLE capture, a Sniffle/CatSniffer dump, an
//	hcidump trace, or any BLE scanner and inspect every
//	documented field.
//
// What this package covers
//
//   - Outer envelope tolerance: the input may be the raw TLV
//     stream (e.g. "1005...10 05..."), the post-CompanyID
//     manufacturer data ("4C00 10 05..."), or the full
//     advertising-data record ("0BFF4C00 10 05..."). The
//     walker auto-detects each form and strips down to the
//     TLV bytes.
//
//   - TLV walking: each message inside the stream is
//     (Type[1] + Length[1] + Value[Length]). Multiple
//     messages per advertisement are common (e.g. Nearby
//     Info + Handoff frequently appear together).
//
//   - Type table (per furiousMAC + AppleJuice + Wireshark):
//     0x02 iBeacon (RFC-equivalent: Apple's own spec,
//     publicly documented as the iBeacon protocol)
//     0x03 AirPrint
//     0x04 AirDrop
//     0x05 HomeKit
//     0x06 Proximity Pairing (AirPods / Beats / etc.)
//     0x07 Hey Siri
//     0x08 AirPlay Source
//     0x09 AirPlay Target
//     0x0A Magic Switch (Apple Pencil)
//     0x0B Watch Connection
//     0x0C Handoff
//     0x0D WiFi Settings Target
//     0x0E Tethering Target (Instant Hotspot)
//     0x0F Nearby Action
//     0x10 Nearby Info
//
//   - Per-type body decoding (best-effort, headline fields):
//
//   - iBeacon (0x02, length 21): UUID (16 bytes hex) +
//     Major (uint16 BE) + Minor (uint16 BE) + TX Power
//     (int8 dBm). The canonical Apple-issued spec.
//
//   - Handoff (0x0C, variable): Clipboard-state byte + IV
//     (2 bytes) + AuthTag (1 byte) + Encrypted Payload.
//
//   - Nearby Info (0x10, variable): high nibble of byte 0
//     = StatusFlags, low nibble = ActionCode (15-entry
//     name table); byte 1 = DataFlags; remaining bytes
//     = AuthTag.
//
//   - Nearby Action (0x0F, variable): ActionFlags byte
//
//   - ActionType byte (15-entry name table for setup
//     flows: Wi-Fi join, AirPods setup, HomePod
//     auto-setup, Apple TV setup, etc.) + AuthTag +
//     optional ActionParameters.
//
//   - AirDrop (0x04, length 18): Status byte + 8 bytes of
//     Apple ID / phone / email hash material.
//
//   - Proximity Pairing (0x06, variable): Device model byte
//
//   - status flags + battery levels (Left + Right + Case
//     for AirPods) + UTP (Unknown Transport Pairing) + Lid
//     state.
//
//   - Hey Siri (0x07, length 5): Hash bytes used to wake
//     Siri across devices.
//
//   - Other types: surfaced with Type + TypeName + Length
//
//   - raw hex body. Operators who need full dissection of
//     AirPlay, HomeKit, or Watch frames can read the bytes.
//
//   - Multi-TLV summary: a per-advertisement summary string
//     (e.g. "Nearby Info + Handoff") for triage.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - The BLE Link-Layer / Advertising PDU framing — that's
//     `ble_classify` / `ble_findmy_*`.
//
//   - The AppleID / phone / email / OfflineFinding key
//     reversal — encrypted material is surfaced as hex; the
//     decryption side belongs in a separate Spec.
//
//   - Handoff payload decryption — IV + AuthTag are
//     surfaced but the cipher-text is opaque without the
//     pairing key.
//
//   - The Bluetooth Low Energy GAP / GATT layer beyond the
//     advertising data record.
package applecontinuity

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the top-level decoded view.
type Result struct {
	Messages    []Message `json:"messages"`
	MessageCnt  int       `json:"message_count"`
	TotalBytes  int       `json:"total_bytes_decoded"`
	Summary     string    `json:"summary"`
	OuterFormat string    `json:"outer_format"`
}

// Message is one decoded Continuity TLV entry.
type Message struct {
	Type     int    `json:"type"`
	TypeHex  string `json:"type_hex"`
	TypeName string `json:"type_name"`
	Length   int    `json:"length"`
	BodyHex  string `json:"body_hex,omitempty"`

	IBeacon      *IBeacon      `json:"ibeacon,omitempty"`
	Handoff      *Handoff      `json:"handoff,omitempty"`
	NearbyInfo   *NearbyInfo   `json:"nearby_info,omitempty"`
	NearbyAction *NearbyAction `json:"nearby_action,omitempty"`
	AirDrop      *AirDrop      `json:"airdrop,omitempty"`
	HeySiri      *HeySiri      `json:"hey_siri,omitempty"`
	ProxPairing  *ProxPairing  `json:"proximity_pairing,omitempty"`
}

// IBeacon is the body of message type 0x02.
type IBeacon struct {
	UUID    string `json:"uuid"`
	Major   uint16 `json:"major"`
	Minor   uint16 `json:"minor"`
	TXPower int8   `json:"tx_power_dbm"`
}

// Handoff is the body of message type 0x0C.
type Handoff struct {
	ClipboardStatus string `json:"clipboard_status"`
	IVHex           string `json:"iv_hex"`
	AuthTagHex      string `json:"auth_tag_hex"`
	PayloadHex      string `json:"encrypted_payload_hex"`
}

// NearbyInfo is the body of message type 0x10.
type NearbyInfo struct {
	StatusFlags int    `json:"status_flags"`
	StatusBits  string `json:"status_bits_decoded"`
	ActionCode  int    `json:"action_code"`
	ActionName  string `json:"action_name"`
	DataFlags   int    `json:"data_flags,omitempty"`
	AuthTagHex  string `json:"auth_tag_hex,omitempty"`
}

// NearbyAction is the body of message type 0x0F.
type NearbyAction struct {
	ActionFlags    int    `json:"action_flags"`
	ActionType     int    `json:"action_type"`
	ActionTypeName string `json:"action_type_name"`
	AuthTagHex     string `json:"auth_tag_hex,omitempty"`
	ParametersHex  string `json:"parameters_hex,omitempty"`
}

// AirDrop is the body of message type 0x04.
type AirDrop struct {
	StatusHex     string `json:"status_hex"`
	IdentifierHex string `json:"identifier_hex"`
}

// HeySiri is the body of message type 0x07.
type HeySiri struct {
	HashHex string `json:"hash_hex"`
}

// ProxPairing is the body of message type 0x06 (AirPods / Beats).
type ProxPairing struct {
	DeviceModel    int    `json:"device_model"`
	DeviceModelHex string `json:"device_model_hex"`
	StatusFlags    int    `json:"status_flags"`
	BatteryLeft    int    `json:"battery_left_pct,omitempty"`
	BatteryRight   int    `json:"battery_right_pct,omitempty"`
	BatteryCase    int    `json:"battery_case_pct,omitempty"`
	LidState       int    `json:"lid_state,omitempty"`
	RawHex         string `json:"raw_hex,omitempty"`
}

// Decode parses an Apple Continuity payload from hex.
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if clean == "" {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("hex must have even length, got %d", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}

	// Strip outer envelopes.
	tlvs, outer, err := stripOuter(b)
	if err != nil {
		return nil, err
	}

	var msgs []Message
	off := 0
	for off < len(tlvs) {
		if off+2 > len(tlvs) {
			return nil, fmt.Errorf("TLV header truncated at offset %d", off)
		}
		typ := int(tlvs[off])
		ln := int(tlvs[off+1])
		if off+2+ln > len(tlvs) {
			return nil, fmt.Errorf("TLV at type 0x%02X declares %d bytes; %d left",
				typ, ln, len(tlvs)-off-2)
		}
		body := tlvs[off+2 : off+2+ln]
		m := Message{
			Type:     typ,
			TypeHex:  fmt.Sprintf("0x%02X", typ),
			TypeName: typeName(typ),
			Length:   ln,
			BodyHex:  strings.ToUpper(hex.EncodeToString(body)),
		}
		decorateMessage(&m, body)
		msgs = append(msgs, m)
		off += 2 + ln
	}

	summary := make([]string, 0, len(msgs))
	for _, m := range msgs {
		summary = append(summary, m.TypeName)
	}

	return &Result{
		Messages:    msgs,
		MessageCnt:  len(msgs),
		TotalBytes:  off,
		Summary:     strings.Join(summary, " + "),
		OuterFormat: outer,
	}, nil
}

// stripOuter detects and strips the optional outer envelopes:
// (a) the full advertising-data record (len + 0xFF + 0x4C00 +
// TLVs); (b) just the manufacturer-data payload (0x4C00 +
// TLVs); (c) the raw TLV stream.
func stripOuter(b []byte) (tlvs []byte, format string, err error) {
	// (a) advertising-data record: byte 0 = total length, byte 1
	// = 0xFF (Manufacturer Specific Data), bytes 2-3 = 0x4C
	// 0x00 (Apple Company ID).
	if len(b) >= 4 && b[1] == 0xFF && b[2] == 0x4C && b[3] == 0x00 {
		declaredLen := int(b[0])
		end := 1 + declaredLen
		// end must reach the body start (>=4) and stay within the buffer;
		// a bogus short length would otherwise slice b[4:<4] and panic.
		if end < 4 || end > len(b) {
			return nil, "", fmt.Errorf("advertising-data length %d inconsistent with a %d-byte buffer",
				declaredLen, len(b))
		}
		return b[4:end], "ad_record", nil
	}
	// (b) post-AdvType manufacturer data: 0x4C 0x00 + TLVs.
	if len(b) >= 2 && b[0] == 0x4C && b[1] == 0x00 {
		return b[2:], "manufacturer_data", nil
	}
	// (c) raw TLV stream — heuristic check: the first byte
	// must be a documented Continuity type (0x02-0x10) and
	// the second byte must be a plausible length (≤ remaining
	// bytes minus the header). If it doesn't look like that,
	// bail.
	if len(b) >= 2 {
		typ := int(b[0])
		ln := int(b[1])
		if typ >= 0x02 && typ <= 0x10 && 2+ln <= len(b) {
			return b, "raw_tlv", nil
		}
	}
	return nil, "", fmt.Errorf("input doesn't look like an Apple Continuity payload "+
		"(no 0xFF/0x4C00 envelope and first 2 bytes %s don't form a documented TLV)",
		hexPreview(b, 4))
}

func decorateMessage(m *Message, body []byte) {
	switch m.Type {
	case 0x02:
		if len(body) == 21 {
			m.IBeacon = &IBeacon{
				UUID:    formatUUID(body[0:16]),
				Major:   binary.BigEndian.Uint16(body[16:18]),
				Minor:   binary.BigEndian.Uint16(body[18:20]),
				TXPower: int8(body[20]),
			}
		}
	case 0x0C:
		if len(body) >= 4 {
			m.Handoff = &Handoff{
				ClipboardStatus: clipboardStatusName(int(body[0])),
				IVHex:           strings.ToUpper(hex.EncodeToString(body[1:3])),
				AuthTagHex:      strings.ToUpper(hex.EncodeToString(body[3:4])),
				PayloadHex:      strings.ToUpper(hex.EncodeToString(body[4:])),
			}
		}
	case 0x10:
		if len(body) >= 1 {
			n := &NearbyInfo{
				StatusFlags: int(body[0]) >> 4,
				ActionCode:  int(body[0]) & 0x0F,
			}
			n.StatusBits = nearbyStatusBits(n.StatusFlags)
			n.ActionName = nearbyActionCodeName(n.ActionCode)
			if len(body) >= 2 {
				n.DataFlags = int(body[1])
			}
			if len(body) >= 3 {
				n.AuthTagHex = strings.ToUpper(hex.EncodeToString(body[2:]))
			}
			m.NearbyInfo = n
		}
	case 0x0F:
		if len(body) >= 2 {
			n := &NearbyAction{
				ActionFlags:    int(body[0]),
				ActionType:     int(body[1]),
				ActionTypeName: nearbyActionTypeName(int(body[1])),
			}
			if len(body) >= 5 {
				n.AuthTagHex = strings.ToUpper(hex.EncodeToString(body[2:5]))
				if len(body) > 5 {
					n.ParametersHex = strings.ToUpper(hex.EncodeToString(body[5:]))
				}
			} else if len(body) > 2 {
				n.AuthTagHex = strings.ToUpper(hex.EncodeToString(body[2:]))
			}
			m.NearbyAction = n
		}
	case 0x04:
		if len(body) >= 9 {
			m.AirDrop = &AirDrop{
				StatusHex:     strings.ToUpper(hex.EncodeToString(body[:1])),
				IdentifierHex: strings.ToUpper(hex.EncodeToString(body[1:])),
			}
		}
	case 0x07:
		m.HeySiri = &HeySiri{
			HashHex: strings.ToUpper(hex.EncodeToString(body)),
		}
	case 0x06:
		if len(body) >= 4 {
			p := &ProxPairing{
				DeviceModel:    int(binary.BigEndian.Uint16(body[1:3])),
				DeviceModelHex: fmt.Sprintf("0x%04X", binary.BigEndian.Uint16(body[1:3])),
				StatusFlags:    int(body[3]),
				RawHex:         strings.ToUpper(hex.EncodeToString(body)),
			}
			// AirPods battery encoding (AppleJuice/apple_bleee
			// research): body[4] high-nibble = left pod %,
			// low-nibble = right pod % (each in steps of 10);
			// body[5] low-nibble = case % (steps of 10), high
			// bit = case-charging flag; body[6] = lid state.
			if len(body) >= 6 {
				p.BatteryLeft = int(body[4]>>4) * 10
				p.BatteryRight = int(body[4]&0x0F) * 10
				if len(body) >= 7 {
					p.BatteryCase = int(body[5]&0x0F) * 10
					p.LidState = int(body[6])
				}
			}
			m.ProxPairing = p
		}
	}
}

func typeName(t int) string {
	switch t {
	case 0x02:
		return "iBeacon"
	case 0x03:
		return "AirPrint"
	case 0x04:
		return "AirDrop"
	case 0x05:
		return "HomeKit"
	case 0x06:
		return "Proximity Pairing"
	case 0x07:
		return "Hey Siri"
	case 0x08:
		return "AirPlay Source"
	case 0x09:
		return "AirPlay Target"
	case 0x0A:
		return "Magic Switch (Apple Pencil)"
	case 0x0B:
		return "Watch Connection"
	case 0x0C:
		return "Handoff"
	case 0x0D:
		return "Wi-Fi Settings Target"
	case 0x0E:
		return "Tethering Target (Instant Hotspot)"
	case 0x0F:
		return "Nearby Action"
	case 0x10:
		return "Nearby Info"
	}
	return fmt.Sprintf("Unknown (0x%02X)", t)
}

func nearbyActionCodeName(code int) string {
	// Per furiousMAC + AppleJuice.
	switch code {
	case 0x00:
		return "Activity Reporting Disabled"
	case 0x01:
		return "Activity Reporting Enabled"
	case 0x03:
		return "iOS Lock Screen"
	case 0x05:
		return "iOS Home Screen"
	case 0x07:
		return "iOS Transition (post-unlock / new screen)"
	case 0x08:
		return "Apple TV Home Screen"
	case 0x09:
		return "iOS Audio Playing with Screen Off"
	case 0x0A:
		return "iOS Lock with Active Call"
	case 0x0B:
		return "iOS Phone Call Active"
	case 0x0C:
		return "iOS Home Screen with Phone Call"
	case 0x0D:
		return "Driving / CarPlay"
	case 0x0E:
		return "FaceTime Active"
	case 0x0F:
		return "iOS Asleep (display off)"
	}
	return fmt.Sprintf("ActionCode 0x%X (undocumented)", code)
}

func nearbyActionTypeName(typ int) string {
	// Per AppleJuice + Apple_BLEEE.
	switch typ {
	case 0x01:
		return "Apple TV Setup"
	case 0x04:
		return "Mobile Backup"
	case 0x05:
		return "Watch Setup"
	case 0x06:
		return "Apple TV Pair"
	case 0x07:
		return "Internet Relay"
	case 0x08:
		return "Wi-Fi Password"
	case 0x09:
		return "iOS Setup (Quick Start)"
	case 0x0A:
		return "Repair"
	case 0x0B:
		return "Speaker Setup (HomePod)"
	case 0x0C:
		return "Apple Pay"
	case 0x0D:
		return "Whole Home Audio Setup"
	case 0x0E:
		return "Developer Tools Pair"
	case 0x0F:
		return "Answered Call"
	case 0x10:
		return "Ended Call"
	case 0x11:
		return "DD Ping"
	case 0x12:
		return "DD Pong"
	case 0x13:
		return "Remote Auto Fill (Password / Cardonomous)"
	case 0x14:
		return "Companion Link Proximity"
	case 0x15:
		return "Remote Management"
	case 0x16:
		return "Remote Auto Fill Pong"
	case 0x17:
		return "Remote Display"
	}
	return fmt.Sprintf("NearbyActionType 0x%02X (undocumented)", typ)
}

func clipboardStatusName(b int) string {
	switch {
	case b == 0:
		return "no clipboard activity"
	case b&0x08 != 0:
		return "clipboard active"
	default:
		return fmt.Sprintf("status byte 0x%02X", b)
	}
}

func nearbyStatusBits(flags int) string {
	parts := []string{}
	if flags&0x08 != 0 {
		parts = append(parts, "PrimaryiCloudAccount")
	}
	if flags&0x04 != 0 {
		parts = append(parts, "AirDropReceiving")
	}
	if flags&0x02 != 0 {
		parts = append(parts, "AutoUnlockActive")
	}
	if flags&0x01 != 0 {
		parts = append(parts, "AutoUnlockEnabled")
	}
	if len(parts) == 0 {
		return "(no status bits set)"
	}
	return strings.Join(parts, " | ")
}

func formatUUID(b []byte) string {
	// 8-4-4-4-12 hex grouping.
	if len(b) != 16 {
		return strings.ToUpper(hex.EncodeToString(b))
	}
	h := strings.ToUpper(hex.EncodeToString(b))
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}

func hexPreview(b []byte, n int) string {
	if len(b) < n {
		n = len(b)
	}
	return strings.ToUpper(hex.EncodeToString(b[:n]))
}

func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
