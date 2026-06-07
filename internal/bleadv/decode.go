// SPDX-License-Identifier: AGPL-3.0-or-later

// Package bleadv decodes a Bluetooth advertising / scan-response payload — the
// GAP "AD structure" list (Bluetooth Core Specification, Vol 3 Part C §11, and
// the Core Specification Supplement / Assigned Numbers). The exact same
// length-type-value structure is the BR/EDR Extended Inquiry Response (EIR), so
// this also decodes EIR.
//
// A BLE advertising payload is what every passive BLE scan surfaces first — the
// Flipper "BLE scan", an ESP32 Marauder / nRF sniffer, a phone's nRF Connect:
// before any connection or GATT traffic (bt_hci_decode → bt_l2cap_decode →
// bt_att_decode), the advertising data is the recon headline. It carries the
// device's advertised name, its discoverability/role flags, the service UUIDs
// it offers, its TX power and appearance, and — most usefully for fingerprinting
// — manufacturer-specific data: Apple iBeacon (proximity UUID + major/minor),
// Eddystone beacons (UID/URL/TLM), and the company identifier of the chipset /
// vendor behind an otherwise anonymous device. It is the advertising-layer
// complement to the project's Bluetooth-stack decode chain.
//
// # Wrap-vs-native judgement
//
//	Native. An advertising payload is a flat list of [length][AD type][data]
//	structures; each AD type has a fixed, documented layout (little-endian
//	UUIDs, a flags bitfield, signed TX power, a 2-byte company identifier, the
//	iBeacon / Eddystone sub-formats). A length-prefixed TLV walk plus small
//	lookup tables; stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The AD type numbers, the Flags bits, the service-UUID list layouts, the
//	company-identifier assignment, and the iBeacon / Eddystone sub-formats
//	follow the Bluetooth Assigned Numbers and the published iBeacon / Eddystone
//	specifications — deterministic and byte-checkable. Where a value space is
//	open-ended or undocumented (an unknown AD type, an unknown company id, a
//	manufacturer blob other than iBeacon such as Apple's proprietary Continuity
//	stream, service data for a UUID other than Eddystone's 0xFEAA), the bytes
//	are surfaced raw with a note rather than guessed.
package bleadv

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of an advertising / scan-response (EIR) payload.
type Result struct {
	Structures []Structure `json:"structures"`
	Notes      []string    `json:"notes,omitempty"`
}

// Structure is one AD structure (one [length][type][data] record).
type Structure struct {
	Length   int    `json:"length"`
	ADType   int    `json:"ad_type"`
	TypeName string `json:"ad_type_name"`

	Flags        []string `json:"flags,omitempty"`
	ServiceUUIDs []string `json:"service_uuids,omitempty"`
	LocalName    string   `json:"local_name,omitempty"`
	TxPowerDBm   *int     `json:"tx_power_dbm,omitempty"`
	Appearance   string   `json:"appearance,omitempty"`
	LERole       string   `json:"le_role,omitempty"`
	URI          string   `json:"uri,omitempty"`

	Manufacturer *Manufacturer `json:"manufacturer,omitempty"`
	ServiceData  *ServiceData  `json:"service_data,omitempty"`
	IBeacon      *IBeacon      `json:"ibeacon,omitempty"`
	Eddystone    *Eddystone    `json:"eddystone,omitempty"`

	Raw   string `json:"raw,omitempty"`
	Notes string `json:"notes,omitempty"`
}

// Manufacturer is decoded AD type 0xFF (Manufacturer Specific Data).
type Manufacturer struct {
	CompanyID   string `json:"company_id"`
	CompanyName string `json:"company_name"`
	DataHex     string `json:"data_hex,omitempty"`
}

// ServiceData is decoded AD type 0x16 / 0x20 / 0x21 (Service Data).
type ServiceData struct {
	UUID    string `json:"uuid"`
	DataHex string `json:"data_hex,omitempty"`
}

// IBeacon is the decoded Apple iBeacon manufacturer payload.
type IBeacon struct {
	UUID          string `json:"proximity_uuid"`
	Major         int    `json:"major"`
	Minor         int    `json:"minor"`
	MeasuredPower int    `json:"measured_power_dbm"`
}

// Eddystone is a decoded Eddystone frame (service data for UUID 0xFEAA).
type Eddystone struct {
	FrameType string `json:"frame_type"`

	// UID / URL frames carry a calibrated 0 m TX power.
	TxPower0mDBm *int `json:"tx_power_0m_dbm,omitempty"`

	// UID frame.
	NamespaceHex string `json:"namespace_hex,omitempty"`
	InstanceHex  string `json:"instance_hex,omitempty"`

	// URL frame.
	URL string `json:"url,omitempty"`

	// TLM (unencrypted, version 0x00) frame.
	BatteryMV     *int     `json:"battery_mv,omitempty"`
	TemperatureC  *float64 `json:"temperature_c,omitempty"`
	AdvCount      *uint32  `json:"adv_count,omitempty"`
	UptimeSeconds *float64 `json:"uptime_seconds,omitempty"`

	Raw string `json:"raw,omitempty"`
}

// Decode parses a BLE advertising / scan-response payload (or BR/EDR EIR) from
// hex (whitespace / ':' / '-' / '_' separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 2 {
		return nil, fmt.Errorf("bleadv: payload too short (need at least one length+type)")
	}

	r := &Result{}
	i := 0
	for i < len(b) {
		ln := int(b[i])
		if ln == 0 {
			// A zero length is the AD-structure list terminator / padding
			// (advertising PDUs are zero-padded to 31 bytes). Stop cleanly.
			break
		}
		if i+1+ln > len(b) {
			r.Notes = append(r.Notes, fmt.Sprintf("truncated AD structure at offset %d: length byte 0x%02X claims %d bytes but only %d remain", i, b[i], ln, len(b)-i-1))
			break
		}
		adType := b[i+1]
		data := b[i+2 : i+1+ln]
		r.Structures = append(r.Structures, decodeStructure(ln, adType, data))
		i += 1 + ln
	}

	if len(r.Structures) == 0 {
		return nil, fmt.Errorf("bleadv: no AD structures decoded")
	}
	r.Notes = append(r.Notes, "BLE advertising / scan-response (GAP AD structures; same format as BR/EDR EIR) — the recon headline of a passive BLE scan: name, flags, service UUIDs and manufacturer fingerprint; pair 16-bit service UUIDs with bluetooth_gatt_uuid_lookup")
	return r, nil
}

func decodeStructure(ln int, adType byte, data []byte) Structure {
	s := Structure{Length: ln, ADType: int(adType), TypeName: adTypeName(adType)}
	switch adType {
	case 0x01: // Flags
		if len(data) >= 1 {
			s.Flags = decodeFlags(data[0])
		}
	case 0x02, 0x03: // Incomplete / Complete list of 16-bit service UUIDs
		s.ServiceUUIDs = uuid16List(data)
	case 0x04, 0x05: // 32-bit service UUIDs
		s.ServiceUUIDs = uuid32List(data)
	case 0x06, 0x07: // 128-bit service UUIDs
		s.ServiceUUIDs = uuid128List(data)
	case 0x14, 0x1F, 0x15: // Service Solicitation (16 / 32 / 128-bit)
		switch adType {
		case 0x14:
			s.ServiceUUIDs = uuid16List(data)
		case 0x1F:
			s.ServiceUUIDs = uuid32List(data)
		case 0x15:
			s.ServiceUUIDs = uuid128List(data)
		}
	case 0x08, 0x09: // Shortened / Complete Local Name
		s.LocalName = strings.ToValidUTF8(string(data), "?")
	case 0x0A: // TX Power Level (signed dBm)
		if len(data) >= 1 {
			p := int(int8(data[0]))
			s.TxPowerDBm = &p
		}
	case 0x19: // Appearance (2 bytes, little-endian)
		if len(data) >= 2 {
			s.Appearance = appearanceName(binary.LittleEndian.Uint16(data))
		}
	case 0x1C: // LE Role
		if len(data) >= 1 {
			s.LERole = leRoleName(data[0])
		}
	case 0x24: // URI (1-byte scheme prefix code + UTF-8)
		s.URI = decodeURI(data)
	case 0x16: // Service Data - 16-bit UUID
		decodeServiceData16(&s, data)
	case 0x20: // Service Data - 32-bit UUID
		if len(data) >= 4 {
			s.ServiceData = &ServiceData{UUID: fmt.Sprintf("0x%08X (32-bit)", binary.LittleEndian.Uint32(data[0:4])), DataHex: hexUpper(data[4:])}
		}
	case 0x21: // Service Data - 128-bit UUID
		if len(data) >= 16 {
			s.ServiceData = &ServiceData{UUID: uuid128(data[0:16]), DataHex: hexUpper(data[16:])}
		}
	case 0xFF: // Manufacturer Specific Data
		decodeManufacturer(&s, data)
	default:
		if len(data) > 0 {
			s.Raw = hexUpper(data)
		}
	}
	return s
}

// decodeServiceData16 handles AD type 0x16 — and decodes the Eddystone frame
// when the service UUID is 0xFEAA.
func decodeServiceData16(s *Structure, data []byte) {
	if len(data) < 2 {
		if len(data) > 0 {
			s.Raw = hexUpper(data)
		}
		return
	}
	u := binary.LittleEndian.Uint16(data[0:2])
	body := data[2:]
	s.ServiceData = &ServiceData{UUID: fmt.Sprintf("0x%04X (16-bit)", u), DataHex: hexUpper(body)}
	if u == 0xFEAA {
		s.Eddystone = decodeEddystone(body)
	}
}

// decodeManufacturer handles AD type 0xFF — names the company and decodes the
// Apple iBeacon sub-format; everything else (incl. Apple Continuity) is raw.
func decodeManufacturer(s *Structure, data []byte) {
	if len(data) < 2 {
		if len(data) > 0 {
			s.Raw = hexUpper(data)
		}
		return
	}
	company := binary.LittleEndian.Uint16(data[0:2])
	body := data[2:]
	s.Manufacturer = &Manufacturer{
		CompanyID:   fmt.Sprintf("0x%04X", company),
		CompanyName: companyName(company),
		DataHex:     hexUpper(body),
	}
	// Apple iBeacon: company 0x004C, sub-type 0x02, sub-length 0x15 (21), then
	// 16-byte proximity UUID + 2-byte major (BE) + 2-byte minor (BE) + signed
	// measured power.
	if company == 0x004C && len(body) >= 23 && body[0] == 0x02 && body[1] == 0x15 {
		s.IBeacon = &IBeacon{
			UUID:          uuid128msb(body[2:18]),
			Major:         int(binary.BigEndian.Uint16(body[18:20])),
			Minor:         int(binary.BigEndian.Uint16(body[20:22])),
			MeasuredPower: int(int8(body[22])),
		}
		return
	}
	if company == 0x004C {
		s.Notes = "Apple manufacturer data that is not iBeacon (e.g. the proprietary Continuity / Nearby / Handoff stream) is surfaced raw — its sub-types are undocumented"
	}
}

// decodeEddystone parses an Eddystone service-data body (after the 0xFEAA UUID).
// https://github.com/google/eddystone — frame type in the first byte.
func decodeEddystone(b []byte) *Eddystone {
	if len(b) < 1 {
		return nil
	}
	e := &Eddystone{}
	switch b[0] {
	case 0x00: // UID
		e.FrameType = "UID"
		if len(b) >= 18 {
			p := int(int8(b[1]))
			e.TxPower0mDBm = &p
			e.NamespaceHex = hexUpper(b[2:12])
			e.InstanceHex = hexUpper(b[12:18])
		} else {
			e.Raw = hexUpper(b)
		}
	case 0x10: // URL
		e.FrameType = "URL"
		if len(b) >= 3 {
			p := int(int8(b[1]))
			e.TxPower0mDBm = &p
			e.URL = decodeEddystoneURL(b[2], b[3:])
		} else {
			e.Raw = hexUpper(b)
		}
	case 0x20: // TLM
		e.FrameType = "TLM"
		if len(b) >= 14 && b[1] == 0x00 { // version 0x00 = unencrypted
			mv := int(binary.BigEndian.Uint16(b[2:4]))
			e.BatteryMV = &mv
			t := fix88(b[4:6])
			e.TemperatureC = &t
			c := binary.BigEndian.Uint32(b[6:10])
			e.AdvCount = &c
			up := float64(binary.BigEndian.Uint32(b[10:14])) / 10.0 // 0.1 s units
			e.UptimeSeconds = &up
		} else {
			e.Raw = hexUpper(b)
		}
	case 0x30: // EID
		e.FrameType = "EID"
		e.Raw = hexUpper(b)
	default:
		e.FrameType = fmt.Sprintf("unknown (0x%02X)", b[0])
		e.Raw = hexUpper(b)
	}
	return e
}

// fix88 reads a signed 8.8 fixed-point big-endian temperature.
func fix88(b []byte) float64 {
	return float64(int16(binary.BigEndian.Uint16(b))) / 256.0
}

// decodeEddystoneURL expands the Eddystone-URL scheme prefix byte and the
// in-band domain abbreviations.
func decodeEddystoneURL(scheme byte, body []byte) string {
	prefixes := []string{"http://www.", "https://www.", "http://", "https://"}
	var sb strings.Builder
	if int(scheme) < len(prefixes) {
		sb.WriteString(prefixes[scheme])
	} else {
		fmt.Fprintf(&sb, "<scheme 0x%02X>", scheme)
	}
	expansions := []string{
		".com/", ".org/", ".edu/", ".net/", ".info/", ".biz/", ".gov/",
		".com", ".org", ".edu", ".net", ".info", ".biz", ".gov",
	}
	for _, c := range body {
		if int(c) < len(expansions) {
			sb.WriteString(expansions[c])
		} else if c >= 0x20 && c < 0x7F {
			sb.WriteByte(c)
		} else {
			fmt.Fprintf(&sb, "\\x%02x", c)
		}
	}
	return sb.String()
}

func decodeFlags(f byte) []string {
	var out []string
	bits := []struct {
		mask byte
		name string
	}{
		{0x01, "LE Limited Discoverable Mode"},
		{0x02, "LE General Discoverable Mode"},
		{0x04, "BR/EDR Not Supported"},
		{0x08, "Simultaneous LE and BR/EDR (Controller)"},
		{0x10, "Simultaneous LE and BR/EDR (Host)"},
	}
	for _, b := range bits {
		if f&b.mask != 0 {
			out = append(out, b.name)
		}
	}
	if len(out) == 0 {
		out = append(out, "none set")
	}
	return out
}

func uuid16List(b []byte) []string {
	var out []string
	for i := 0; i+2 <= len(b); i += 2 {
		out = append(out, fmt.Sprintf("0x%04X", binary.LittleEndian.Uint16(b[i:i+2])))
	}
	return out
}

func uuid32List(b []byte) []string {
	var out []string
	for i := 0; i+4 <= len(b); i += 4 {
		out = append(out, fmt.Sprintf("0x%08X", binary.LittleEndian.Uint32(b[i:i+4])))
	}
	return out
}

func uuid128List(b []byte) []string {
	var out []string
	for i := 0; i+16 <= len(b); i += 16 {
		out = append(out, uuid128(b[i:i+16]))
	}
	return out
}

// uuid128 renders a 128-bit UUID from little-endian wire bytes.
func uuid128(b []byte) string { return uuid128msb(reverse(b)) }

// uuid128msb renders a 128-bit UUID from MSB-first bytes.
func uuid128msb(b []byte) string {
	if len(b) != 16 {
		return hexUpper(b)
	}
	s := hexUpper(b)
	return fmt.Sprintf("%s-%s-%s-%s-%s", s[0:8], s[8:12], s[12:16], s[16:20], s[20:32])
}

func reverse(b []byte) []byte {
	r := make([]byte, len(b))
	for i := range b {
		r[i] = b[len(b)-1-i]
	}
	return r
}

func decodeURI(b []byte) string {
	if len(b) < 1 {
		return ""
	}
	// First byte is a scheme-prefix code (Bluetooth Assigned Numbers, URI
	// scheme name string mapping). 0x16 = "http:", 0x17 = "https:". The rest is
	// UTF-8; surface the documented common prefixes, else mark the code.
	rest := strings.ToValidUTF8(string(b[1:]), "?")
	switch b[0] {
	case 0x16:
		return "http:" + rest
	case 0x17:
		return "https:" + rest
	case 0x01:
		// 0x01 is the "no scheme; rest is the full URI" sentinel.
		return rest
	default:
		return fmt.Sprintf("<scheme 0x%02X>%s", b[0], rest)
	}
}

func adTypeName(t byte) string {
	names := map[byte]string{
		0x01: "Flags",
		0x02: "Incomplete List of 16-bit Service Class UUIDs",
		0x03: "Complete List of 16-bit Service Class UUIDs",
		0x04: "Incomplete List of 32-bit Service Class UUIDs",
		0x05: "Complete List of 32-bit Service Class UUIDs",
		0x06: "Incomplete List of 128-bit Service Class UUIDs",
		0x07: "Complete List of 128-bit Service Class UUIDs",
		0x08: "Shortened Local Name",
		0x09: "Complete Local Name",
		0x0A: "Tx Power Level",
		0x0D: "Class of Device",
		0x0E: "Simple Pairing Hash C-192",
		0x0F: "Simple Pairing Randomizer R-192",
		0x10: "Device ID / Security Manager TK Value",
		0x11: "Security Manager Out of Band Flags",
		0x12: "Peripheral Connection Interval Range",
		0x14: "List of 16-bit Service Solicitation UUIDs",
		0x15: "List of 128-bit Service Solicitation UUIDs",
		0x16: "Service Data - 16-bit UUID",
		0x17: "Public Target Address",
		0x18: "Random Target Address",
		0x19: "Appearance",
		0x1A: "Advertising Interval",
		0x1B: "LE Bluetooth Device Address",
		0x1C: "LE Role",
		0x1D: "Simple Pairing Hash C-256",
		0x1E: "Simple Pairing Randomizer R-256",
		0x1F: "List of 32-bit Service Solicitation UUIDs",
		0x20: "Service Data - 32-bit UUID",
		0x21: "Service Data - 128-bit UUID",
		0x22: "LE Secure Connections Confirmation Value",
		0x23: "LE Secure Connections Random Value",
		0x24: "URI",
		0x25: "Indoor Positioning",
		0x26: "Transport Discovery Data",
		0x27: "LE Supported Features",
		0x28: "Channel Map Update Indication",
		0x29: "PB-ADV",
		0x2A: "Mesh Message",
		0x2B: "Mesh Beacon",
		0x2C: "BIGInfo",
		0x2D: "Broadcast_Code",
		0x2E: "Resolvable Set Identifier",
		0x2F: "Advertising Interval - long",
		0x30: "Broadcast_Name",
		0x3D: "3D Information Data",
		0xFF: "Manufacturer Specific Data",
	}
	if n, ok := names[t]; ok {
		return n
	}
	return fmt.Sprintf("AD type 0x%02X", t)
}

func leRoleName(v byte) string {
	switch v {
	case 0x00:
		return "Only Peripheral Role supported"
	case 0x01:
		return "Only Central Role supported"
	case 0x02:
		return "Peripheral and Central; Peripheral preferred for connection"
	case 0x03:
		return "Peripheral and Central; Central preferred for connection"
	default:
		return fmt.Sprintf("0x%02X (reserved)", v)
	}
}

// appearanceName maps the GATT Appearance category (top 10 bits) to a name.
func appearanceName(v uint16) string {
	cat := v >> 6
	cats := map[uint16]string{
		0x000: "Unknown", 0x001: "Phone", 0x002: "Computer", 0x003: "Watch",
		0x004: "Clock", 0x005: "Display", 0x006: "Remote Control", 0x007: "Eye-glasses",
		0x008: "Tag", 0x009: "Keyring", 0x00A: "Media Player", 0x00B: "Barcode Scanner",
		0x00C: "Thermometer", 0x00D: "Heart Rate Sensor", 0x00E: "Blood Pressure",
		0x00F: "Human Interface Device", 0x010: "Glucose Meter", 0x011: "Running Walking Sensor",
		0x012: "Cycling", 0x013: "Control Device", 0x014: "Network Device",
		0x015: "Sensor", 0x016: "Light Fixtures", 0x017: "Fan", 0x018: "HVAC",
		0x019: "Air Conditioning", 0x01A: "Humidifier", 0x01B: "Heating",
		0x01C: "Access Control", 0x01D: "Motorized Device", 0x01E: "Power Device",
		0x01F: "Light Source", 0x021: "Pulse Oximeter", 0x022: "Weight Scale",
		0x023: "Personal Mobility Device", 0x024: "Continuous Glucose Monitor",
		0x025: "Insulin Pump", 0x026: "Medication Delivery", 0x031: "Outdoor Sports Activity",
		0x051: "Audio Sink", 0x052: "Audio Source", 0x053: "Motorized Vehicle",
		0x054: "Domestic Appliance", 0x055: "Wearable Audio Device", 0x056: "Aircraft",
		0x057: "AV Equipment", 0x058: "Display Equipment", 0x059: "Hearing aid",
		0x05A: "Gaming", 0x05B: "Signage",
	}
	if n, ok := cats[cat]; ok {
		return fmt.Sprintf("0x%04X (%s)", v, n)
	}
	return fmt.Sprintf("0x%04X (category 0x%03X)", v, cat)
}

// companyName maps a Bluetooth SIG Company Identifier to a name. Curated to the
// identifiers a BLE scan most commonly surfaces; an unknown id is reported by
// value (not guessed).
func companyName(id uint16) string {
	names := map[uint16]string{
		0x0006: "Microsoft",
		0x0075: "Samsung Electronics",
		0x004C: "Apple, Inc.",
		0x00E0: "Google",
		0x0059: "Nordic Semiconductor ASA",
		0x000F: "Broadcom",
		0x0001: "Ericsson Technology Licensing",
		0x0002: "Intel Corp.",
		0x000A: "Cambridge Silicon Radio (Qualcomm)",
		0x0157: "Tile, Inc.",
		0x0118: "Garmin International",
		0x0087: "Garmin International",
		0x004F: "Logitech International",
		0x0131: "Cypress Semiconductor",
		0x05A7: "Sonos Inc",
		0x0171: "Amazon.com Services",
		0x038F: "Xiaomi Inc.",
		0x0499: "Ruuvi Innovations Ltd.",
		0x0030: "ST Microelectronics",
		0x000D: "Texas Instruments Inc.",
		0x0078: "Nike, Inc.",
		0x0110: "Bose Corporation",
		0x01D1: "Espressif Systems",
		0x0A8D: "Espressif Systems",
		0x015D: "Estimote, Inc.",
		0x008A: "Bose Corporation",
		0x0154: "Fitbit, Inc.",
	}
	if n, ok := names[id]; ok {
		return n
	}
	return "unknown company (not guessed)"
}

func hexUpper(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) }

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("bleadv: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("bleadv: input is not valid hex: %w", err)
	}
	return b, nil
}
