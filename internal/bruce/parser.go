package bruce

import (
	"regexp"
	"strconv"
	"strings"
)

// --- Banner parsing ---------------------------------------------------------

// bannerVersionRE matches "Bruce <semver>" anywhere in the banner line.
var bannerVersionRE = regexp.MustCompile(`(?i)bruce\s+(\d+\.\d+[\w.]*)`)

// ParseBanner extracts Capabilities from the Bruce boot banner string.
//
// Bruce banners observed in the wild (source:
// https://github.com/pr3y/Bruce/wiki/Supported-Boards):
//
//	"Bruce 1.0.4 M5StackCardputer"
//	"Bruce 1.2 ESP32-C5 5G"
//	"Bruce 1.1 M5StickCPlus2"
//	"Bruce 1.3 T-Display-S3"
//	"Bruce 1.0 CYD"      (Cheap Yellow Display)
//
// Capability rules:
//   - HasFiveGHz  — banner contains "ESP32-C5" or "5G" (case-insensitive)
//   - HasZigbee   — banner contains "Zigbee" (case-insensitive)
//   - HasLoRa     — banner contains "LoRa" (case-insensitive)
//   - HasNFC      — banner contains "NFC" or "PN532" (case-insensitive)
//   - HasIR       — banner contains "IR" or any known IR-capable board name
//     (Cardputer, M5Stick, T-Display have IR by default)
//   - BoardType   — normalized lowercase token derived from the board identifier
//   - FirmwareVersion — semver string from the banner
func ParseBanner(banner string) Capabilities {
	caps := Capabilities{}
	lower := strings.ToLower(banner)

	// Firmware version
	if m := bannerVersionRE.FindStringSubmatch(banner); m != nil {
		caps.FirmwareVersion = m[1]
	}

	// 5 GHz: ESP32-C5 is the only currently-supported 5 GHz variant.
	if strings.Contains(lower, "esp32-c5") || strings.Contains(lower, "5g") {
		caps.HasFiveGHz = true
	}

	// Zigbee
	if strings.Contains(lower, "zigbee") {
		caps.HasZigbee = true
	}

	// LoRa
	if strings.Contains(lower, "lora") {
		caps.HasLoRa = true
	}

	// NFC — explicit tag or PN532 module mentioned
	if strings.Contains(lower, "nfc") || strings.Contains(lower, "pn532") {
		caps.HasNFC = true
	}

	// IR — explicit tag or boards that ship with IR hardware by default
	// (https://github.com/pr3y/Bruce/wiki/Supported-Boards)
	if strings.Contains(lower, " ir") ||
		strings.Contains(lower, "cardputer") ||
		strings.Contains(lower, "m5stick") ||
		strings.Contains(lower, "t-display") ||
		strings.Contains(lower, "tdisplay") {
		caps.HasIR = true
	}

	// Board type
	caps.BoardType = parseBoardType(lower)

	return caps
}

// parseBoardType derives a normalized board identifier from the lowercase banner.
func parseBoardType(lower string) string {
	switch {
	case strings.Contains(lower, "cardputer"):
		return "cardputer"
	case strings.Contains(lower, "m5stickcplus2"):
		return "m5stickcplus2"
	case strings.Contains(lower, "m5stickc"):
		return "m5stickc"
	case strings.Contains(lower, "t-display-s3"), strings.Contains(lower, "tdisplays3"):
		return "t-display-s3"
	case strings.Contains(lower, "t-display"):
		return "t-display"
	case strings.Contains(lower, "esp32-c5"):
		return "esp32-c5"
	case strings.Contains(lower, "cyd"):
		return "cyd"
	case strings.Contains(lower, "esp32"):
		return "esp32"
	default:
		return ""
	}
}

// --- AP list parsing --------------------------------------------------------

// apBSSIDRE matches a 6-octet MAC address anywhere in a line.
var apBSSIDRE = regexp.MustCompile(`([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})`)

// apRSSIRE matches "RSSI: -42" or "-42dBm".
var apRSSIRE = regexp.MustCompile(`(?:RSSI|rssi)\s*[=:]\s*(-?\d+)|-?\d+\s*[dD][bB][mM]`)

// apChannelRE matches "CH: 6" or "ch6" etc.
var apChannelRE = regexp.MustCompile(`(?i)(?:ch(?:an(?:nel)?)?)\s*[=:]?\s*(\d+)`)

// apSSIDRE matches "SSID: HomeName" (with or without quotes).
var apSSIDRE = regexp.MustCompile(`(?i)(?:SSID)\s*[=:]\s*"?([^",\n]+)"?`)

// ParseAPList parses Bruce AP-scan output into a slice of AP structs.
// band is annotated on each AP ("2.4GHz" or "5GHz").
// Lines that cannot be parsed as APs are silently skipped; callers that need
// the raw text can use the AP.RawLine field for traceability.
func ParseAPList(raw, band string) []AP {
	var aps []AP
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		ap, ok := parseAPLine(line, band)
		if ok {
			aps = append(aps, ap)
		}
	}
	return aps
}

func parseAPLine(line, band string) (AP, bool) {
	ap := AP{RawLine: line, Band: band}

	if m := apBSSIDRE.FindStringSubmatch(line); m != nil {
		ap.BSSID = strings.ToLower(m[1])
	}

	if m := apSSIDRE.FindStringSubmatch(line); m != nil {
		ap.SSID = strings.TrimSpace(m[1])
	}

	if m := apRSSIRE.FindStringSubmatch(line); m != nil {
		raw := m[1]
		if raw == "" {
			// "<N>dBm" form — strip non-numeric suffix
			raw = strings.TrimRight(m[0], "dDbBmM ")
		}
		if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
			ap.RSSI = n
		}
	}

	if m := apChannelRE.FindStringSubmatch(line); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			ap.Channel = n
		}
	}

	// Require at least a BSSID or SSID to count as a real AP row.
	if ap.BSSID == "" && ap.SSID == "" {
		return AP{}, false
	}
	return ap, true
}

// --- Zigbee parsing ---------------------------------------------------------

// zigbeePANRE matches "PAN: 0x1234" or "PAN ID: 0x1234".
var zigbeePANRE = regexp.MustCompile(`(?i)PAN\s*(?:ID)?\s*[=:]\s*(0x[0-9a-fA-F]+|\d+)`)

// zigbeeAddrRE matches "Addr: 0x1234" or "Short: 0x5678".
var zigbeeAddrRE = regexp.MustCompile(`(?i)(?:addr|short)\s*[=:]\s*(0x[0-9a-fA-F]+|\d+)`)

// zigbeeChanRE matches "Ch: 11" or "Channel: 26".
var zigbeeChanRE = regexp.MustCompile(`(?i)ch(?:an(?:nel)?)?\s*[=:]\s*(\d+)`)

// ParseZigbeeList parses Bruce Zigbee/IEEE 802.15.4 scan output into a slice
// of ZigbeePeer structs.
func ParseZigbeeList(raw string) []ZigbeePeer {
	var peers []ZigbeePeer
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p, ok := parseZigbeeLine(line)
		if ok {
			peers = append(peers, p)
		}
	}
	return peers
}

func parseZigbeeLine(line string) (ZigbeePeer, bool) {
	p := ZigbeePeer{RawLine: line}
	if m := zigbeePANRE.FindStringSubmatch(line); m != nil {
		p.PANID = m[1]
	}
	if m := zigbeeAddrRE.FindStringSubmatch(line); m != nil {
		p.ShortAddr = m[1]
	}
	if m := zigbeeChanRE.FindStringSubmatch(line); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			p.Channel = n
		}
	}
	if p.PANID == "" && p.ShortAddr == "" {
		return ZigbeePeer{}, false
	}
	return p, true
}

// --- IR capture parsing -----------------------------------------------------

// irProtocolRE matches "Protocol: NEC" etc.
var irProtocolRE = regexp.MustCompile(`(?i)proto(?:col)?\s*[=:]\s*(\S+)`)

// irCodeRE matches "Code: 0xDEADBEEF" or "Data: 12345678".
var irCodeRE = regexp.MustCompile(`(?i)(?:code|data)\s*[=:]\s*(\S+)`)

// ParseCapture parses Bruce IR receive output into a Capture struct.
func ParseCapture(raw string) Capture {
	c := Capture{RawData: raw}
	if m := irProtocolRE.FindStringSubmatch(raw); m != nil {
		c.Protocol = m[1]
	}
	if m := irCodeRE.FindStringSubmatch(raw); m != nil {
		c.Code = m[1]
	}
	return c
}

// --- NFC card parsing -------------------------------------------------------

// nfcUIDRE matches "UID: 04 5A 3B FF" or "UID: 04:5A:3B:FF".
var nfcUIDRE = regexp.MustCompile(`(?i)UID\s*[=:]\s*([0-9a-fA-F: ]+)`)

// nfcATQRE matches "ATQ: 0004" or "ATQA: 0004".
var nfcATQRE = regexp.MustCompile(`(?i)ATQ[A]?\s*[=:]\s*([0-9a-fA-F]+)`)

// nfcSAKRE matches "SAK: 08".
var nfcSAKRE = regexp.MustCompile(`(?i)SAK\s*[=:]\s*([0-9a-fA-F]+)`)

// ParseNFCCard parses Bruce NFC read output into an NFCCard struct.
func ParseNFCCard(raw string) NFCCard {
	card := NFCCard{}
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			card.RawLines = append(card.RawLines, line)
		}
	}
	if m := nfcUIDRE.FindStringSubmatch(raw); m != nil {
		card.UID = strings.TrimSpace(m[1])
	}
	if m := nfcATQRE.FindStringSubmatch(raw); m != nil {
		card.ATQ = m[1]
	}
	if m := nfcSAKRE.FindStringSubmatch(raw); m != nil {
		card.SAK = m[1]
	}
	return card
}
