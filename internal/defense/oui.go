package defense

import "strings"

// OUI prefix table for hardware commonly used by Flipper-Zero-class
// attackers. v0.22.0. The defensive layer uses this to attribute a
// captured BLE/WiFi advertisement to the most likely transmitter
// family — distinguishing "random Bluetooth headphone" from "Flipper
// running a BLE-spam payload" purely from the OUI.
//
// Keys are uppercase 24-bit OUI prefixes (no separators). Values
// describe the SoC family. Coverage is curated, not exhaustive — the
// goal is to flag *known* attack-capable hardware, not catalogue every
// vendor in the IEEE registry. Add entries when a new attack vehicle
// shows up in the wild.
//
// Source attribution: prefixes drawn from the IEEE Standards
// Association MA-L registry (public domain), augmented with the
// well-known dev-board ranges used by Flipper Zero (BLE peripheral
// and the WiFi devboard) plus the ESP32-class SoCs that Marauder /
// nRF52 spam tools run on.
//
//nolint:gochecknoglobals
var ouiTable = map[string]string{
	// Nordic Semiconductor — nRF52 family (Flipper Zero BLE peripheral,
	// most BLE-spam capable boards). The IEEE assignments span several
	// blocks; these are the high-traffic ones.
	"D040D0": "Nordic Semiconductor (nRF52 — Flipper Zero / BLE-spam capable)",
	"E5984D": "Nordic Semiconductor (nRF52 — Flipper Zero / BLE-spam capable)",
	"5C0272": "Nordic Semiconductor (nRF52 — Flipper Zero / BLE-spam capable)",
	"FC4D8C": "Nordic Semiconductor (nRF52 — Flipper Zero / BLE-spam capable)",
	"D6E2E1": "Nordic Semiconductor (nRF52 — Flipper Zero / BLE-spam capable)",

	// Espressif — ESP32 family (Marauder devboard, WiFi-deauth boards,
	// most BLE-spam appliances built by ESP32 hobbyists).
	"94B97E": "Espressif (ESP32 — Marauder / BLE-spam / WiFi-deauth capable)",
	"24B2DE": "Espressif (ESP32 — Marauder / BLE-spam / WiFi-deauth capable)",
	"08B61F": "Espressif (ESP32 — Marauder / BLE-spam / WiFi-deauth capable)",
	"3C71BF": "Espressif (ESP32 — Marauder / BLE-spam / WiFi-deauth capable)",
	"7C9EBD": "Espressif (ESP32 — Marauder / BLE-spam / WiFi-deauth capable)",
	"E0E2E6": "Espressif (ESP32 — Marauder / BLE-spam / WiFi-deauth capable)",

	// Texas Instruments — CC2540/CC2541 BLE radios used by older
	// Flipper-class peripherals and some commercial BLE jammers.
	"E0E5CF": "Texas Instruments (CC254x — legacy BLE-spam capable)",
	"24DBED": "Texas Instruments (CC254x — legacy BLE-spam capable)",
}

// LookupOUI returns the descriptive label for a captured MAC address,
// or "" when the prefix isn't in the curated attack-hardware list.
// MAC may be in colon, dash, or unseparated form, lower or upper
// case. Anything malformed (too short, non-hex chars) returns "".
//
// Used by the defensive classifier to enrich a Match struct's
// description with attribution evidence — operators see "BLE spam
// from Espressif (ESP32 …)" instead of just "BLE spam from
// AC:BC:DE:01:02:03".
func LookupOUI(mac string) string {
	prefix := canonicalOUIPrefix(mac)
	if prefix == "" {
		return ""
	}
	return ouiTable[prefix]
}

// canonicalOUIPrefix extracts the first three bytes of the MAC,
// stripping separators and upper-casing. Returns "" when input is
// too short or contains non-hex characters.
func canonicalOUIPrefix(mac string) string {
	stripped := strings.Map(func(r rune) rune {
		switch {
		case r == ':' || r == '-' || r == '.':
			return -1
		case r >= '0' && r <= '9':
			return r
		case r >= 'a' && r <= 'f':
			return r - 32 // upper-case
		case r >= 'A' && r <= 'F':
			return r
		}
		return -1 // drop anything else; caller then sees a short string
	}, mac)
	if len(stripped) < 6 {
		return ""
	}
	return stripped[:6]
}

// IsKnownAttackOUI is the boolean form of LookupOUI for callers that
// only need the yes/no signal.
func IsKnownAttackOUI(mac string) bool {
	return LookupOUI(mac) != ""
}
