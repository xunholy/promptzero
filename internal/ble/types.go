package ble

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Apple Continuity action types. Sourced from furiousMAC/continuity
// (https://github.com/furiousMAC/continuity), AppleJuice / AppleBleee
// reverse-engineering writeups, and the Wall-of-Flippers ruleset.
// Type bytes that operators see in the wild but that aren't formally
// documented appear in actionTypeNames with their best-known label
// and a "(undocumented)" suffix.
var actionTypeNames = map[byte]string{
	0x02: "iBeacon",
	0x03: "AirPrint",
	0x05: "AirDrop",
	0x06: "HomeKit",
	0x07: "ProximityPairing",
	0x08: "HeySiri",
	0x09: "AirPlayTarget",
	0x0A: "AirPlaySource",
	0x0B: "MagicSwitch",
	0x0C: "Handoff",
	0x0D: "InstantHotspotTethering",
	0x0E: "TetheringTargetPresence",
	0x0F: "NearbyAction",
	0x10: "NearbyInfo",
	0x12: "OfflineFinding",
}

func actionTypeName(t byte) string {
	if n, ok := actionTypeNames[t]; ok {
		return n
	}
	return "Unknown"
}

// decodeFields dispatches per-action-type field decoders for the
// well-documented Continuity types. Returns the field map and an
// optional warning when the payload is too short for the documented
// shape (the operator still gets the raw hex; the warning flags
// that fields may be partial).
//
// For types we don't dissect further (HomeKit, HeySiri, AirPlay*,
// AirPrint, Offline Finding — all have private/encrypted bodies
// past the public prefix) we return nil so the JSON stays compact.
func decodeFields(t byte, v []byte) (map[string]any, string) {
	switch t {
	case 0x02: // iBeacon
		return decodeIBeacon(v)
	case 0x05: // AirDrop
		return decodeAirDrop(v)
	case 0x07: // ProximityPairing (AirPods etc.)
		return decodeProximityPairing(v)
	case 0x0B: // MagicSwitch
		return decodeMagicSwitch(v)
	case 0x0C: // Handoff
		return decodeHandoff(v)
	case 0x0D: // InstantHotspotTethering
		return decodeTethering(v)
	case 0x0F: // NearbyAction
		return decodeNearbyAction(v)
	case 0x10: // NearbyInfo
		return decodeNearbyInfo(v)
	}
	return nil, ""
}

// decodeIBeacon parses an iBeacon payload — the Apple variant is
// well-documented: 16-byte ProximityUUID, 2-byte Major, 2-byte
// Minor, 1-byte measured Tx power at 1m.
//
// Note: iBeacon predates the formal Continuity catalog; some
// firmwares emit it under Continuity (type 0x02) while others use
// the older Apple iBeacon advertisement (type 0x02 + sub-prefix
// 0x15). We render the 21-byte shape; shorter payloads return a
// warning.
func decodeIBeacon(v []byte) (map[string]any, string) {
	if len(v) < 21 {
		return nil, fmt.Sprintf("iBeacon payload %d bytes; want ≥21", len(v))
	}
	return map[string]any{
		"proximity_uuid": hexString(v[0:16]),
		"major":          int(v[16])<<8 | int(v[17]),
		"minor":          int(v[18])<<8 | int(v[19]),
		"tx_power_dbm":   int8(v[20]),
	}, ""
}

// decodeAirDrop parses an AirDrop payload (action 0x05). The public
// shape is 18 bytes:
//
//	prefix:8 + AppleID-hash:2 + Phone-hash:2 + Email-hash:2 +
//	  Email2-hash:2 + ZeroSuffix:2 — actually a version + 8 zero
//	  bytes + 4 contact-hash 16-bit values + version-byte suffix.
//
// Implementations vary; we report the version, the suffix byte
// (often "VersionMinor"), and the four hash slots verbatim so an
// operator can cross-reference with their own AirDrop scan.
func decodeAirDrop(v []byte) (map[string]any, string) {
	if len(v) < 18 {
		return nil, fmt.Sprintf("AirDrop payload %d bytes; want ≥18", len(v))
	}
	return map[string]any{
		"version":      int(v[0]),
		"appleid_hash": hexString(v[9:11]),
		"phone_hash":   hexString(v[11:13]),
		"email_hash":   hexString(v[13:15]),
		"email2_hash":  hexString(v[15:17]),
		"suffix":       int(v[17]),
	}, ""
}

// decodeProximityPairing parses the public prefix of a Proximity
// Pairing payload (action 0x07). AirPods, Beats and the wider
// "magic pairing" family all use this. The public-facing fields
// are the first 10 bytes; the rest is encrypted with a session key
// that's negotiated out-of-band.
//
// Public shape:
//
//	prefix:1 + device_model:2 + status:1 + battery_left:1 +
//	  battery_right:1 + battery_case_lid_state:1 + lid_open_counter:1 +
//	  device_color:1 + reserved:1
//
// Two notable models we name inline; everything else is rendered as
// hex for the operator to look up.
func decodeProximityPairing(v []byte) (map[string]any, string) {
	if len(v) < 9 {
		return nil, fmt.Sprintf("ProximityPairing payload %d bytes; want ≥9", len(v))
	}
	model := uint16(v[1])<<8 | uint16(v[2])
	fields := map[string]any{
		"prefix":          int(v[0]),
		"device_model":    fmt.Sprintf("%04X", model),
		"device_model_id": int(model),
		"status":          int(v[3]),
		"battery_left":    decodeBatteryNibble(v[4] >> 4),
		"battery_right":   decodeBatteryNibble(v[4] & 0x0F),
		"battery_case":    decodeBatteryNibble(v[5] >> 4),
		"charging_state":  fmt.Sprintf("%01X", v[5]&0x0F),
		"lid_counter":     int(v[6]),
		"device_color":    int(v[7]),
		"reserved":        int(v[8]),
	}
	if name, ok := proximityModels[model]; ok {
		fields["device_model_name"] = name
	}
	if len(v) > 9 {
		fields["encrypted_tail"] = hexString(v[9:])
	}
	return fields, ""
}

// decodeBatteryNibble maps the public battery nibble convention
// (0-10 = 0-100% in 10% steps, 0xF = not-charging-sentinel). We
// surface both the raw nibble and a percent (or -1 for sentinel)
// so callers don't have to know the encoding.
func decodeBatteryNibble(n byte) map[string]any {
	out := map[string]any{"raw": int(n)}
	if n <= 10 {
		out["percent"] = int(n) * 10
	} else {
		out["percent"] = -1
	}
	return out
}

// proximityModels maps the public 2-byte device-model identifier to
// a human name. Kept short — the field grows quickly with each
// AirPods/Beats generation. Operators can extend by editing this
// table; the decoder doesn't depend on coverage.
var proximityModels = map[uint16]string{
	0x0220: "AirPods (1st gen)",
	0x0F20: "AirPods (2nd gen)",
	0x1320: "AirPods (3rd gen)",
	0x0E20: "AirPods Pro",
	0x1420: "AirPods Pro (2nd gen)",
	0x0A20: "AirPods Max",
	0x0520: "AirPods (Beats)",
	0x0620: "Beats Solo3",
	0x0920: "BeatsX",
	0x0B20: "BeatsStudio3",
	0x1120: "Powerbeats Pro",
	0x1220: "Beats Solo Pro",
}

// decodeMagicSwitch parses a MagicSwitch payload (action 0x0B).
// 3-byte body: 2-byte data + 1-byte confidence/encoding-state. We
// surface the raw form — Apple doesn't publish the field meaning.
func decodeMagicSwitch(v []byte) (map[string]any, string) {
	if len(v) < 3 {
		return nil, fmt.Sprintf("MagicSwitch payload %d bytes; want ≥3", len(v))
	}
	return map[string]any{
		"data":       hexString(v[0:2]),
		"confidence": int(v[2]),
	}, ""
}

// decodeHandoff parses a Handoff payload (action 0x0C). 14-byte
// public shape:
//
//	clipboard_status:1 + sequence_iv:2 + auth_tag:1 + encrypted:10
//
// The encrypted body is AES-GCM under a session key we can't
// recover; we surface clipboard status + IV + auth tag so an
// operator can correlate sequential captures from the same source.
func decodeHandoff(v []byte) (map[string]any, string) {
	if len(v) < 14 {
		return nil, fmt.Sprintf("Handoff payload %d bytes; want ≥14", len(v))
	}
	return map[string]any{
		"clipboard_status": int(v[0]),
		"sequence_iv":      int(v[1])<<8 | int(v[2]),
		"auth_tag":         fmt.Sprintf("%02X", v[3]),
		"encrypted":        hexString(v[4:14]),
	}, ""
}

// decodeTethering parses the Instant Hotspot / Tethering payload
// (action 0x0D). 6-byte shape:
//
//	flags:1 + battery_life:1 + cell_service_type:2 +
//	  cell_service_strength:1 + cell_data_type:1
//
// Battery life is a 0-100 percent; cell service strength is the
// signal-bar nibble; the type bytes are operator-facing values
// (LTE/5G/Wi-Fi-Calling) that we leave as raw codes — Apple has
// changed the encoding across iOS versions.
func decodeTethering(v []byte) (map[string]any, string) {
	if len(v) < 6 {
		return nil, fmt.Sprintf("Tethering payload %d bytes; want ≥6", len(v))
	}
	return map[string]any{
		"flags":                 int(v[0]),
		"battery_percent":       int(v[1]),
		"cell_service_type":     int(v[2])<<8 | int(v[3]),
		"cell_service_strength": int(v[4]),
		"cell_data_type":        int(v[5]),
	}, ""
}

// decodeNearbyAction parses an Action 0x0F payload. 5-byte shape:
//
//	flags:1 + action_type:1 + auth_tag:3
//
// We map a handful of well-known action types ("WiFi password
// request", "Apple TV setup") and leave the rest as raw codes.
func decodeNearbyAction(v []byte) (map[string]any, string) {
	if len(v) < 5 {
		return nil, fmt.Sprintf("NearbyAction payload %d bytes; want ≥5", len(v))
	}
	at := v[1]
	fields := map[string]any{
		"flags":           int(v[0]),
		"action_type":     int(at),
		"action_type_hex": fmt.Sprintf("%02X", at),
		"auth_tag":        hexString(v[2:5]),
	}
	if name, ok := nearbyActionTypes[at]; ok {
		fields["action_name"] = name
	}
	return fields, ""
}

// nearbyActionTypes maps the documented action codes. Drawn from
// furiousMAC/continuity's nearbyaction.md.
var nearbyActionTypes = map[byte]string{
	0x01: "AppleTVSetup",
	0x04: "MobileBackupSetup",
	0x05: "WatchSetup",
	0x06: "AppleIDSetup",
	0x07: "InternetRelay",
	0x08: "WiFiPasswordRequest",
	0x09: "iOSSetup",
	0x0A: "RepairMode",
	0x0B: "Speaker",
	0x0C: "AppleTVPair",
	0x0D: "HomeKitSetup",
	0x0E: "AccessoryUnpaired",
	0x0F: "DevToolsPair",
	0x10: "AnisetteV2",
	0x11: "HomePodSetup",
	0x13: "AccessorySetup",
	0x14: "AccessoryUnreachable",
	0x15: "AppleVision",
	0x17: "HomeKitConfiguration",
	0x19: "TrackingActionTypeMail",
	0x20: "WidgetDiscovery",
}

// decodeNearbyInfo parses a NearbyInfo payload (action 0x10).
// 5-byte shape:
//
//	status:1 + flags:1 + auth_tag:3
//
// The status nibble has documented meanings ("AirDrop receiving",
// "primary device", etc.); the flags byte is a bitfield with both
// documented and reserved bits. We surface both raw and decoded
// forms so a developer can cross-reference against Apple's flag
// catalog.
func decodeNearbyInfo(v []byte) (map[string]any, string) {
	if len(v) < 5 {
		return nil, fmt.Sprintf("NearbyInfo payload %d bytes; want ≥5", len(v))
	}
	status := v[0]
	flags := v[1]
	fields := map[string]any{
		"status":             int(status),
		"status_hex":         fmt.Sprintf("%02X", status),
		"action_code":        int(status & 0x0F),
		"status_flags":       int(status >> 4),
		"data_flags":         int(flags),
		"data_flags_hex":     fmt.Sprintf("%02X", flags),
		"auth_tag":           hexString(v[2:5]),
		"data_flags_decoded": decodeNearbyInfoFlags(flags),
	}
	if name, ok := nearbyInfoActionCodes[status&0x0F]; ok {
		fields["action_code_name"] = name
	}
	return fields, ""
}

// nearbyInfoActionCodes is the documented action-code nibble
// catalog from furiousMAC/continuity nearbyinfo.md.
var nearbyInfoActionCodes = map[byte]string{
	0x00: "Activity Level - Unknown",
	0x01: "Activity Level - Activity reporting disabled",
	0x03: "Activity Level - Idle",
	0x05: "Activity Level - Audio playing",
	0x07: "Activity Level - Screen on",
	0x09: "Activity Level - Screen on + video playing",
	0x0A: "Activity Level - Watch on wrist",
	0x0B: "Activity Level - Recent user interaction",
	0x0D: "Activity Level - User is driving a vehicle",
	0x0E: "Activity Level - Phone or Facetime call",
}

// decodeNearbyInfoFlags expands the documented bits of the
// data-flags byte. Reserved bits are not surfaced (any non-zero
// value the operator should treat as suspicious; we leave that
// decision to the defense classifier rather than encoding it here).
func decodeNearbyInfoFlags(f byte) []string {
	var out []string
	if f&0x80 != 0 {
		out = append(out, "primary_device")
	}
	if f&0x40 != 0 {
		out = append(out, "airpod_connection")
	}
	if f&0x20 != 0 {
		out = append(out, "auth_tag_present")
	}
	if f&0x10 != 0 {
		out = append(out, "wifi_on")
	}
	if f&0x08 != 0 {
		out = append(out, "watch_unlocked")
	}
	if f&0x04 != 0 {
		out = append(out, "auto_unlock_enabled")
	}
	if f&0x02 != 0 {
		out = append(out, "auto_unlock_unlocked")
	}
	if f&0x01 != 0 {
		out = append(out, "is_ipad")
	}
	return out
}

// hexString is a small helper — uppercase hex with no separators.
func hexString(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}
