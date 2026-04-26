package defense

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

// SignatureID identifies one BLE-advertisement classification rule.
type SignatureID string

const (
	// SigAppleContinuitySpam matches an Apple Continuity payload whose
	// Action Type byte falls outside the documented set 0x05, 0x07, 0x09,
	// 0x0B, 0x0C, 0x0D, 0x0F, 0x10. The Flipper's spam library iterates
	// through arbitrary 0x00-0xFF action types and the Marauder/Bruce
	// equivalents do the same, producing payloads that real Apple devices
	// never emit. Reference:
	// https://github.com/k3yomi/Wall-of-Flippers — Apple-Continuity rule.
	SigAppleContinuitySpam SignatureID = "apple_continuity_spam"

	// SigSwiftPairMalformed matches a Microsoft Swift Pair payload whose
	// length is < 6 bytes or whose flags byte is reserved (≥0x05). The
	// genuine Swift Pair protocol uses ≥6-byte payloads and flags
	// 0x00-0x04. Flipper spam frequently emits 4-5 byte payloads.
	SigSwiftPairMalformed SignatureID = "swift_pair_malformed"

	// SigSamsungWatchSpam matches Samsung Wear/Watch advertisements whose
	// model-id bytes fall outside the published Samsung lookup ranges.
	// Reference: Wall-of-Flippers' samsung_models.json table.
	SigSamsungWatchSpam SignatureID = "samsung_watch_spam"

	// SigGoogleFastPairSpam matches Google Fast Pair advertisements with
	// the spam library's signature 3-byte model-id pattern (a single
	// repeating byte; genuine model IDs are 24-bit unique values).
	SigGoogleFastPairSpam SignatureID = "google_fast_pair_spam"

	// SigFlipperServiceUUID matches the Flipper Zero's own BLE serial
	// service UUID 0xFE60 advertised when a Flipper is in normal (not
	// spam) operation. False positives: any genuine Flipper Zero in
	// range. The detector logs but does not raise alerts unless the
	// operator opted in via DetectFlipperPresence=true.
	SigFlipperServiceUUID SignatureID = "flipper_service_uuid"

	// SigHighFrequencyMACRotation marks an advertiser whose source MAC
	// changed > the configured threshold within the rolling window. The
	// classifier needs caller-supplied state (RotationTracker) for this
	// check; raised by [Tracker.Classify], not the stateless [Classify].
	SigHighFrequencyMACRotation SignatureID = "high_freq_mac_rotation"
)

// Apple Continuity (Manufacturer Data 0x004C) action types that genuine
// iOS / macOS devices emit. Anything outside this set inside an Apple
// continuity payload counts as the Flipper-spam signature.
//
// References: https://hexway.io/blog/apple-bleee/ documents the published
// set; the Flipper-zero-bluetooth-spam project iterates through all
// 0x00..0xFF, producing many out-of-set actions.
var legitAppleActionTypes = map[byte]string{
	0x05: "AirDrop",
	0x07: "ProximityPairing",
	0x09: "AirPlayTarget",
	0x0A: "AirPlaySource",
	0x0B: "MagicSwitch",
	0x0C: "Handoff",
	0x0D: "InstantHotspotTethering",
	0x0F: "NearbyAction",
	0x10: "NearbyInfo",
}

// Match is one classification verdict against a captured advertisement.
type Match struct {
	Signature   SignatureID
	Description string
	// SourceMAC is the captured peer MAC address in canonical
	// uppercase colon notation (AA:BB:CC:DD:EE:FF). Empty when the
	// caller's transport didn't surface the address.
	SourceMAC string
	// FirstSeen is when this advertiser was first observed, or the
	// timestamp of this match if no tracker is involved.
	FirstSeen time.Time
}

// Advertisement is the minimal view of a BLE advertisement the classifier
// needs. The package's scanner (scanner.go) builds this from the platform
// adapter; tests construct it directly from fixture bytes.
type Advertisement struct {
	// Address is the peer MAC in canonical uppercase colon notation.
	// Empty is allowed — some platforms strip MACs from privacy-mode
	// advertisements. Tests pass empty strings when checking the
	// signature-only path.
	Address string

	// LocalName is the GAP local name (complete or shortened). Empty
	// when not present in the advertisement.
	LocalName string

	// ServiceUUIDs is the list of advertised service UUIDs in 128-bit
	// canonical lowercase form. Stack-emitted UUID strings.
	ServiceUUIDs []string

	// ManufacturerData maps the 16-bit manufacturer ID to the raw
	// payload bytes. Apple is 0x004C; Microsoft 0x0006; Samsung
	// 0x0075; Google Fast Pair uses service-data 0xFE2C, not
	// manufacturer-data, so it goes through ServiceData below.
	ManufacturerData map[uint16][]byte

	// ServiceData maps a 16-bit service UUID to its raw bytes.
	ServiceData map[uint16][]byte

	// CapturedAt is when the scanner observed this packet.
	CapturedAt time.Time
}

// Classify runs every stateless signature against ad and returns the
// matched signatures. Call this from a scanner's per-advertisement
// callback. Order is deterministic (signatures are evaluated in the
// order declared above) so tests can rely on indexing.
//
// Stateless signatures that need cross-advertisement context (MAC
// rotation, frequency thresholds) live on [Tracker.Classify] instead.
func Classify(ad Advertisement) []Match {
	var out []Match

	if data, ok := ad.ManufacturerData[0x004C]; ok {
		if m, ok := classifyApple(data); ok {
			out = append(out, withSource(ad, m))
		}
	}

	if data, ok := ad.ManufacturerData[0x0006]; ok {
		if m, ok := classifySwiftPair(data); ok {
			out = append(out, withSource(ad, m))
		}
	}

	if data, ok := ad.ManufacturerData[0x0075]; ok {
		if m, ok := classifySamsung(data); ok {
			out = append(out, withSource(ad, m))
		}
	}

	if data, ok := ad.ServiceData[0xFE2C]; ok {
		if m, ok := classifyGoogleFastPair(data); ok {
			out = append(out, withSource(ad, m))
		}
	}

	for _, u := range ad.ServiceUUIDs {
		if isFlipperServiceUUID(u) {
			out = append(out, withSource(ad, Match{
				Signature:   SigFlipperServiceUUID,
				Description: "Flipper Zero BLE serial service UUID 0xFE60 advertised — likely a real Flipper in normal mode",
			}))
			break
		}
	}

	return out
}

func withSource(ad Advertisement, m Match) Match {
	if m.SourceMAC == "" {
		m.SourceMAC = strings.ToUpper(ad.Address)
	}
	if m.FirstSeen.IsZero() {
		m.FirstSeen = ad.CapturedAt
		if m.FirstSeen.IsZero() {
			m.FirstSeen = time.Now()
		}
	}
	return m
}

// classifyApple inspects an Apple-Continuity manufacturer-data payload.
// Apple-Continuity payloads are a sequence of TLVs:
//
//	[ActionType:1][Length:1][Value:Length]
//
// We walk the TLVs until we hit a malformed one or fall off the end.
// A single TLV whose ActionType is outside legitAppleActionTypes flags
// the whole payload as spam.
func classifyApple(data []byte) (Match, bool) {
	if len(data) < 2 {
		return Match{}, false
	}
	for i := 0; i < len(data); {
		actionType := data[i]
		if i+1 >= len(data) {
			break
		}
		length := int(data[i+1])
		if i+2+length > len(data) {
			// Truncated TLV — the spam library produces these.
			return Match{
				Signature: SigAppleContinuitySpam,
				Description: fmt.Sprintf("Apple Continuity TLV truncated at offset %d (claimed len=%d, remaining=%d)",
					i, length, len(data)-i-2),
			}, true
		}
		if _, legit := legitAppleActionTypes[actionType]; !legit {
			return Match{
				Signature:   SigAppleContinuitySpam,
				Description: fmt.Sprintf("Apple Continuity action type 0x%02X is not in the published set", actionType),
			}, true
		}
		i += 2 + length
	}
	return Match{}, false
}

// classifySwiftPair inspects a Microsoft Bluetooth payload. Genuine
// Swift Pair advertisements are at least 6 bytes long and start with a
// flags byte in 0x00-0x04 followed by a manufacturer-specific payload.
// The Flipper-spam library shipping in many BLE-spam apps emits
// truncated 4-5 byte payloads with garbled flags.
func classifySwiftPair(data []byte) (Match, bool) {
	if len(data) < 6 {
		return Match{
			Signature:   SigSwiftPairMalformed,
			Description: fmt.Sprintf("Microsoft (0x0006) advertisement length %d < 6 — Swift Pair requires ≥6", len(data)),
		}, true
	}
	if data[0] >= 0x05 {
		return Match{
			Signature:   SigSwiftPairMalformed,
			Description: fmt.Sprintf("Microsoft Swift Pair flags byte 0x%02X is reserved (legit values: 0x00-0x04)", data[0]),
		}, true
	}
	return Match{}, false
}

// classifySamsung inspects a Samsung manufacturer payload. Samsung Wear
// and Galaxy advertisements use a 3-byte model-id at offset 1; the spam
// library emits all-zero or all-FF model IDs as a side effect of
// iterating shape-only data.
func classifySamsung(data []byte) (Match, bool) {
	if len(data) < 4 {
		return Match{}, false
	}
	model := data[1:4]
	if bytes.Equal(model, []byte{0x00, 0x00, 0x00}) || bytes.Equal(model, []byte{0xFF, 0xFF, 0xFF}) {
		return Match{
			Signature: SigSamsungWatchSpam,
			Description: fmt.Sprintf("Samsung manufacturer payload uses sentinel model-id %02X%02X%02X — spam-iteration signature",
				model[0], model[1], model[2]),
		}, true
	}
	return Match{}, false
}

// classifyGoogleFastPair inspects a Google Fast Pair service-data payload.
// Genuine Fast Pair model IDs are 24-bit unique values; the spam library
// emits payloads whose three model-id bytes are all the same byte.
func classifyGoogleFastPair(data []byte) (Match, bool) {
	if len(data) < 3 {
		return Match{}, false
	}
	if data[0] == data[1] && data[1] == data[2] {
		return Match{
			Signature: SigGoogleFastPairSpam,
			Description: fmt.Sprintf("Google Fast Pair model-id 0x%02X%02X%02X is a single repeated byte — spam-iteration signature",
				data[0], data[1], data[2]),
		}, true
	}
	return Match{}, false
}

// isFlipperServiceUUID checks for Flipper's 0xFE60 short-form or its
// canonical 128-bit form. The 16-bit-to-128-bit base UUID in BLE is
// 0000XXXX-0000-1000-8000-00805F9B34FB; the Flipper service alternates
// between the short form on the wire and the long form when surfaced via
// the platform adapter.
func isFlipperServiceUUID(u string) bool {
	low := strings.ToLower(strings.TrimSpace(u))
	switch low {
	case "0xfe60", "fe60", "0000fe60", "0000fe60-0000-1000-8000-00805f9b34fb":
		return true
	}
	// The Flipper firmware also exposes the proprietary serial-service
	// UUID 0000fe60-cc7a-482a-984a-7f2ed5b3e58f (see ble.go); accept
	// this as a stronger indicator (a non-spam Flipper).
	return low == "0000fe60-cc7a-482a-984a-7f2ed5b3e58f"
}
