// Package btuuid resolves Bluetooth SIG-assigned 16-bit GATT
// UUIDs (Services, Characteristics, Descriptors) to their
// canonical names. Pure offline parser; no transport, no
// hardware.
//
// Wrap-vs-native judgement: the Bluetooth SIG Assigned Numbers
// document is fully public. The lookup is a small map +
// 128-bit UUID base-pattern detector. Wrapping a FAP for this
// would require an SD-card install + a firmware-fork dependency
// for a pure lookup. Native delivers offline analysis —
// operators enumerating a BLE GATT database (with bluetoothctl
// / nRF Connect / btmon / Flipper BT scan) paste each UUID
// they see and get the canonical name + category back without
// re-running the enumeration.
//
// Pairs with the existing BLE decoders (ble_gap_decode for
// advertisement records, ble_continuity_decode for Apple
// manufacturer data, ble_eddystone_decode for Google service
// data, bluetooth_cod_decode for the BT Classic side).
//
// What this package covers:
//   - 16-bit UUID lookup: ~75 Services (0x18xx + assorted
//     0xFEXX) + ~250 Characteristics (0x2A0X range) + ~50
//     Descriptors (0x2900 range)
//   - 128-bit UUID detection: matches the standard base
//     UUID 0000XXXX-0000-1000-8000-00805F9B34FB to extract
//     the 16-bit short form, otherwise reports as
//     "vendor-specific"
//   - Per-UUID category ("Service", "Characteristic",
//     "Descriptor") for routing decisions downstream
//
// What this package does NOT cover (deliberately out of scope):
//   - SIG-assigned 32-bit UUIDs (rarely seen in practice)
//   - Vendor-specific 128-bit UUIDs (vendors don't publish a
//     central catalog — operators look these up manually)
//   - GATT read/write semantics or characteristic
//     interpretation (just the name resolution)
package btuuid

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// Result is the resolved UUID metadata.
type Result struct {
	// Input is the operator-supplied UUID string after
	// normalisation (uppercase, no separators).
	Input string `json:"input"`
	// ShortUUID is the 16-bit short form when the input is
	// either a 16-bit hex or a 128-bit UUID matching the SIG
	// base pattern. Empty for unrecognised 128-bit UUIDs.
	ShortUUID string `json:"short_uuid,omitempty"`
	// CanonicalUUID is the 128-bit form
	// (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) — always
	// populated for valid inputs.
	CanonicalUUID string `json:"canonical_uuid"`
	// Name is the SIG-assigned canonical name when in our
	// catalog, "" otherwise.
	Name string `json:"name,omitempty"`
	// Category is "Service", "Characteristic", "Descriptor",
	// or "" for unrecognised UUIDs.
	Category string `json:"category,omitempty"`
	// Vendor is true when the UUID is 128-bit and doesn't match
	// the SIG base pattern (i.e. it's a vendor-allocated
	// random UUID).
	VendorSpecific bool `json:"vendor_specific"`
}

// Lookup resolves a UUID string against the catalog. Accepts:
//   - 16-bit short form: "180F", "0x180F", "180f"
//   - 128-bit canonical: "0000180F-0000-1000-8000-00805F9B34FB"
//   - 128-bit unhyphenated: "0000180F00001000800000805F9B34FB"
//
// Tolerates ':' / '-' / '_' / whitespace separators.
func Lookup(s string) (Result, error) {
	cleaned := stripSeparators(s)
	cleaned = strings.TrimPrefix(strings.ToLower(cleaned), "0x")
	cleaned = strings.ToUpper(cleaned)
	if cleaned == "" {
		return Result{}, fmt.Errorf("btuuid: empty input")
	}
	switch len(cleaned) {
	case 4:
		return resolveShort(cleaned)
	case 32:
		return resolve128(cleaned)
	}
	return Result{}, fmt.Errorf("btuuid: invalid UUID length %d hex chars (want 4 for 16-bit or 32 for 128-bit)",
		len(cleaned))
}

// resolveShort handles a 16-bit hex input.
func resolveShort(s string) (Result, error) {
	if _, err := hex.DecodeString(s); err != nil {
		return Result{}, fmt.Errorf("btuuid: invalid hex: %w", err)
	}
	out := Result{
		Input:         s,
		ShortUUID:     s,
		CanonicalUUID: shortToCanonical(s),
	}
	if name, cat := lookup16(s); name != "" {
		out.Name = name
		out.Category = cat
	}
	return out, nil
}

// resolve128 handles a 128-bit unhyphenated hex input. Detects
// the SIG base pattern to extract the short form.
func resolve128(s string) (Result, error) {
	if _, err := hex.DecodeString(s); err != nil {
		return Result{}, fmt.Errorf("btuuid: invalid hex: %w", err)
	}
	out := Result{
		Input:         s,
		CanonicalUUID: format128(s),
	}
	// SIG base UUID pattern: 0000XXXX-0000-1000-8000-00805F9B34FB
	// Unhyphenated: 0000XXXX00001000800000805F9B34FB
	const baseSuffix = "00001000800000805F9B34FB"
	if strings.HasPrefix(s, "0000") && strings.HasSuffix(s, baseSuffix) {
		short := s[4:8]
		out.ShortUUID = short
		if name, cat := lookup16(short); name != "" {
			out.Name = name
			out.Category = cat
		}
	} else {
		out.VendorSpecific = true
	}
	return out, nil
}

// lookup16 returns the canonical name + category for a 16-bit
// UUID. Returns ("", "") when not in our catalog.
func lookup16(short string) (string, string) {
	if name, ok := services[short]; ok {
		return name, "Service"
	}
	if name, ok := characteristics[short]; ok {
		return name, "Characteristic"
	}
	if name, ok := descriptors[short]; ok {
		return name, "Descriptor"
	}
	return "", ""
}

// shortToCanonical converts a 4-char hex UUID into the
// canonical 128-bit form using the SIG base.
func shortToCanonical(short string) string {
	return fmt.Sprintf("0000%s-0000-1000-8000-00805F9B34FB", short)
}

// canonicalRE validates that a 128-bit hex string is exactly 32
// hex chars (already enforced by caller; kept as a paranoia
// check before formatting).
var canonicalRE = regexp.MustCompile(`^[0-9A-F]{32}$`)

// format128 inserts hyphens into a 32-char hex string to produce
// the canonical 128-bit UUID form.
func format128(s string) string {
	if !canonicalRE.MatchString(s) {
		return s
	}
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		s[0:8], s[8:12], s[12:16], s[16:20], s[20:32])
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
