// SPDX-License-Identifier: AGPL-3.0-or-later

// Package btoob decodes Bluetooth Out-Of-Band (OOB) pairing records —
// the "tap-to-pair" payload carried by an NFC handover tag and the
// Bluetooth Secure Simple Pairing OOB data block.
//
// Two MIME types carry these records in an NDEF message:
//   - application/vnd.bluetooth.ep.oob — BR/EDR ("Easy Pairing"): a
//     2-byte little-endian OOB Data Length (counting itself) + a 6-byte
//     little-endian Bluetooth Device Address (BD_ADDR), followed by
//     optional EIR attributes (the same (length, AD-type, data) grammar
//     as a BLE advertisement).
//   - application/vnd.bluetooth.le.oob — Bluetooth LE: a bare sequence of
//     AD structures, including the LE Bluetooth Device Address (0x1B) and
//     LE Role (0x1C) that an LE pairing needs.
//
// Decoding such a record recovers the peer's Bluetooth address, device
// class / role, local name, and the Secure-Simple-Pairing OOB key
// material (hash C / randomizer R, or the LE SC confirmation/random
// values) that a tag offers for an authenticated tap-to-pair exchange.
//
// Wrap-vs-native: native. The EIR/AD walk is already implemented in
// internal/ble (DecodeGAPBytes); this package adds only the thin BR/EDR
// framing header (length + BD_ADDR) and routes both variants through that
// shared walker. No third-party dependency is warranted. The BR/EDR
// framing and the LE Role / device-address value formats are taken from
// the Bluetooth Core Specification Supplement Part A and the NFC Forum
// "Bluetooth Secure Simple Pairing Using NFC" application document, as
// implemented in the ndeflib reference library — verified, not recalled.
//
// Deferred: the OOB key material (Simple Pairing Hash C-192/256 0x0E/0x1D,
// Randomizer R 0x0F/0x1E, LE SC Confirmation 0x22 / Random 0x23, Security
// Manager TK 0x10) is surfaced as raw hex via the EIR walker — it is
// opaque key bytes, not a structure to interpret. Full Class-of-Device
// minor/service-class tables are device-major specific and left raw
// beyond the Major Device Class.
package btoob

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ble"
)

// Result is a decoded Bluetooth OOB record.
type Result struct {
	// Variant is "br_edr" or "le".
	Variant string `json:"variant"`
	// DeviceAddress is the mandatory BD_ADDR for a BR/EDR record
	// (MSB-first display form). Empty for an LE record, whose
	// address travels as the LE Bluetooth Device Address AD type.
	DeviceAddress string `json:"device_address,omitempty"`
	// OOBDataLength is the declared BR/EDR OOB Data Length field
	// (counts itself); nil for an LE record.
	OOBDataLength *int `json:"oob_data_length,omitempty"`
	// EIR is the decoded EIR / AD-structure block.
	EIR *ble.GAPAdvertisement `json:"eir,omitempty"`
	// Notes collects non-fatal observations.
	Notes []string `json:"notes,omitempty"`
}

func clean(s string) string {
	return strings.NewReplacer(":", "", "-", "", "_", "", " ", "", "\n", "", "\t", "").Replace(s)
}

// DecodeHex decodes a hex-encoded OOB record. variant selects the
// framing: "le" / "ble" for application/vnd.bluetooth.le.oob, anything
// else ("br_edr", "bredr", "ep", "") for the BR/EDR Easy Pairing record.
func DecodeHex(variant, hexStr string) (*Result, error) {
	c := clean(hexStr)
	if c == "" {
		return nil, fmt.Errorf("btoob: empty input")
	}
	b, err := hex.DecodeString(c)
	if err != nil {
		return nil, fmt.Errorf("btoob: invalid hex: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(variant)) {
	case "le", "ble", "le.oob", "low-energy":
		return DecodeLE(b)
	default:
		return DecodeBREDR(b)
	}
}

// DecodeBREDR decodes a BR/EDR ("Easy Pairing") OOB record: 2-byte
// little-endian OOB Data Length + 6-byte little-endian BD_ADDR +
// optional EIR.
func DecodeBREDR(b []byte) (*Result, error) {
	if len(b) < 8 {
		return nil, fmt.Errorf("btoob: BR/EDR OOB record needs at least 8 bytes (2 length + 6 address), got %d", len(b))
	}
	res := &Result{Variant: "br_edr"}
	declared := int(b[0]) | int(b[1])<<8
	res.OOBDataLength = &declared
	if declared != len(b) {
		res.Notes = append(res.Notes,
			fmt.Sprintf("declared OOB Data Length %d != actual %d bytes", declared, len(b)))
	}
	res.DeviceAddress = formatAddrLE(b[2:8])
	if len(b) > 8 {
		adv, err := ble.DecodeGAPBytes(b[8:])
		if err != nil {
			res.Notes = append(res.Notes, "EIR parse: "+err.Error())
		} else {
			res.EIR = &adv
		}
	}
	return res, nil
}

// DecodeLE decodes a Bluetooth LE OOB record: a bare sequence of AD
// structures.
func DecodeLE(b []byte) (*Result, error) {
	res := &Result{Variant: "le"}
	adv, err := ble.DecodeGAPBytes(b)
	if err != nil {
		return nil, fmt.Errorf("btoob: LE OOB EIR parse: %w", err)
	}
	res.EIR = &adv
	return res, nil
}

// formatAddrLE renders 6 little-endian address octets as a MSB-first
// colon-separated MAC.
func formatAddrLE(b []byte) string {
	parts := make([]string, 6)
	for i := 0; i < 6; i++ {
		parts[i] = fmt.Sprintf("%02X", b[5-i])
	}
	return strings.Join(parts, ":")
}
