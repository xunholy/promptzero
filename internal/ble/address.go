// SPDX-License-Identifier: AGPL-3.0-or-later

package ble

import (
	"fmt"
	"strings"
)

// AddrResult is the classification of a BLE device address.
type AddrResult struct {
	Address       string   `json:"address"`
	DeclaredType  string   `json:"declared_type"`            // "public", "random", or "unspecified"
	RandomSubtype string   `json:"random_subtype,omitempty"` // when random / unspecified
	OUI           string   `json:"oui,omitempty"`            // when public
	Trackability  string   `json:"trackability,omitempty"`
	Notes         []string `json:"notes,omitempty"`
}

// ClassifyAddress classifies a 48-bit BLE device address. The address bytes
// alone do not say whether an address is public or random — that is carried by
// the advertising PDU's TxAdd bit — so declaredType ("public" / "random" / "")
// selects the interpretation:
//
//   - random: the two most-significant bits of the most-significant octet give
//     the subtype (per Bluetooth Core Vol 6 Part B §1.3.2): 0b11 = static
//     random, 0b01 = resolvable private (RPA), 0b00 = non-resolvable private,
//     0b10 = reserved.
//   - public: the address is an IEEE EUI-48; the OUI (first 3 octets) is
//     surfaced.
//   - unspecified: the random-address interpretation is reported with a note
//     that, if the address is in fact public, those bits are an OUI instead.
//
// The subtype bits are an exact, unambiguous spec rule — no enum, no guess.
func ClassifyAddress(addr, declaredType string) (*AddrResult, error) {
	h := strings.ToUpper(strings.NewReplacer(":", "", "-", "", ".", "", " ", "").Replace(strings.TrimSpace(addr)))
	if len(h) != 12 {
		return nil, fmt.Errorf("ble: need 12 hex digits (48-bit address); got %d", len(h))
	}
	b := make([]byte, 6)
	for i := 0; i < 6; i++ {
		hi, ok1 := hexNibbleBLE(h[2*i])
		lo, ok2 := hexNibbleBLE(h[2*i+1])
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("ble: non-hex character in %q", addr)
		}
		b[i] = hi<<4 | lo
	}
	norm := fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4], b[5])

	dt := strings.ToLower(strings.TrimSpace(declaredType))
	switch dt {
	case "", "unspecified":
		dt = "unspecified"
	case "public", "random":
	default:
		return nil, fmt.Errorf("ble: address_type %q must be \"public\", \"random\", or empty", declaredType)
	}

	r := &AddrResult{Address: norm, DeclaredType: dt}

	subtype, track := randomSubtype(b[0])

	if dt == "public" {
		r.OUI = fmt.Sprintf("%02X:%02X:%02X", b[0], b[1], b[2])
		r.Trackability = "public address — manufacturer-assigned EUI-48 (OUI-identifiable), stable and trackable"
		return r, nil
	}

	r.RandomSubtype = subtype
	r.Trackability = track
	if dt == "unspecified" {
		r.Notes = append(r.Notes, "BLE addresses do not self-identify public vs random — that is the advertising PDU's TxAdd bit. The subtype above assumes a RANDOM address; if it is PUBLIC, the leading bits are part of an OUI instead. Pass address_type to disambiguate.")
	}
	return r, nil
}

// randomSubtype maps the two most-significant bits of a random address's
// most-significant octet to its subtype and a trackability note.
func randomSubtype(msb byte) (subtype, trackability string) {
	switch msb >> 6 {
	case 0b11:
		return "static random", "static random address — stable across the session (often across reboots); trackable while it persists, but not vendor-identifiable"
	case 0b01:
		return "resolvable private (RPA)", "resolvable private address — rotates periodically; tracking-resistant (privacy enabled), resolvable only by a peer holding the device's IRK"
	case 0b00:
		return "non-resolvable private", "non-resolvable private address — random, typically single-session; not trackable and not resolvable"
	default: // 0b10
		return "reserved", "the two most-significant bits are 0b10, which is reserved/invalid for a random BLE address — likely not a random address (or malformed)"
	}
}

func hexNibbleBLE(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}
