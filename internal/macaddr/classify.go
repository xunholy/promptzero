// SPDX-License-Identifier: AGPL-3.0-or-later

// Package macaddr classifies an IEEE 802 MAC address (EUI-48) from its two
// administration bits — the I/G bit (individual vs group/multicast) and the
// U/L bit (universally vs locally administered). The U/L bit is the standard
// signal that an address is locally administered, which on a unicast address
// is the hallmark of a randomized / privacy MAC (modern iOS, Android, Windows
// and Linux randomize the client MAC, setting this bit). It is the offline
// analysis complement to the WiFi/BLE scan tooling, whose results are lists
// of MACs.
//
// # Wrap-vs-native judgement
//
// Native. The classification is two bit tests on the first octet plus an
// all-ones broadcast check — the IEEE 802 address-format rules, fixed and
// unambiguous. There is nothing to wrap.
//
// # Verifiable / no confidently-wrong output
//
// The I/G and U/L bits have exact, universally-agreed definitions, so the
// multicast / locally-administered / broadcast determinations are facts, not
// guesses. The "randomized MAC" reading is framed as an observation (a
// locally-administered unicast address is *commonly* a randomized/privacy
// MAC), not a verdict — a device can be locally administered for other
// reasons. The OUI (first three octets) is surfaced raw and only when the
// address is universally administered (a locally-administered address has no
// meaningful OUI); the full IEEE OUI-to-vendor registry is large and not
// embedded here, so a vendor name is not guessed at this layer.
package macaddr

import (
	"fmt"
	"strings"
)

// Result is the structural classification of a MAC address.
type Result struct {
	MAC                     string   `json:"mac"` // normalised AA:BB:CC:DD:EE:FF
	Unicast                 bool     `json:"unicast"`
	Multicast               bool     `json:"multicast"`
	Broadcast               bool     `json:"broadcast"`
	LocallyAdministered     bool     `json:"locally_administered"`
	UniversallyAdministered bool     `json:"universally_administered"`
	OUI                     string   `json:"oui,omitempty"` // first 3 octets, only when universally administered
	RandomizedLikely        bool     `json:"randomized_likely"`
	Notes                   []string `json:"notes,omitempty"`
}

// Classify parses a MAC address (accepting ':' / '-' / '.' / no separators)
// and reports its IEEE 802 administration bits.
func Classify(raw string) (*Result, error) {
	h := strings.ToUpper(strings.NewReplacer(":", "", "-", "", ".", "", " ", "").Replace(strings.TrimSpace(raw)))
	if len(h) != 12 {
		return nil, fmt.Errorf("macaddr: need 12 hex digits (48-bit MAC); got %d", len(h))
	}
	b := make([]byte, 6)
	for i := 0; i < 6; i++ {
		hi, ok1 := hexVal(h[2*i])
		lo, ok2 := hexVal(h[2*i+1])
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("macaddr: non-hex character in %q", raw)
		}
		b[i] = hi<<4 | lo
	}
	norm := fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4], b[5])

	igGroup := b[0]&0x01 != 0 // I/G bit: 1 = group/multicast
	ulLocal := b[0]&0x02 != 0 // U/L bit: 1 = locally administered
	broadcast := b[0] == 0xFF && b[1] == 0xFF && b[2] == 0xFF && b[3] == 0xFF && b[4] == 0xFF && b[5] == 0xFF

	r := &Result{
		MAC:                     norm,
		Unicast:                 !igGroup,
		Multicast:               igGroup,
		Broadcast:               broadcast,
		LocallyAdministered:     ulLocal,
		UniversallyAdministered: !ulLocal,
	}
	if !ulLocal {
		r.OUI = fmt.Sprintf("%02X:%02X:%02X", b[0], b[1], b[2])
	}
	// A locally-administered unicast address that is not the broadcast address
	// is the hallmark of a randomized/privacy MAC.
	if ulLocal && !igGroup && !broadcast {
		r.RandomizedLikely = true
		r.Notes = append(r.Notes, "locally-administered unicast address — commonly a randomized/privacy MAC (iOS/Android/Windows/Linux MAC randomization), not a manufacturer-assigned OUI address")
	}
	if broadcast {
		r.Notes = append(r.Notes, "broadcast address (FF:FF:FF:FF:FF:FF)")
	} else if igGroup {
		r.Notes = append(r.Notes, "group/multicast address — not an individual station")
	}
	return r, nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}
