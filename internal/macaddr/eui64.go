// SPDX-License-Identifier: AGPL-3.0-or-later

package macaddr

import (
	"fmt"
	"net"
	"strings"
)

// EUI64Result is the recovery of a MAC address from an IPv6 interface
// identifier (the low 64 bits of the address).
type EUI64Result struct {
	IPv6         string   `json:"ipv6"`
	InterfaceID  string   `json:"interface_id"` // low 64 bits, hex
	EUI64Derived bool     `json:"eui64_derived"`
	RecoveredMAC string   `json:"recovered_mac,omitempty"`
	Notes        []string `json:"notes,omitempty"`
}

// RecoverMAC inspects an IPv6 address's interface identifier (low 64 bits) and,
// when it is a Modified EUI-64 — recognised by the FF:FE marker in the middle —
// recovers the embedded MAC by removing the FF:FE and flipping the U/L bit
// back. This deanonymises a host whose SLAAC address was derived from its MAC.
// A privacy-extension / RFC 7217 stable-private / random IID does not carry the
// marker (and matches it only ~1 in 65536 by chance), so the result is framed
// as an observation, not a certainty.
func RecoverMAC(ipv6 string) (*EUI64Result, error) {
	ip := net.ParseIP(strings.TrimSpace(ipv6))
	if ip == nil {
		return nil, fmt.Errorf("macaddr: %q is not a valid IP address", ipv6)
	}
	if ip.To4() != nil {
		return nil, fmt.Errorf("macaddr: %q is an IPv4 address; an IPv6 address is required", ipv6)
	}
	v6 := ip.To16()
	if v6 == nil {
		return nil, fmt.Errorf("macaddr: %q is not an IPv6 address", ipv6)
	}
	iid := v6[8:16]
	r := &EUI64Result{
		IPv6:        ip.String(),
		InterfaceID: fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x", iid[0], iid[1], iid[2], iid[3], iid[4], iid[5], iid[6], iid[7]),
	}
	if iid[3] == 0xFF && iid[4] == 0xFE {
		mac := []byte{iid[0] ^ 0x02, iid[1], iid[2], iid[5], iid[6], iid[7]}
		r.EUI64Derived = true
		r.RecoveredMAC = fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
		r.Notes = append(r.Notes, "interface identifier is a Modified EUI-64 (FF:FE marker present) — MAC recovered by removing FF:FE and flipping the U/L bit; a privacy/random IID matches this pattern only ~1 in 65536, so treat as a strong but not certain recovery")
	} else {
		r.Notes = append(r.Notes, "interface identifier is not EUI-64-derived (no FF:FE marker) — likely a privacy-extension (RFC 4941), stable-private (RFC 7217), or otherwise random/manually-set IID; no MAC to recover")
	}
	return r, nil
}

// MACToEUI64IID builds the Modified EUI-64 interface identifier (8 bytes) for a
// MAC — the forward transform RecoverMAC inverts. Exposed so callers (and the
// round-trip tests) can synthesise a SLAAC interface identifier from a MAC.
func MACToEUI64IID(mac string) ([]byte, error) {
	h := strings.ToUpper(strings.NewReplacer(":", "", "-", "", ".", "", " ", "").Replace(strings.TrimSpace(mac)))
	if len(h) != 12 {
		return nil, fmt.Errorf("macaddr: need a 48-bit MAC; got %d hex digits", len(h))
	}
	b := make([]byte, 6)
	for i := 0; i < 6; i++ {
		hi, ok1 := hexVal(h[2*i])
		lo, ok2 := hexVal(h[2*i+1])
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("macaddr: non-hex character in %q", mac)
		}
		b[i] = hi<<4 | lo
	}
	return []byte{b[0] ^ 0x02, b[1], b[2], 0xFF, 0xFE, b[3], b[4], b[5]}, nil
}
