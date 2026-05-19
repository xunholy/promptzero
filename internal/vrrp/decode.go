// Package vrrp decodes Virtual Router Redundancy Protocol
// (VRRP) packets per RFC 5798 (v3, IPv4 + IPv6) and the
// older RFC 3768 (v2, IPv4-only, still widely deployed).
//
// Wrap-vs-native judgement
//
//	Native. Both RFCs are fully public; VRRP is a tight
//	8-byte fixed header followed by a list of 4-byte (IPv4)
//	or 16-byte (IPv6) virtual addresses. No crypto, no
//	compression, no varints. Operators paste VRRP bytes
//	(IP protocol number 112, multicast to 224.0.0.18 or
//	ff02::12) from a `tcpdump -X proto 112` line, a Wireshark
//	Follow-IP-Stream view, or any VRRP-speaking router's
//	tcpdump and get the documented header + per-version
//	body + virtual address list.
//
// What this package covers
//
//   - **8-byte common header** (RFC 5798 §5.1 / RFC 3768 §5.1):
//
//   - byte 0: Version (4 bits; 2 or 3) + Type (4 bits;
//     only 1 Advertisement is defined).
//
//   - byte 1: **Virtual Router Identifier (VRID)** — 1-255;
//     the per-VLAN HA-group identifier (the same VRID on
//     multiple routers means they're in the same HA group).
//
//   - byte 2: **Priority** — 0-255; 255 = "I am the IP
//     address owner" (highest priority), 0 = "remove me
//     from this group / I'm shutting down" (the lowest-
//     priority router with the highest-numbered VRID
//     becomes Master). Default backup priority is 100.
//
//   - byte 3: Count IPvX Addresses — number of virtual
//     addresses (IPv4 in v2, IPv4 or IPv6 in v3 per the
//     outer IP packet's family).
//
//   - bytes 4-5: version-specific —
//
//   - **VRRPv2**: byte 4 = Auth Type (0 None, 1 Simple
//     Text, 2 IP Authentication Header — both deprecated
//     per RFC 5798 §9.3); byte 5 = Adver Int (seconds;
//     default 1).
//
//   - **VRRPv3**: bits 0-3 = Reserved, bits 4-15 =
//     **Max Adver Interval** (12 bits, in centiseconds;
//     default 100 cs = 1 second).
//
//   - bytes 6-7: Checksum (uint16 BE, surfaced as hex).
//
//   - **Virtual Address list** — N × 4 bytes (IPv4) or N × 16
//     bytes (IPv6). The address family is inferred from the
//     outer IP packet; this decoder uses byte arithmetic
//     (remaining bytes / Count) to detect 4 vs 16, then
//     formats accordingly.
//
//   - **VRRPv2 Authentication Data** (8 bytes, when Auth
//     Type 1 = Simple Text) — surfaced as decoded UTF-8 if
//     printable, hex otherwise.
//
//   - **Priority semantic notes** — surface a Note for the
//     two special values (0 = withdraw / 255 = IP owner).
//
//   - **Conformance check** — Type != 1 surfaces a Note;
//     Version not in {2, 3} surfaces a Note.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - IP framing — feed VRRP bytes after the IPv4 / IPv6
//     header strip. VRRP runs over IP protocol 112.
//
//   - VRRPv2 IP Authentication Header (Auth Type 2) — the
//     auth data is wrapped in the IP header (RFC 2402); we
//     surface only the 8-byte VRRP auth field.
//
//   - Master election simulation — Priority is surfaced;
//     reasoning about who becomes Master across a multi-
//     router HA group is higher-level analysis.
//
//   - VRRP cryptographic verification — RFC 3768's Auth
//     Types are all deprecated; if you need integrity,
//     run VRRP over IPsec.
package vrrp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"unicode/utf8"
)

// Result is the top-level decoded view.
type Result struct {
	Version      int    `json:"version"`
	Type         int    `json:"type"`
	TypeName     string `json:"type_name"`
	VRID         int    `json:"vrid"`
	Priority     int    `json:"priority"`
	PriorityNote string `json:"priority_note,omitempty"`
	CountIPvX    int    `json:"count_addresses"`

	AuthType        int    `json:"auth_type,omitempty"`
	AuthTypeName    string `json:"auth_type_name,omitempty"`
	AdverIntSeconds int    `json:"adver_int_seconds,omitempty"`

	MaxAdverIntCs int `json:"max_adver_interval_cs,omitempty"`
	MaxAdverIntMs int `json:"max_adver_interval_ms,omitempty"`

	ChecksumHex string `json:"checksum_hex"`

	AddressFamily    string   `json:"address_family,omitempty"`
	VirtualAddresses []string `json:"virtual_addresses,omitempty"`

	AuthDataHex  string `json:"auth_data_hex,omitempty"`
	AuthDataText string `json:"auth_data_text,omitempty"`

	TotalBytes int      `json:"total_bytes"`
	Notes      []string `json:"notes,omitempty"`
}

// Decode parses a single VRRP packet from hex.
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if clean == "" {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("hex must have even length, got %d", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) < 8 {
		return nil, fmt.Errorf("VRRP header truncated (%d bytes; need ≥8)", len(b))
	}

	r := &Result{
		TotalBytes:  len(b),
		Version:     int(b[0] >> 4),
		Type:        int(b[0] & 0x0F),
		VRID:        int(b[1]),
		Priority:    int(b[2]),
		CountIPvX:   int(b[3]),
		ChecksumHex: fmt.Sprintf("0x%04X", binary.BigEndian.Uint16(b[6:8])),
	}
	r.TypeName = typeName(r.Type)
	r.PriorityNote = priorityNote(r.Priority)

	if r.Type != 1 {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"VRRP Type %d — only Type 1 (Advertisement) is defined per RFC 5798",
			r.Type))
	}

	switch r.Version {
	case 2:
		r.AuthType = int(b[4])
		r.AuthTypeName = authTypeName(r.AuthType)
		r.AdverIntSeconds = int(b[5])
	case 3:
		// bits 0-3 reserved, bits 4-15 Max Adver Interval (12 bits, centiseconds)
		mav := binary.BigEndian.Uint16(b[4:6]) & 0x0FFF
		r.MaxAdverIntCs = int(mav)
		r.MaxAdverIntMs = int(mav) * 10
	default:
		r.Notes = append(r.Notes, fmt.Sprintf(
			"VRRP version %d — RFC 5798 defines 3 (IPv4+IPv6), RFC 3768 defines 2 "+
				"(IPv4 only). Other versions are not catalogued here.",
			r.Version))
	}

	// Address list starts at byte 8. Address family is
	// inferred from (remaining bytes - optional auth) / Count.
	addrStart := 8
	addrEnd := len(b)

	// VRRPv2 Simple Text Auth is the last 8 bytes after the
	// address list. Subtract it from the address window.
	if r.Version == 2 && r.AuthType == 1 && len(b) >= addrStart+8 {
		addrEnd -= 8
		r.AuthDataHex = strings.ToUpper(hex.EncodeToString(b[addrEnd:]))
		if utf8.Valid(b[addrEnd:]) {
			// Trim trailing zero pad bytes for readability.
			text := strings.TrimRight(string(b[addrEnd:]), "\x00")
			if text != "" {
				r.AuthDataText = text
			}
		}
	}

	addrBytes := addrEnd - addrStart
	if r.CountIPvX > 0 && addrBytes > 0 {
		perAddr := addrBytes / r.CountIPvX
		switch perAddr {
		case 4:
			r.AddressFamily = "IPv4"
		case 16:
			r.AddressFamily = "IPv6"
		default:
			r.Notes = append(r.Notes, fmt.Sprintf(
				"address list has %d bytes for %d addresses (perAddr=%d) — "+
					"expected 4 (IPv4) or 16 (IPv6)",
				addrBytes, r.CountIPvX, perAddr))
		}
		if perAddr == 4 || perAddr == 16 {
			for i := 0; i < r.CountIPvX; i++ {
				off := addrStart + i*perAddr
				if off+perAddr > addrEnd {
					break
				}
				r.VirtualAddresses = append(r.VirtualAddresses,
					formatAddress(b[off:off+perAddr]))
			}
		}
	}

	return r, nil
}

func typeName(t int) string {
	if t == 1 {
		return "Advertisement"
	}
	return fmt.Sprintf("uncatalogued type %d", t)
}

func priorityNote(p int) string {
	switch p {
	case 0:
		return "0 — withdraw (router signalling 'remove me from this VR / shutting down')"
	case 100:
		return "100 — default backup priority"
	case 255:
		return "255 — IP address owner (highest priority, always Master)"
	}
	return ""
}

func authTypeName(a int) string {
	switch a {
	case 0:
		return "No Authentication"
	case 1:
		return "Simple Text Password (deprecated, RFC 5798 §9.3)"
	case 2:
		return "IP Authentication Header (deprecated, RFC 2402)"
	}
	return fmt.Sprintf("uncatalogued auth type %d", a)
}

func formatAddress(b []byte) string {
	switch len(b) {
	case 4:
		return net.IP(b).To4().String()
	case 16:
		return net.IP(b).String()
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
