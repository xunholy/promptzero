// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vtp decodes Cisco's VLAN Trunking Protocol — the L2 protocol
// that synchronises the VLAN database across the switches of a VTP
// domain. VTP is a notorious switch-security hazard: a VTP server (or a
// rogue host that can reach a trunk) advertising a **higher
// configuration-revision number** overwrites the VLAN database of every
// switch in the domain — injecting a Subset advertisement with a high
// revision and an empty/forged VLAN list deletes or rewrites all VLANs
// domain-wide (a classic L2 denial-of-service). Decoding a captured VTP
// frame surfaces the domain name, the message type, and the all-
// important configuration revision — the reconnaissance a switch-
// security audit needs. It joins the project's switch / L2 decoders
// (internal/cdp, lldp, stp, lacp, vlan, macsec, dtp).
//
// # Wrap-vs-native judgement
//
//	Native. A VTP PDU is a fixed header (version, code, a per-code
//	octet, a domain-name length + 32-octet domain name) followed by a
//	per-code body, carried in an LLC/SNAP frame (OUI 0x00000C, PID
//	0x2003). Decoding is byte-field extraction + a short record walk —
//	a dependency is not justified. stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The header and the Summary / Subset bodies — including the VLAN
//	information records (id, name, status, type, MTU) of a Subset
//	advertisement — are decoded and were verified field-for-field
//	against scapy's VTP layer. The MD5 digest is surfaced as hex and
//	NOT verified (it is computed over the VLAN database + the VTP
//	password, which is not on the wire). Advertisement-Request and
//	Join messages carry little beyond the domain, so they are named
//	with the header decoded and the body left raw.
package vtp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of a VTP PDU.
type Result struct {
	Version    int    `json:"version"`
	Code       int    `json:"code"`
	CodeName   string `json:"code_name"`
	DomainName string `json:"domain_name"`

	// Summary / Subset advertisement fields.
	Followers       *int   `json:"followers,omitempty"`        // Summary
	SequenceNumber  *int   `json:"sequence_number,omitempty"`  // Subset
	ConfigRevision  *int64 `json:"config_revision,omitempty"`  // the attack-critical field
	UpdaterIdentity string `json:"updater_identity,omitempty"` // Summary (IPv4)
	UpdateTimestamp string `json:"update_timestamp,omitempty"` // Summary (YYMMDDHHMMSS)
	MD5Hex          string `json:"md5_digest_hex,omitempty"`   // Summary (not verified)

	VLANs []VLANInfo `json:"vlans,omitempty"` // Subset advertisement

	PayloadHex string   `json:"payload_hex,omitempty"`
	Notes      []string `json:"notes,omitempty"`
}

// VLANInfo is one VLAN record from a Subset advertisement.
type VLANInfo struct {
	VLANID     int    `json:"vlan_id"`
	Name       string `json:"name"`
	Status     int    `json:"status"`
	StatusName string `json:"status_name"`
	Type       int    `json:"type"`
	TypeName   string `json:"type_name"`
	MTU        int    `json:"mtu"`
}

var snapSig = []byte{0x00, 0x00, 0x0C, 0x20, 0x03} // Cisco OUI + VTP PID

// Decode parses a VTP PDU. The input is hex (whitespace / ':' / '-' / '_'
// separators and a '0x' prefix tolerated). It may be the PDU itself, or
// any frame containing the LLC/SNAP VTP signature (OUI 0x00000C, PID
// 0x2003).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if i := indexOf(b, snapSig); i >= 0 {
		b = b[i+len(snapSig):]
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("vtp: %d bytes — too short for a VTP header", len(b))
	}
	r := &Result{Version: int(b[0]), Code: int(b[1])}
	r.CodeName = codeName(r.Code)
	thirdByte := int(b[2])
	domLen := int(b[3])
	if len(b) < 4+32 {
		return nil, fmt.Errorf("vtp: %d bytes — too short for the 32-octet domain name", len(b))
	}
	dom := b[4:36]
	if domLen > 32 {
		domLen = 32
	}
	r.DomainName = strings.TrimRight(string(dom[:domLen]), "\x00")
	body := b[36:]

	switch r.Code {
	case 1: // Summary Advertisement
		f := thirdByte
		r.Followers = &f
		if len(body) >= 36 {
			rev := int64(binary.BigEndian.Uint32(body[0:4]))
			r.ConfigRevision = &rev
			r.UpdaterIdentity = fmt.Sprintf("%d.%d.%d.%d", body[4], body[5], body[6], body[7])
			r.UpdateTimestamp = strings.TrimRight(string(body[8:20]), "\x00")
			r.MD5Hex = strings.ToUpper(hex.EncodeToString(body[20:36]))
			r.Notes = append(r.Notes, "MD5 surfaced as hex, NOT verified — it is computed over the VLAN database + the VTP password, which is not on the wire")
		} else {
			r.Notes = append(r.Notes, "Summary body truncated")
		}
	case 2: // Subset Advertisement
		s := thirdByte
		r.SequenceNumber = &s
		if len(body) >= 4 {
			rev := int64(binary.BigEndian.Uint32(body[0:4]))
			r.ConfigRevision = &rev
			r.VLANs = decodeVLANs(body[4:])
		}
	default: // Advertisement Request / Join / unknown
		r.PayloadHex = strings.ToUpper(hex.EncodeToString(body))
		r.Notes = append(r.Notes, fmt.Sprintf("code %d (%s): header decoded; body surfaced raw", r.Code, r.CodeName))
	}
	if r.ConfigRevision != nil {
		r.Notes = append(r.Notes, "config_revision is the attack-critical field: a VTP advertisement with a higher revision overwrites every switch's VLAN database in the domain (VTP DoS / VLAN manipulation)")
	}
	return r, nil
}

func decodeVLANs(b []byte) []VLANInfo {
	var out []VLANInfo
	off := 0
	for off+12 <= len(b) {
		recLen := int(b[off])
		if recLen < 12 || off+recLen > len(b) {
			break
		}
		nameLen := int(b[off+3])
		v := VLANInfo{
			Status: int(b[off+1]),
			Type:   int(b[off+2]),
			VLANID: int(binary.BigEndian.Uint16(b[off+4:])),
			MTU:    int(binary.BigEndian.Uint16(b[off+6:])),
		}
		nameStart := off + 12
		if nameStart+nameLen <= off+recLen && nameStart+nameLen <= len(b) {
			v.Name = strings.TrimRight(string(b[nameStart:nameStart+nameLen]), "\x00")
		}
		v.StatusName = vlanStatusName(v.Status)
		v.TypeName = vlanTypeName(v.Type)
		out = append(out, v)
		off += recLen
	}
	return out
}

func codeName(c int) string {
	switch c {
	case 1:
		return "Summary Advertisement"
	case 2:
		return "Subset Advertisement"
	case 3:
		return "Advertisement Request"
	case 4:
		return "Join / Takeover"
	}
	return fmt.Sprintf("unknown (%d)", c)
}

func vlanStatusName(s int) string {
	if s == 0 {
		return "operational"
	}
	return "suspended"
}

func vlanTypeName(t int) string {
	switch t {
	case 1:
		return "Ethernet"
	case 2:
		return "FDDI"
	case 3:
		return "Token Ring (TrCRF)"
	case 4:
		return "FDDI-Net"
	case 5:
		return "Token Ring (TrBRF)"
	}
	return fmt.Sprintf("type %d", t)
}

func indexOf(haystack, needle []byte) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("vtp: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("vtp: input is not valid hex: %w", err)
	}
	return b, nil
}
