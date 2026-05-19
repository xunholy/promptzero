// Package vlan decodes IEEE 802.1Q (C-tag) and 802.1ad
// (S-tag, QinQ) VLAN tags per IEEE 802.1Q-2018.
//
// Wrap-vs-native judgement
//
//	Native. IEEE 802.1Q is fully public; each VLAN tag is a
//	tight 32-bit field (16-bit TPID + 16-bit TCI) inserted
//	between the source MAC and the EtherType in an Ethernet
//	frame. The tag walker is trivial bit-twiddling — no
//	crypto, no compression, no length prefixes. Operators
//	paste the tag bytes (just the 4 bytes per tag plus the
//	2-byte EtherType that follows) from a `tcpdump -i ethX
//	-X` line, a Wireshark Follow-Frame view, or any
//	VLAN-emitting tool and get the documented PCP / DEI /
//	VID + double-tag (QinQ) structure plus inner EtherType
//	identification.
//
// What this package covers
//
//   - **Tag walker** — starts at the first TPID and consumes
//     4-byte tags until it encounters a non-tag EtherType
//     (anything that isn't 0x8100 / 0x88A8 / 0x9100 / 0x9200
//     / 0x9300). The remaining 2 bytes are surfaced as the
//     inner EtherType.
//
//   - **TPID table** (5 entries):
//
//   - 0x8100 — IEEE 802.1Q C-tag (Customer VLAN)
//
//   - 0x88A8 — IEEE 802.1ad S-tag (Service VLAN, QinQ)
//
//   - 0x9100 — Legacy QinQ TPID (pre-standardisation)
//
//   - 0x9200 — Legacy QinQ TPID
//
//   - 0x9300 — Legacy QinQ TPID
//
//   - **TCI bit breakdown** (16 bits BE):
//
//   - PCP (Priority Code Point, 3 bits) — 802.1p priority
//     0-7 with an **8-entry name table**:
//
//   - 0 Background (Best Effort default)
//
//   - 1 Background (Lowest)
//
//   - 2 Excellent Effort
//
//   - 3 Critical Applications
//
//   - 4 Video (<100ms latency)
//
//   - 5 Voice (<10ms latency)
//
//   - 6 Internetwork Control
//
//   - 7 Network Control (Highest)
//
//   - DEI (Drop Eligible Indicator, 1 bit) — formerly CFI
//     (Canonical Format Indicator); when 1, the frame may
//     be dropped under congestion.
//
//   - VID (VLAN Identifier, 12 bits) — 0-4095:
//
//   - 0: priority-tagged frame (no VLAN; only PCP/DEI
//     matter)
//
//   - 1: default native VLAN (often Cisco "VLAN 1")
//
//   - 4095: reserved
//
//   - **Double-tag (QinQ) detection** — when the first tag's
//     TPID is 0x88A8 (or a legacy QinQ TPID) and the second
//     tag's TPID is 0x8100, the frame is service-provider
//     tagged: the outer S-tag identifies the customer, the
//     inner C-tag identifies the customer's internal VLAN.
//
//   - **Inner EtherType identification** — **10-entry name
//     table** for the post-tag EtherType:
//
//   - 0x0800 IPv4
//
//   - 0x0806 ARP
//
//   - 0x86DD IPv6
//
//   - 0x8035 RARP
//
//   - 0x8847 MPLS unicast
//
//   - 0x8848 MPLS multicast
//
//   - 0x8863 PPPoE Discovery
//
//   - 0x8864 PPPoE Session
//
//   - 0x888E EAPOL (802.1X)
//
//   - 0x88CC LLDP
//
// What this package does NOT cover (deliberately out of scope)
//
//   - Ethernet header (dst MAC + src MAC) — feed the bytes
//     starting at the first TPID.
//
//   - VLAN translation / TPID rewriting — common in carrier
//     networks but a separate L2-config concern.
//
//   - Inner payload dissection — the inner EtherType is
//     surfaced; operators pipe the post-tag bytes to the
//     appropriate decoder (`ip_packet_decode`, `arp_decode`,
//     `lldp_decode`, etc.).
//
//   - MAC-in-MAC (IEEE 802.1ah, PBB) — different encapsulation
//     (24-byte header), a separate Spec.
package vlan

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the top-level decoded view.
type Result struct {
	Tags           []Tag    `json:"tags"`
	TagCount       int      `json:"tag_count"`
	IsQinQ         bool     `json:"is_qinq"`
	InnerEtherType int      `json:"inner_ether_type,omitempty"`
	InnerEtherHex  string   `json:"inner_ether_type_hex,omitempty"`
	InnerEtherName string   `json:"inner_ether_type_name,omitempty"`
	TotalTagBytes  int      `json:"total_tag_bytes"`
	TotalBytes     int      `json:"total_bytes"`
	Notes          []string `json:"notes,omitempty"`
}

// Tag is one decoded VLAN tag.
type Tag struct {
	TPID     int    `json:"tpid"`
	TPIDHex  string `json:"tpid_hex"`
	TPIDName string `json:"tpid_name"`
	PCP      int    `json:"pcp"`
	PCPName  string `json:"pcp_name"`
	DEI      bool   `json:"dei"`
	VID      int    `json:"vid"`
	VIDNote  string `json:"vid_note,omitempty"`
}

// Decode parses a sequence of VLAN tags + final EtherType from
// hex. Input should start at the first TPID (after the
// Ethernet src MAC) and include at least one tag plus the
// final 2-byte EtherType.
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
	if len(b) < 6 {
		return nil, fmt.Errorf("buffer too short (%d bytes; need ≥6 for one tag + EtherType)",
			len(b))
	}

	r := &Result{TotalBytes: len(b)}
	off := 0
	for off+2 <= len(b) {
		tpid := int(binary.BigEndian.Uint16(b[off : off+2]))
		if !isTPID(tpid) {
			break
		}
		if off+4 > len(b) {
			return nil, fmt.Errorf("tag at offset %d truncated (need 4 bytes, have %d)",
				off, len(b)-off)
		}
		tci := binary.BigEndian.Uint16(b[off+2 : off+4])
		tag := Tag{
			TPID:     tpid,
			TPIDHex:  fmt.Sprintf("0x%04X", tpid),
			TPIDName: tpidName(tpid),
			PCP:      int(tci>>13) & 0x07,
			DEI:      tci&0x1000 != 0,
			VID:      int(tci & 0x0FFF),
		}
		tag.PCPName = pcpName(tag.PCP)
		tag.VIDNote = vidNote(tag.VID)
		r.Tags = append(r.Tags, tag)
		off += 4
	}

	r.TagCount = len(r.Tags)
	r.TotalTagBytes = off

	if r.TagCount == 0 {
		return nil, fmt.Errorf("no VLAN tag found at offset 0 (first 2 bytes 0x%s "+
			"is not a known TPID — input must start at the first TPID)",
			strings.ToUpper(hex.EncodeToString(b[:2])))
	}

	if r.TagCount >= 2 {
		// QinQ: outer S-tag (0x88A8 or legacy) + inner C-tag (0x8100).
		if r.Tags[0].TPID == 0x88A8 || isLegacyQinQ(r.Tags[0].TPID) {
			r.IsQinQ = true
			r.Notes = append(r.Notes, fmt.Sprintf(
				"QinQ (IEEE 802.1ad) double tagging: outer S-tag VID=%d %s wraps "+
					"inner C-tag VID=%d",
				r.Tags[0].VID, r.Tags[0].TPIDName, r.Tags[1].VID))
		}
	}
	if r.TagCount > 2 {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"unusual: %d stacked VLAN tags (typical deployments use 1 or 2)",
			r.TagCount))
	}

	if off+2 > len(b) {
		return nil, fmt.Errorf("inner EtherType truncated after %d tag bytes",
			off)
	}
	r.InnerEtherType = int(binary.BigEndian.Uint16(b[off : off+2]))
	r.InnerEtherHex = fmt.Sprintf("0x%04X", r.InnerEtherType)
	r.InnerEtherName = etherTypeName(r.InnerEtherType)

	return r, nil
}

func isTPID(t int) bool {
	switch t {
	case 0x8100, 0x88A8, 0x9100, 0x9200, 0x9300:
		return true
	}
	return false
}

func isLegacyQinQ(t int) bool {
	switch t {
	case 0x9100, 0x9200, 0x9300:
		return true
	}
	return false
}

func tpidName(t int) string {
	switch t {
	case 0x8100:
		return "IEEE 802.1Q C-tag (Customer VLAN)"
	case 0x88A8:
		return "IEEE 802.1ad S-tag (Service VLAN, QinQ)"
	case 0x9100:
		return "Legacy QinQ TPID 0x9100 (pre-standardisation)"
	case 0x9200:
		return "Legacy QinQ TPID 0x9200 (pre-standardisation)"
	case 0x9300:
		return "Legacy QinQ TPID 0x9300 (pre-standardisation)"
	}
	return fmt.Sprintf("unknown TPID 0x%04X", t)
}

func pcpName(p int) string {
	switch p {
	case 0:
		return "Background (Best Effort default)"
	case 1:
		return "Background (Lowest)"
	case 2:
		return "Excellent Effort"
	case 3:
		return "Critical Applications"
	case 4:
		return "Video (<100ms latency)"
	case 5:
		return "Voice (<10ms latency)"
	case 6:
		return "Internetwork Control"
	case 7:
		return "Network Control (Highest)"
	}
	return fmt.Sprintf("PCP %d", p)
}

func vidNote(v int) string {
	switch v {
	case 0:
		return "priority-tagged frame (no VLAN; only PCP/DEI matter)"
	case 1:
		return "default native VLAN (often the Cisco-vendor 'VLAN 1')"
	case 4095:
		return "reserved (must not be used per IEEE 802.1Q §9.6)"
	}
	return ""
}

func etherTypeName(t int) string {
	switch t {
	case 0x0800:
		return "IPv4"
	case 0x0806:
		return "ARP"
	case 0x86DD:
		return "IPv6"
	case 0x8035:
		return "RARP"
	case 0x8847:
		return "MPLS unicast"
	case 0x8848:
		return "MPLS multicast"
	case 0x8863:
		return "PPPoE Discovery"
	case 0x8864:
		return "PPPoE Session"
	case 0x888E:
		return "EAPOL (802.1X)"
	case 0x88CC:
		return "LLDP"
	case 0x88E5:
		return "MACsec (802.1AE)"
	}
	if t < 0x0600 {
		return fmt.Sprintf("length field (%d; 802.3 LLC frame)", t)
	}
	return fmt.Sprintf("EtherType 0x%04X (uncatalogued)", t)
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
