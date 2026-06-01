// SPDX-License-Identifier: AGPL-3.0-or-later

// Package rsn decodes the IEEE 802.11 RSN (Robust Security Network)
// Information Element — the WPA2/WPA3 element in beacons, probe responses
// and association requests — into named cipher and AKM suites, the
// management-frame-protection (PMF) state, and a derived security posture.
//
// # Wrap-vs-native judgement
//
// Native. The RSNE layout and the 00-0F-AC suite-number assignments are a
// public IEEE standard (802.11-2020 §9.4.2.24, Tables 9-151/9-152),
// implemented identically by hostapd, wpa_supplicant, aircrack-ng and
// Wireshark. Decoding is a short walker over a byte slice plus two static
// number→name tables; no crypto, no hardware, no SDR. The existing
// internal/ieee80211 decoder surfaces the raw suite OUIs ("000FAC-04") but,
// by its own note, leaves suite naming + the RSN-capabilities (PMF) bits to
// a follow-on Spec — this is that Spec: it turns the raw RSNE into the
// security-posture readout an operator triages an AP by (WPA2-Personal vs
// WPA3-SAE vs WPA3 transition vs Enterprise vs Enhanced-Open/OWE, and
// whether PMF is required — which decides deauth / KRACK / downgrade
// exposure).
//
// # No confidently-wrong output
//
// Only suite numbers under the standard 00-0F-AC OUI are named; a
// vendor-OUI suite or an unassigned number is surfaced as its raw
// "OUI-type" form, never guessed. Optional trailing fields (RSN
// capabilities, PMKID list, group-management cipher) are parsed only when
// the bytes are present; a truncated element yields the fields parsed so
// far plus a note.
package rsn

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// stdOUI is the IEEE 802.11 suite-selector OUI (00-0F-AC) under which the
// standard cipher and AKM suite numbers are assigned.
var stdOUI = [3]byte{0x00, 0x0F, 0xAC}

// Suite is one cipher or AKM suite selector.
type Suite struct {
	OUI  string `json:"oui"`  // "00-0F-AC" for standard suites
	Type int    `json:"type"` // suite number
	Name string `json:"name"` // canonical name, or "OUI-type" raw form when not standard
}

// RSN is the decoded view of an RSN Information Element.
type RSN struct {
	Version         int      `json:"version"`
	GroupCipher     Suite    `json:"group_cipher"`
	PairwiseCiphers []Suite  `json:"pairwise_ciphers"`
	AKMSuites       []Suite  `json:"akm_suites"`
	HasCapabilities bool     `json:"has_capabilities"`
	CapabilitiesHex string   `json:"capabilities_hex,omitempty"`
	PMFCapable      bool     `json:"pmf_capable"`
	PMFRequired     bool     `json:"pmf_required"`
	PreAuth         bool     `json:"preauth"`
	PMKIDCount      int      `json:"pmkid_count,omitempty"`
	GroupMgmtCipher *Suite   `json:"group_mgmt_cipher,omitempty"`
	Security        string   `json:"security"` // derived posture
	Notes           []string `json:"notes,omitempty"`
}

var cipherNames = map[int]string{
	0:  "Use-group",
	1:  "WEP-40",
	2:  "TKIP",
	4:  "CCMP-128",
	5:  "WEP-104",
	6:  "BIP-CMAC-128",
	7:  "Group-addressed-disallowed",
	8:  "GCMP-128",
	9:  "GCMP-256",
	10: "CCMP-256",
	11: "BIP-GMAC-128",
	12: "BIP-GMAC-256",
	13: "BIP-CMAC-256",
}

var akmNames = map[int]string{
	1:  "802.1X",
	2:  "PSK",
	3:  "FT-802.1X",
	4:  "FT-PSK",
	5:  "802.1X-SHA256",
	6:  "PSK-SHA256",
	7:  "TDLS",
	8:  "SAE",
	9:  "FT-SAE",
	10: "AP-PeerKey",
	11: "802.1X-SuiteB-SHA256",
	12: "802.1X-SuiteB-SHA384",
	13: "FT-802.1X-SHA384",
	14: "FILS-SHA256",
	15: "FILS-SHA384",
	16: "FT-FILS-SHA256",
	17: "FT-FILS-SHA384",
	18: "OWE",
	19: "FT-PSK-SHA384",
	20: "PSK-SHA384",
}

// Decode parses a hex-encoded RSN element. The input may be the bare RSNE
// body (starting at the 2-byte version) or the full Information Element
// (element ID 0x30 + length + body); the IE header is stripped.
func Decode(hexStr string) (*RSN, error) {
	b, err := parseHex(hexStr)
	if err != nil {
		return nil, err
	}
	// Full IE: element ID 48 (0x30) + length + body.
	if len(b) >= 2 && b[0] == 0x30 {
		ln := int(b[1])
		if 2+ln <= len(b) {
			b = b[2 : 2+ln]
		} else {
			b = b[2:]
		}
	}
	return DecodeBytes(b)
}

// DecodeBytes parses a bare RSNE body.
func DecodeBytes(b []byte) (*RSN, error) {
	if len(b) < 8 {
		return nil, fmt.Errorf("rsn: element %d bytes; need >=8 (version + group cipher)", len(b))
	}
	out := &RSN{
		Version:     int(binary.LittleEndian.Uint16(b[0:2])),
		GroupCipher: suite(b[2:6], cipherNames),
	}
	off := 6

	pc := int(binary.LittleEndian.Uint16(b[off : off+2]))
	off += 2
	for i := 0; i < pc; i++ {
		if off+4 > len(b) {
			out.Notes = append(out.Notes, "pairwise cipher list truncated")
			break
		}
		out.PairwiseCiphers = append(out.PairwiseCiphers, suite(b[off:off+4], cipherNames))
		off += 4
	}

	if off+2 > len(b) {
		out.Security = derive(out)
		return out, nil
	}
	ac := int(binary.LittleEndian.Uint16(b[off : off+2]))
	off += 2
	for i := 0; i < ac; i++ {
		if off+4 > len(b) {
			out.Notes = append(out.Notes, "AKM suite list truncated")
			break
		}
		out.AKMSuites = append(out.AKMSuites, suite(b[off:off+4], akmNames))
		off += 4
	}

	// Optional: RSN capabilities (2 bytes).
	if off+2 <= len(b) {
		caps := binary.LittleEndian.Uint16(b[off : off+2])
		off += 2
		out.HasCapabilities = true
		out.CapabilitiesHex = fmt.Sprintf("0x%04X", caps)
		out.PreAuth = caps&0x0001 != 0
		out.PMFRequired = caps&0x0040 != 0 // bit 6 MFPR
		out.PMFCapable = caps&0x0080 != 0  // bit 7 MFPC
	}

	// Optional: PMKID count (2) + PMKID list (16 each).
	if off+2 <= len(b) {
		n := int(binary.LittleEndian.Uint16(b[off : off+2]))
		off += 2
		out.PMKIDCount = n
		off += n * 16
		if off > len(b) {
			out.Notes = append(out.Notes, "PMKID list truncated")
			off = len(b)
		}
	}

	// Optional: group management cipher suite (4) — present with MFP.
	if off+4 <= len(b) {
		s := suite(b[off:off+4], cipherNames)
		out.GroupMgmtCipher = &s
	}

	out.Security = derive(out)
	return out, nil
}

// suite decodes a 4-byte suite selector against the given name table,
// naming it only when it carries the standard 00-0F-AC OUI.
func suite(b []byte, names map[int]string) Suite {
	oui := [3]byte{b[0], b[1], b[2]}
	typ := int(b[3])
	s := Suite{
		OUI:  fmt.Sprintf("%02X-%02X-%02X", b[0], b[1], b[2]),
		Type: typ,
	}
	if oui == stdOUI {
		if n, ok := names[typ]; ok {
			s.Name = n
			return s
		}
	}
	s.Name = fmt.Sprintf("%02X-%02X-%02X-%d", b[0], b[1], b[2], typ)
	return s
}

// derive summarises the security posture from the AKM suites.
func derive(out *RSN) string {
	akm := map[string]bool{}
	for _, a := range out.AKMSuites {
		akm[a.Name] = true
	}
	has := func(names ...string) bool {
		for _, n := range names {
			if akm[n] {
				return true
			}
		}
		return false
	}
	sae := has("SAE", "FT-SAE")
	psk := has("PSK", "PSK-SHA256", "FT-PSK", "PSK-SHA384", "FT-PSK-SHA384")
	switch {
	case has("OWE"):
		return "Enhanced Open (OWE)"
	case sae && psk:
		return "WPA3-Personal transition (SAE + PSK)"
	case sae:
		return "WPA3-Personal (SAE)"
	case has("802.1X-SuiteB-SHA384"):
		return "WPA3-Enterprise 192-bit"
	case has("802.1X", "FT-802.1X", "802.1X-SHA256", "802.1X-SuiteB-SHA256", "FT-802.1X-SHA384"):
		return "WPA2/WPA3-Enterprise (802.1X)"
	case psk:
		return "WPA2-Personal (PSK)"
	case len(out.AKMSuites) == 0:
		return "unknown (no AKM suites)"
	default:
		return "unknown AKM"
	}
}

func parseHex(s string) ([]byte, error) {
	clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "", "\n", "", "\t", "").Replace(strings.TrimSpace(s))
	if strings.HasPrefix(strings.ToLower(clean), "0x") {
		clean = clean[2:]
	}
	if clean == "" {
		return nil, fmt.Errorf("rsn: empty hex input")
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("rsn: invalid hex: %w", err)
	}
	return b, nil
}
