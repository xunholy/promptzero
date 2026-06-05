// SPDX-License-Identifier: AGPL-3.0-or-later

// Package macsec decodes the IEEE 802.1AE (MACsec) Security TAG — the
// per-frame header that prefixes a MACsec-protected Ethernet frame
// (EtherType 0x88E5). MACsec provides hop-by-hop L2 confidentiality and
// integrity on a wired LAN, typically keyed by 802.1X / MKA; the SecTAG
// is transmitted in the clear, so decoding it from a capture exposes the
// secure-channel identifier, the association number, the replay-
// protection packet number, and whether the user data is encrypted —
// the visibility a network-access-control / MACsec-deployment audit
// needs. It complements the project's other wired-L2 decoders
// (internal/vlan, lldp, cdp, stp, lacp), which already name 0x88E5 but
// do not body it out.
//
// # Wrap-vs-native judgement
//
//	Native. The SecTAG is a fixed, fully-public bit/byte layout (IEEE
//	802.1AE-2006 §9.3): a one-octet TCI/AN, a one-octet Short Length,
//	a 32-bit Packet Number, and an optional 64-bit Secure Channel
//	Identifier. Decoding is byte-field extraction + bit-masking — a
//	dependency is not justified. stdlib only, no new go.mod dep.
//
// # What this package covers
//
//   - The SecTAG: the TCI flags (Version, End-Station, SCI-present,
//     Single-Copy-Broadcast, Encryption, Changed-text) and the
//     Association Number; the Short Length; the Packet Number (replay
//     protection / GCM IV input); and, when SC is set, the Secure
//     Channel Identifier split into its 48-bit system identifier
//     (a MAC address) and 16-bit port identifier.
//   - Optionally the outer Ethernet header (destination / source MAC)
//     when a full frame whose EtherType is 0x88E5 is passed.
//   - The trailing user data is split into the Secure Data (encrypted
//     when E=1, authenticated cleartext when E=0) and the 16-octet ICV.
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - Decryption / ICV verification — both need the Secure Association
//     Key (SAK), which is derived by MKA and never on the wire, so the
//     Secure Data is surfaced opaque and the ICV is not verified (the
//     same reason the lorawan / wmbus decoders surface their encrypted
//     payloads raw).
//   - Cipher suites with a non-16-octet ICV — the mandatory-to-
//     implement GCM-AES-128/256 default of 16 octets is assumed for
//     the Secure-Data / ICV split, and that assumption is noted.
package macsec

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of a MACsec frame.
type Result struct {
	DestMAC string `json:"dest_mac,omitempty"`
	SrcMAC  string `json:"src_mac,omitempty"`

	Version         int    `json:"version"`
	EndStation      bool   `json:"end_station"`
	SCIPresent      bool   `json:"sci_present"`
	SingleCopyBcast bool   `json:"single_copy_broadcast"`
	Encrypted       bool   `json:"encrypted"`    // E: user data is encrypted
	Changed         bool   `json:"changed_text"` // C: secure data differs from original
	AssociationNum  int    `json:"association_number"`
	ShortLength     int    `json:"short_length"`
	PacketNumber    uint32 `json:"packet_number"`

	SCI              string `json:"sci,omitempty"`
	SystemIdentifier string `json:"system_identifier,omitempty"` // 48-bit MAC inside the SCI
	PortIdentifier   int    `json:"port_identifier,omitempty"`

	SecureDataHex string   `json:"secure_data_hex,omitempty"`
	ICVHex        string   `json:"icv_hex,omitempty"`
	Notes         []string `json:"notes,omitempty"`
}

const etherTypeMACsec = 0x88E5

// Decode parses a MACsec frame. The input is hex (whitespace / ':' / '-'
// / '_' separators and a '0x' prefix tolerated). It may begin at the
// SecTAG, or be a full Ethernet frame whose EtherType is 0x88E5.
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	r := &Result{}
	// Full Ethernet frame? dst(6) + src(6) + ethertype(2) == 0x88E5.
	if len(b) >= 16 && binary.BigEndian.Uint16(b[12:14]) == etherTypeMACsec {
		r.DestMAC = macAddr(b[0:6])
		r.SrcMAC = macAddr(b[6:12])
		b = b[14:]
	}
	if len(b) < 6 {
		return nil, fmt.Errorf("macsec: %d bytes — too short for a SecTAG (min 6)", len(b))
	}
	tci := b[0]
	r.Version = int(tci>>7) & 1
	r.EndStation = tci&0x40 != 0
	r.SCIPresent = tci&0x20 != 0
	r.SingleCopyBcast = tci&0x10 != 0
	r.Encrypted = tci&0x08 != 0
	r.Changed = tci&0x04 != 0
	r.AssociationNum = int(tci & 0x03)
	r.ShortLength = int(b[1] & 0x3F)
	r.PacketNumber = binary.BigEndian.Uint32(b[2:6])

	off := 6
	if r.SCIPresent {
		if len(b) < 14 {
			return nil, fmt.Errorf("macsec: SC flag set but only %d bytes — need 14 for the SCI", len(b))
		}
		sci := b[6:14]
		r.SCI = hexUpper(sci)
		r.SystemIdentifier = macAddr(sci[0:6])
		r.PortIdentifier = int(binary.BigEndian.Uint16(sci[6:8]))
		off = 14
	}

	// The remainder is Secure Data + a trailing ICV (16 octets for the
	// mandatory GCM-AES default).
	rest := b[off:]
	const icvLen = 16
	if len(rest) >= icvLen {
		r.SecureDataHex = hexUpper(rest[:len(rest)-icvLen])
		r.ICVHex = hexUpper(rest[len(rest)-icvLen:])
	} else if len(rest) > 0 {
		r.SecureDataHex = hexUpper(rest)
		r.Notes = append(r.Notes, fmt.Sprintf(
			"only %d trailing octets — fewer than the 16-octet GCM-AES ICV, so no ICV split was made", len(rest)))
	}
	if r.Encrypted {
		r.Notes = append(r.Notes, "E flag set: the Secure Data is encrypted (decryption needs the SAK, which is derived by MKA and not on the wire — deferred)")
	} else {
		r.Notes = append(r.Notes, "E flag clear: the Secure Data is integrity-protected cleartext (authenticated, not encrypted)")
	}
	r.Notes = append(r.Notes, "the ICV is not verified and the Secure Data is not decrypted — both need the Secure Association Key (SAK); the 16-octet ICV split assumes the mandatory GCM-AES cipher suite")
	return r, nil
}

func macAddr(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02X", x)
	}
	return strings.Join(parts, ":")
}

func hexUpper(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("macsec: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("macsec: input is not valid hex: %w", err)
	}
	return b, nil
}
