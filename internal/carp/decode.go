// SPDX-License-Identifier: AGPL-3.0-or-later

// Package carp decodes the Common Address Redundancy Protocol — the open
// first-hop-redundancy protocol (FHRP) used by OpenBSD, FreeBSD and
// pfSense / OPNsense for gateway / firewall high availability. CARP is
// the third member of the project's FHRP-decoder set alongside
// internal/hsrp (Cisco HSRP) and internal/vrrp (IETF VRRP), and it is
// decoded for the same reason: FHRP hijacking is a classic on-path
// (MITM) attack — a host that advertises for the virtual router with a
// better election metric becomes the master and draws the LAN's default-
// gateway traffic through itself. For CARP that metric is the
// advertisement skew (advskew): the lower it is, the more frequently the
// node advertises and the more likely it wins, so a captured CARP
// advertisement with a very low advskew (especially 0) is the hijack /
// preemption signal.
//
// # Wrap-vs-native judgement
//
//	Native. A CARP advertisement is a fixed 36-octet structure (carried
//	in an IP packet with protocol number 112, shared with VRRP, to the
//	224.0.0.18 multicast): a version/type octet, the VHID, advskew,
//	auth length, demotion, advbase, a checksum, a 64-bit counter and a
//	20-octet SHA-1 HMAC. Decoding is byte-field extraction — a
//	dependency is not justified. stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	Every header field was verified field-for-field against scapy's
//	CARP layer. The advertisement interval is the documented CARP
//	timing (advbase + advskew/256 seconds). The 20-octet HMAC is
//	surfaced as hex and NOT verified — it is an SHA-1 HMAC keyed by the
//	CARP passphrase, which is not on the wire (the same reason the
//	vtp / wpa decoders do not verify their keyed digests).
package carp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of a CARP advertisement.
type Result struct {
	Version        int      `json:"version"`
	Type           int      `json:"type"`
	TypeName       string   `json:"type_name"`
	VHID           int      `json:"vhid"` // virtual host ID (the redundancy group)
	AdvSkew        int      `json:"adv_skew"`
	AdvBase        int      `json:"adv_base"`
	AdvIntervalSec float64  `json:"adv_interval_sec"`
	AuthLen        int      `json:"auth_len"`
	Demotion       int      `json:"demotion"`
	ChecksumHex    string   `json:"checksum_hex"`
	CounterHex     string   `json:"counter_hex"`
	HMACSHA1Hex    string   `json:"hmac_sha1_hex"`
	Notes          []string `json:"notes,omitempty"`
}

const carpLen = 36

// Decode parses a CARP advertisement. The input is hex (whitespace /
// ':' / '-' / '_' separators and a '0x' prefix tolerated). It may be the
// CARP PDU itself, or an IPv4 packet (protocol 112) whose payload is CARP.
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	// Strip an IPv4 header if this is a full packet with protocol 112.
	if len(b) >= 20 && b[0]>>4 == 4 && b[9] == 112 {
		ihl := int(b[0]&0x0F) * 4
		if ihl >= 20 && ihl <= len(b) {
			b = b[ihl:]
		}
	}
	if len(b) < carpLen {
		return nil, fmt.Errorf("carp: %d bytes — a CARP advertisement is %d octets", len(b), carpLen)
	}
	r := &Result{
		Version:     int(b[0] >> 4),
		Type:        int(b[0] & 0x0F),
		VHID:        int(b[1]),
		AdvSkew:     int(b[2]),
		AuthLen:     int(b[3]),
		Demotion:    int(b[4]),
		AdvBase:     int(b[5]),
		ChecksumHex: fmt.Sprintf("0x%04X", binary.BigEndian.Uint16(b[6:8])),
		CounterHex:  strings.ToUpper(hex.EncodeToString(b[8:16])),
		HMACSHA1Hex: strings.ToUpper(hex.EncodeToString(b[16:36])),
	}
	r.TypeName = typeName(r.Type)
	r.AdvIntervalSec = float64(r.AdvBase) + float64(r.AdvSkew)/256.0
	if r.Version != 2 {
		r.Notes = append(r.Notes, fmt.Sprintf("version %d is unexpected (CARP advertisements are version 2) — this may not be CARP", r.Version))
	}
	r.Notes = append(r.Notes, fmt.Sprintf(
		"adv_skew %d: lower skew advertises more often and wins the master election, so a low/zero skew is the CARP hijack/preemption (on-path MITM) signal — the FHRP attack class shared with HSRP priority 255 / VRRP priority 255",
		r.AdvSkew))
	r.Notes = append(r.Notes, "the 20-octet HMAC is surfaced as hex and NOT verified — it is an SHA-1 HMAC keyed by the CARP passphrase, which is not on the wire")
	return r, nil
}

func typeName(t int) string {
	if t == 1 {
		return "advertisement"
	}
	return fmt.Sprintf("type %d", t)
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("carp: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("carp: input is not valid hex: %w", err)
	}
	return b, nil
}
