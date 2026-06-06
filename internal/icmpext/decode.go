// SPDX-License-Identifier: AGPL-3.0-or-later

// Package icmpext decodes the ICMP multipart message extension structure
// (RFC 4884) and, within it, the MPLS Label Stack object (RFC 4950). When a
// router sends an ICMP Time Exceeded (TTL expired) or Destination Unreachable
// message, RFC 4884 lets it append an extension structure describing the
// context — and RFC 4950 defines the MPLS Label Stack object that carries the
// label stack the original packet was carrying when it was dropped. This is a
// real network-reconnaissance lever: a traceroute through an MPLS core elicits
// Time-Exceeded messages whose extensions leak the **MPLS labels** (and their
// TTLs) at each hop, exposing the label-switched path and the provider's MPLS
// topology that would otherwise be hidden behind the tunnel. RFC 5837 adds
// Interface Information / Identification objects (the egress interface index,
// IP, name and MTU), which similarly enumerate a router's interfaces. The ICMP
// extension member of the project's network-decoder family, pairing with
// icmp_packet_decode and mpls_decode.
//
// # Wrap-vs-native judgement
//
//	Native. The extension structure is a 4-byte header (version + checksum)
//	then a series of TLV objects (length + class-num + c-type + payload); the
//	MPLS object payload is a stack of 32-bit label entries. A byte walk + a
//	bit-field read; stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The extension header, the object TLV framing and the MPLS Label Stack
//	object (the 32-bit label / TC / bottom-of-stack / TTL entries) were
//	verified field-for-field against scapy's ICMP-extensions layer
//	(scapy.contrib.icmp_extensions) and RFC 4950. The MPLS object — the recon
//	headline — is fully decoded. The Interface Information / Identification
//	objects (RFC 5837) carry intricate conditional fields (a bit-flagged
//	c-type selecting an optional ifIndex / IP sub-object / length-framed
//	ifName / MTU), so to avoid a confidently-wrong decode their payload is
//	surfaced as raw hex with the class name rather than field-decoded; the
//	Extended Information and any unknown class are likewise surfaced raw. A
//	malformed object length stops the walk and surfaces the remainder raw.
package icmpext

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of an ICMP multipart extension structure.
type Result struct {
	Version  int      `json:"version"`
	Checksum string   `json:"checksum"`
	Objects  []Object `json:"objects"`
	Notes    []string `json:"notes,omitempty"`
}

// Object is one TLV object within the extension structure.
type Object struct {
	Length     int         `json:"length"`
	ClassNum   int         `json:"class_num"`
	ClassName  string      `json:"class_name"`
	ClassType  int         `json:"class_type"`
	MPLSStack  []MPLSLabel `json:"mpls_stack,omitempty"`
	PayloadHex string      `json:"payload_hex,omitempty"`
}

// MPLSLabel is one 32-bit entry of an MPLS Label Stack object (RFC 4950).
type MPLSLabel struct {
	Label         int  `json:"label"`
	TrafficClass  int  `json:"traffic_class"`
	BottomOfStack bool `json:"bottom_of_stack"`
	TTL           int  `json:"ttl"`
}

// Decode parses an ICMP multipart extension structure (the RFC 4884 extension
// header + objects, i.e. the bytes following the ICMP message's original-
// datagram field) from hex (whitespace / ':' / '-' / '_' separators and a
// '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("icmpext: %d bytes — too short for the 4-byte extension header", len(b))
	}
	version := int(b[0] >> 4)
	r := &Result{
		Version:  version,
		Checksum: fmt.Sprintf("0x%04X", binary.BigEndian.Uint16(b[2:4])),
	}
	if version != 2 {
		r.Notes = append(r.Notes, fmt.Sprintf("extension header version is %d, not the RFC 4884 version 2 — parsed structurally anyway", version))
	}
	r.Notes = append(r.Notes, "ICMP multipart extension (RFC 4884) — appended to a Time Exceeded / Destination Unreachable message; the MPLS Label Stack object leaks the label-switched path traversed (MPLS topology recon)")

	off := 4
	for off+4 <= len(b) {
		objLen := int(binary.BigEndian.Uint16(b[off : off+2]))
		classNum := int(b[off+2])
		classType := int(b[off+3])
		obj := Object{
			Length:    objLen,
			ClassNum:  classNum,
			ClassName: className(classNum),
			ClassType: classType,
		}
		// objLen counts the 4-byte object header; guard it.
		if objLen < 4 || off+objLen > len(b) {
			obj.PayloadHex = strings.ToUpper(hex.EncodeToString(b[off:]))
			r.Notes = append(r.Notes, fmt.Sprintf("object at offset %d has an out-of-range length (%d) — the remainder is surfaced as raw hex", off, objLen))
			r.Objects = append(r.Objects, obj)
			break
		}
		payload := b[off+4 : off+objLen]
		if classNum == 1 { // MPLS Label Stack (RFC 4950)
			if len(payload)%4 == 0 && len(payload) > 0 {
				for i := 0; i+4 <= len(payload); i += 4 {
					v := binary.BigEndian.Uint32(payload[i : i+4])
					obj.MPLSStack = append(obj.MPLSStack, MPLSLabel{
						Label:         int(v >> 12),
						TrafficClass:  int(v >> 9 & 0x7),
						BottomOfStack: v>>8&0x1 != 0,
						TTL:           int(v & 0xFF),
					})
				}
			} else {
				obj.PayloadHex = strings.ToUpper(hex.EncodeToString(payload))
				r.Notes = append(r.Notes, "MPLS object payload is not a whole number of 32-bit label entries — surfaced raw")
			}
		} else if len(payload) > 0 {
			// Interface Information / Identification / Extended / unknown — surfaced raw.
			obj.PayloadHex = strings.ToUpper(hex.EncodeToString(payload))
		}
		r.Objects = append(r.Objects, obj)
		off += objLen
	}
	if len(r.Objects) == 0 {
		return nil, fmt.Errorf("icmpext: no extension objects found after the 4-byte header")
	}
	return r, nil
}

// className maps the RFC 4884 object class-num to its name.
func className(c int) string {
	switch c {
	case 1:
		return "MPLS Label Stack (RFC 4950)"
	case 2:
		return "Interface Information (RFC 5837)"
	case 3:
		return "Interface Identification (RFC 5837)"
	case 4:
		return "Extended Information"
	}
	return fmt.Sprintf("class %d", c)
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("icmpext: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("icmpext: input is not valid hex: %w", err)
	}
	return b, nil
}
