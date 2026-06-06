// SPDX-License-Identifier: AGPL-3.0-or-later

// Package oam decodes Ethernet OAM / Connectivity Fault Management (CFM)
// frames — IEEE 802.1ag / ITU-T Y.1731, EtherType 0x8902. It is an L2
// service-topology reconnaissance source and so joins the project's
// LAN decoder family (dtp, vtp, vqp, gxrp, stp, maccontrol): the
// Continuity Check Message (CCM) is a multicast frame a maintenance
// endpoint emits continuously, and it advertises the Maintenance Domain
// **level**, the Maintenance Entity Group (**MEG / MA**) identifier and
// the source **MEP ID** — so a captured CCM stream maps out the L2
// maintenance topology (which bridges are MEPs, at which MD level, in
// which maintenance association), and the RDI flag flags a remote defect.
// Loopback (LBM/LBR) and Linktrace (LTM/LTR) are the L2 ping / traceroute
// of the same framework.
//
// # Wrap-vs-native judgement
//
//	Native. A CFM PDU is a 4-byte common header (MD level + version,
//	opcode, flags, TLV offset) followed by an opcode-specific body and a
//	TLV list. A byte-field read + an opcode switch; stdlib only, no new
//	go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The common header and the CCM body (sequence / MEP ID / MEG ID) were
//	verified field-for-field against scapy's OAM layer
//	(scapy.contrib.oam). CFM defines 24 opcodes with varied,
//	often-vendor-extended bodies, so only the universally-present common
//	header (decoded for every opcode, naming the OAM function and MD
//	level) and the CCM body (the recon headline) are decoded; every other
//	opcode's body, and the trailing TLV list, are surfaced as raw hex
//	with the opcode named — never guessed.
package oam

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of an Ethernet OAM / CFM PDU.
type Result struct {
	MDLevel    int    `json:"md_level"`
	Version    int    `json:"version"`
	Opcode     int    `json:"opcode"`
	OpcodeName string `json:"opcode_name"`
	Flags      int    `json:"flags"`
	TLVOffset  int    `json:"tlv_offset"`

	// CCM (opcode 1).
	RDI        *bool   `json:"rdi,omitempty"`
	Period     *int    `json:"ccm_period,omitempty"`
	PeriodName string  `json:"ccm_period_name,omitempty"`
	SeqNum     *uint32 `json:"sequence_number,omitempty"`
	MEPID      *int    `json:"mep_id,omitempty"`
	MEGID      string  `json:"meg_id,omitempty"`
	MEGIDHex   string  `json:"meg_id_hex,omitempty"`

	BodyHex string   `json:"body_hex,omitempty"`
	TLVHex  string   `json:"tlv_hex,omitempty"`
	Notes   []string `json:"notes,omitempty"`
}

// Decode parses an Ethernet OAM / CFM PDU (the EtherType-0x8902 payload)
// from hex (whitespace / ':' / '-' / '_' separators and a '0x' prefix
// tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("oam: %d bytes — too short for a CFM common header", len(b))
	}
	r := &Result{
		MDLevel:    int(b[0] >> 5),
		Version:    int(b[0] & 0x1f),
		Opcode:     int(b[1]),
		OpcodeName: opcodeName(b[1]),
		Flags:      int(b[2]),
		TLVOffset:  int(b[3]),
	}
	// The first TLV sits TLVOffset bytes after the TLV Offset field (b[3]),
	// i.e. at index 4+TLVOffset; the opcode body is the bytes in between.
	bodyEnd := 4 + r.TLVOffset
	if bodyEnd > len(b) {
		bodyEnd = len(b)
		r.Notes = append(r.Notes, "TLV offset points past the captured bytes — body truncated")
	}
	body := b[4:bodyEnd]
	if bodyEnd < len(b) {
		r.TLVHex = hexUpper(b[bodyEnd:])
	}

	if b[1] == 0x01 { // CCM
		rdi := b[2]&0x80 != 0
		period := int(b[2] & 0x07)
		r.RDI, r.Period, r.PeriodName = &rdi, &period, periodName(period)
		if len(body) >= 6 {
			seq := binary.BigEndian.Uint32(body[0:4])
			mep := int(binary.BigEndian.Uint16(body[4:6]) & 0x1fff)
			r.SeqNum, r.MEPID = &seq, &mep
		}
		if len(body) >= 54 {
			meg := body[6:54]
			r.MEGIDHex = hexUpper(meg)
			if s := printableASCII(meg); s != "" {
				r.MEGID = s
			}
		}
		r.Notes = append(r.Notes, "CCM advertises the L2 maintenance topology: MD level, the MEG/MA identifier and the source MEP ID; a captured CCM stream maps the maintenance endpoints, and RDI signals a remote defect")
	} else {
		r.BodyHex = hexUpper(body)
		r.Notes = append(r.Notes, fmt.Sprintf("opcode %d (%s): body surfaced raw — only the CCM body is decoded", r.Opcode, r.OpcodeName))
	}
	return r, nil
}

func periodName(p int) string {
	switch p {
	case 0:
		return "invalid"
	case 1:
		return "3.33ms (300/s)"
	case 2:
		return "10ms (100/s)"
	case 3:
		return "100ms (10/s)"
	case 4:
		return "1s"
	case 5:
		return "10s"
	case 6:
		return "1min"
	case 7:
		return "10min"
	}
	return fmt.Sprintf("%d", p)
}

func opcodeName(op byte) string {
	switch op {
	case 1:
		return "Continuity Check Message (CCM)"
	case 2:
		return "Loopback Reply (LBR)"
	case 3:
		return "Loopback Message (LBM)"
	case 4:
		return "Linktrace Reply (LTR)"
	case 5:
		return "Linktrace Message (LTM)"
	case 32:
		return "Generic Notification Message (GNM)"
	case 33:
		return "Alarm Indication Signal (AIS)"
	case 35:
		return "Lock Signal (LCK)"
	case 37:
		return "Test Signal (TST)"
	case 39:
		return "Automatic Protection Switching (APS)"
	case 40:
		return "Ring-Automatic Protection Switching (R-APS)"
	case 41:
		return "Maintenance Communication Channel (MCC)"
	case 42:
		return "Loss Measurement Reply (LMR)"
	case 43:
		return "Loss Measurement Message (LMM)"
	case 45:
		return "One Way Delay Measurement (1DM)"
	case 46:
		return "Delay Measurement Reply (DMR)"
	case 47:
		return "Delay Measurement Message (DMM)"
	case 48:
		return "Experimental OAM Reply (EXR)"
	case 49:
		return "Experimental OAM Message (EXM)"
	case 50:
		return "Vendor Specific Reply (VSR)"
	case 51:
		return "Vendor Specific Message (VSM)"
	case 52:
		return "Client Signal Fail (CSF)"
	case 53:
		return "One Way Synthetic Loss Measurement (1SL)"
	case 54:
		return "Synthetic Loss Reply (SLR)"
	case 55:
		return "Synthetic Loss Message (SLM)"
	}
	return fmt.Sprintf("opcode %d", op)
}

func printableASCII(b []byte) string {
	// The MEG ID carries a 1-byte format + 1-byte length prefix before the
	// actual identifier, so surface the longest printable run anywhere in the
	// field (best-effort, alongside the raw hex) rather than only a leading
	// run. Requires >= 3 chars so a stray printable byte isn't reported.
	var best, cur string
	for _, c := range b {
		if c >= 0x21 && c <= 0x7e {
			cur += string(c)
			if len(cur) > len(best) {
				best = cur
			}
		} else {
			cur = ""
		}
	}
	if len(best) < 3 {
		return ""
	}
	return best
}

func hexUpper(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("oam: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("oam: input is not valid hex: %w", err)
	}
	return b, nil
}
