// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tcl decodes the ISO/IEC 14443-4 block transmission protocol (T=CL)
// — the half-duplex block layer that carries APDUs between a contactless
// reader (PCD) and a Type-4 proximity card (PICC) after activation. It is the
// transport that sits between card activation and the application layer in the
// project's NFC stack: ATQA + SAK identify the card (internal/iso14443a), the
// ATS advertises its capabilities (also internal/iso14443a), T=CL frames the
// exchange (here), and the APDUs inside are decoded by internal/iso7816. Every
// T=CL frame begins with a Protocol Control Byte (PCB) selecting one of three
// block types: an I-block (information — carries an APDU, possibly chained), an
// R-block (receive-ready — ACK / NAK for chaining flow control) or an S-block
// (supervisory — WTX waiting-time-extension or DESELECT). Decoding the PCB of a
// captured T=CL exchange reveals the block type, the block number / chaining
// state, the CID (card identifier for multi-card fields) and NAD (node
// address) usage, and lifts out the INF field (the APDU fragment) for handoff
// to the APDU decoder — useful when analysing an NFC reader/card capture.
//
// # Wrap-vs-native judgement
//
//	Native. The PCB is a single byte of bit-fields, optionally followed by a
//	CID byte, a NAD byte (I-blocks only) and the INF field. A bit read + two
//	optional byte reads; stdlib only, no new go.mod dep. The T=CL member of
//	the project's NFC family (internal/iso14443a, iso14443b, iso7816).
//
// # Verifiable / no confidently-wrong output
//
//	The PCB coding follows ISO/IEC 14443-4 §7.1 and was reconciled against the
//	canonical PCB values used by Proxmark / libnfc (I-block 0x02 / chaining
//	0x12, R(ACK) 0xA2 / R(NAK) 0xB2, S(DESELECT) 0xC2 / S(WTX) 0xF2, CID bit
//	0x08). The block type is taken from the top two bits (00 = I, 10 = R,
//	11 = S; 01 is RFU and reported as such). Only the standardised PCB +
//	CID + NAD + S(WTX) parameter are decoded; the INF field (the APDU
//	fragment or proprietary payload) is surfaced as raw hex for handoff to the
//	APDU decoder, never reinterpreted here. A frame whose PCB fixed bits are
//	wrong, or which is truncated before a promised CID / NAD byte, is reported,
//	not guessed.
package tcl

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of an ISO 14443-4 T=CL block.
type Result struct {
	PCB       int    `json:"pcb"`
	PCBHex    string `json:"pcb_hex"`
	BlockType string `json:"block_type"`

	BlockNumber *int   `json:"block_number,omitempty"`
	Chaining    bool   `json:"chaining,omitempty"` // I-block: more blocks follow
	CIDPresent  bool   `json:"cid_present,omitempty"`
	CID         *int   `json:"cid,omitempty"`
	NADPresent  bool   `json:"nad_present,omitempty"` // I-block only
	NAD         *int   `json:"nad,omitempty"`
	ACK         *bool  `json:"ack,omitempty"`          // R-block: true = ACK, false = NAK
	SBlockType  string `json:"s_block_type,omitempty"` // S-block: "DESELECT" / "WTX"
	WTXM        *int   `json:"wtx_multiplier,omitempty"`

	INFHex string   `json:"inf_hex,omitempty"`
	Notes  []string `json:"notes,omitempty"`
}

// Decode parses an ISO 14443-4 T=CL block (starting at the PCB) from hex
// (whitespace / ':' / '-' / '_' separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 1 {
		return nil, fmt.Errorf("tcl: empty — need at least the PCB byte")
	}
	pcb := b[0]
	r := &Result{PCB: int(pcb), PCBHex: fmt.Sprintf("0x%02X", pcb)}
	off := 1

	switch pcb >> 6 {
	case 0x0: // I-block (b8 b7 = 00)
		if pcb&0x02 == 0 {
			return r, fmt.Errorf("tcl: 0x%02X has I-block prefix but bit2 (fixed 1) is clear — not a valid PCB", pcb)
		}
		r.BlockType = "I-block"
		bn := int(pcb & 0x01)
		r.BlockNumber = &bn
		r.Chaining = pcb&0x10 != 0
		r.CIDPresent = pcb&0x08 != 0
		r.NADPresent = pcb&0x04 != 0
		off, err = readCID(r, b, off)
		if err != nil {
			return r, err
		}
		if r.NADPresent {
			if off >= len(b) {
				return r, fmt.Errorf("tcl: I-block promises a NAD byte but the frame ends")
			}
			nad := int(b[off])
			r.NAD = &nad
			off++
		}
	case 0x2: // R-block (b8 b7 = 10)
		if pcb&0x02 == 0 {
			return r, fmt.Errorf("tcl: 0x%02X has R-block prefix but bit2 (fixed 1) is clear — not a valid PCB", pcb)
		}
		r.BlockType = "R-block"
		bn := int(pcb & 0x01)
		r.BlockNumber = &bn
		r.CIDPresent = pcb&0x08 != 0
		ack := pcb&0x10 == 0 // bit5 set = NAK
		r.ACK = &ack
		off, err = readCID(r, b, off)
		if err != nil {
			return r, err
		}
	case 0x3: // S-block (b8 b7 = 11)
		r.BlockType = "S-block"
		r.CIDPresent = pcb&0x08 != 0
		switch (pcb >> 4) & 0x3 { // b6 b5
		case 0x0:
			r.SBlockType = "DESELECT"
		case 0x3:
			r.SBlockType = "WTX"
		default:
			r.SBlockType = "RFU"
			r.Notes = append(r.Notes, fmt.Sprintf("S-block b6b5 = %02b is not DESELECT (00) or WTX (11)", (pcb>>4)&0x3))
		}
		off, err = readCID(r, b, off)
		if err != nil {
			return r, err
		}
		if r.SBlockType == "WTX" && off < len(b) {
			// INF byte: bits 0-5 = WTXM (waiting-time-extension multiplier),
			// bits 6-7 = power level.
			wtxm := int(b[off] & 0x3F)
			r.WTXM = &wtxm
			off++
		}
	default: // b8 b7 = 01 → RFU
		r.BlockType = "RFU"
		r.Notes = append(r.Notes, fmt.Sprintf("PCB top two bits 01 (0x%02X) are reserved — not an I/R/S block", pcb))
	}

	if off < len(b) {
		r.INFHex = strings.ToUpper(hex.EncodeToString(b[off:]))
	}
	r.Notes = append(r.Notes, "ISO 14443-4 T=CL block — the PCB selects I-block (APDU data) / R-block (ACK/NAK) / S-block (WTX/DESELECT); an I-block's INF field is the APDU fragment (chain to the APDU decoder)")
	return r, nil
}

// readCID consumes the optional CID byte when the PCB's CID bit is set. The
// CID value is the low nibble; the high bits carry a power-level indicator.
func readCID(r *Result, b []byte, off int) (int, error) {
	if !r.CIDPresent {
		return off, nil
	}
	if off >= len(b) {
		return off, fmt.Errorf("tcl: PCB promises a CID byte but the frame ends")
	}
	cid := int(b[off] & 0x0F)
	r.CID = &cid
	return off + 1, nil
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("tcl: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("tcl: input is not valid hex: %w", err)
	}
	return b, nil
}
