// SPDX-License-Identifier: AGPL-3.0-or-later

// Package felica decodes FeliCa (Sony, JIS X 6319-4) — NFC-F / NFC Forum Type
// 3 — command and response frames. FeliCa is the contactless protocol behind
// the huge transit and payment deployments of East Asia (Suica / PASMO,
// Octopus, EZ-Link, nanaco, Edy, WAON) and the NFC Forum Type 3 Tag; the
// Flipper Zero and Proxmark can read it. A captured FeliCa frame is NFC
// reconnaissance: the polling response carries the card's **IDm** (Manufacture
// ID — the card's unique identifier and the value used for anti-collision and
// access logging), its **PMm** (Manufacture Parameter — IC type + timing), and
// the **System Code** that identifies the on-card application system (transit,
// payment, NDEF, FeliCa Lite-S); a Read Without Encryption response carries
// the requested **block data**. Decoding it identifies the card family, the
// system, and any returned block contents — the recon headline for FeliCa.
//
// # Wrap-vs-native judgement
//
//	Native. A FeliCa frame is a length-prefixed, fixed-layout structure: LEN
//	+ a 1-byte command/response code + (for all but the Polling command) an
//	8-byte IDm, then per-code fixed fields. A byte-slice walk + a code
//	lookup; stdlib only, no new go.mod dep. The NFC-F member of the project's
//	NFC family (internal/iso14443a/b, iso15693, the nfc_t2t / nfc_emv tools).
//
// # Verifiable / no confidently-wrong output
//
//	The frame layout and the command/response code table follow the
//	authoritative Sony FeliCa Card User's Manual / JIS X 6319-4 — there is no
//	scapy model for FeliCa, so verification is by the deterministic,
//	byte-checkable structural walk against spec-built vectors (the same
//	approach used for internal/goose and internal/sv). Only the standardised,
//	deterministic fields are decoded: LEN, the code + name, the IDm (+ its
//	2-byte manufacturer code), the PMm (+ IC code), the polling System Code,
//	the read status flags and block data, and the Request System Code list. A
//	handful of well-known System Codes are named; any other System Code, IC
//	code or unhandled command body is surfaced as raw hex (the per-vendor
//	value spaces are not enumerated, to avoid a confidently-wrong label). A
//	declared LEN that disagrees with the buffer, or a body too short for the
//	code's fixed fields, is reported, not guessed.
package felica

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of a FeliCa command/response frame.
type Result struct {
	Length     int    `json:"length"`
	Code       int    `json:"code"`
	CodeHex    string `json:"code_hex"`
	CodeName   string `json:"code_name"`
	IsResponse bool   `json:"is_response"`

	IDm              string `json:"idm,omitempty"`
	ManufacturerCode string `json:"manufacturer_code,omitempty"`
	PMm              string `json:"pmm,omitempty"`
	ICCode           string `json:"ic_code,omitempty"`

	// Polling command (0x00)
	SystemCodeRequested string `json:"system_code_requested,omitempty"`
	RequestCode         *int   `json:"request_code,omitempty"`
	RequestCodeName     string `json:"request_code_name,omitempty"`
	TimeSlot            *int   `json:"time_slot,omitempty"`

	// Polling response (0x01) / Request System Code response (0x0D)
	SystemCode     string   `json:"system_code,omitempty"`
	SystemCodeName string   `json:"system_code_name,omitempty"`
	SystemCodes    []string `json:"system_codes,omitempty"`

	// Read/Write Without Encryption response (0x07 / 0x09)
	StatusFlag1 *int     `json:"status_flag1,omitempty"`
	StatusFlag2 *int     `json:"status_flag2,omitempty"`
	StatusOK    *bool    `json:"status_ok,omitempty"`
	NumBlocks   *int     `json:"num_blocks,omitempty"`
	Blocks      []string `json:"blocks,omitempty"`

	PayloadHex string   `json:"payload_hex,omitempty"`
	Notes      []string `json:"notes,omitempty"`
}

// Decode parses a FeliCa frame (starting at the LEN byte) from hex (whitespace
// / ':' / '-' / '_' separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 2 {
		return nil, fmt.Errorf("felica: %d bytes — too short for a LEN + code", len(b))
	}
	length := int(b[0])
	code := b[1]
	name := codeName(code)
	if name == "" {
		return nil, fmt.Errorf("felica: 0x%02X is not a known FeliCa command/response code", code)
	}
	r := &Result{
		Length:     length,
		Code:       int(code),
		CodeHex:    fmt.Sprintf("0x%02X", code),
		CodeName:   name,
		IsResponse: code%2 == 1, // responses are odd (cmd N, response N+1)
	}
	if length != len(b) {
		r.Notes = append(r.Notes, fmt.Sprintf("declared LEN %d does not match the %d-byte buffer", length, len(b)))
	}

	body := b[2:]
	switch code {
	case 0x00: // Polling command — no IDm: systemCode(2) requestCode(1) timeSlot(1)
		if len(body) >= 4 {
			r.SystemCodeRequested = hexUpper(body[0:2])
			rc := int(body[2])
			r.RequestCode = &rc
			r.RequestCodeName = requestCodeName(body[2])
			ts := int(body[3])
			r.TimeSlot = &ts
		} else {
			r.PayloadHex = hexUpper(body)
		}
	case 0x01: // Polling response: IDm(8) PMm(8) [requestData(2) = system code]
		if len(body) >= 16 {
			setIDm(r, body[0:8])
			setPMm(r, body[8:16])
			if len(body) >= 18 {
				r.SystemCode = hexUpper(body[16:18])
				r.SystemCodeName = systemCodeName(binary.BigEndian.Uint16(body[16:18]))
			}
		} else {
			r.PayloadHex = hexUpper(body)
		}
	case 0x07: // Read Without Encryption response: IDm(8) SF1(1) SF2(1) [n(1) blocks(16n)]
		if len(body) >= 10 {
			setIDm(r, body[0:8])
			setStatus(r, body[8], body[9])
			if body[8] == 0x00 && len(body) >= 11 {
				n := int(body[10])
				r.NumBlocks = &n
				p := 11
				for i := 0; i < n && p+16 <= len(body); i++ {
					r.Blocks = append(r.Blocks, hexUpper(body[p:p+16]))
					p += 16
				}
			}
		} else {
			r.PayloadHex = hexUpper(body)
		}
	case 0x09: // Write Without Encryption response: IDm(8) SF1(1) SF2(1)
		if len(body) >= 10 {
			setIDm(r, body[0:8])
			setStatus(r, body[8], body[9])
		} else {
			r.PayloadHex = hexUpper(body)
		}
	case 0x0D: // Request System Code response: IDm(8) n(1) systemCodes(2n)
		if len(body) >= 9 {
			setIDm(r, body[0:8])
			n := int(body[8])
			p := 9
			for i := 0; i < n && p+2 <= len(body); i++ {
				r.SystemCodes = append(r.SystemCodes, hexUpper(body[p:p+2]))
				p += 2
			}
		} else {
			r.PayloadHex = hexUpper(body)
		}
	default:
		// Every other command/response carries the IDm right after the code.
		if len(body) >= 8 {
			setIDm(r, body[0:8])
			if len(body) > 8 {
				r.PayloadHex = hexUpper(body[8:])
			}
		} else if len(body) > 0 {
			r.PayloadHex = hexUpper(body)
		}
	}

	r.Notes = append(r.Notes, "FeliCa (NFC-F / JIS X 6319-4) — the IDm is the card's unique identifier; the System Code names the on-card application (transit / payment / NDEF / Lite-S); block contents and unknown system/IC codes are surfaced raw")
	return r, nil
}

func setIDm(r *Result, idm []byte) {
	r.IDm = hexUpper(idm)
	r.ManufacturerCode = hexUpper(idm[0:2])
}

func setPMm(r *Result, pmm []byte) {
	r.PMm = hexUpper(pmm)
	r.ICCode = hexUpper(pmm[0:2])
}

func setStatus(r *Result, sf1, sf2 byte) {
	s1 := int(sf1)
	s2 := int(sf2)
	r.StatusFlag1 = &s1
	r.StatusFlag2 = &s2
	ok := sf1 == 0x00
	r.StatusOK = &ok
}

// codeName maps the FeliCa command/response code to its name (JIS X 6319-4 /
// Sony FeliCa Card User's Manual). Empty for an unknown code.
func codeName(c byte) string {
	switch c {
	case 0x00:
		return "Polling (command)"
	case 0x01:
		return "Polling (response)"
	case 0x02:
		return "Request Service (command)"
	case 0x03:
		return "Request Service (response)"
	case 0x04:
		return "Request Response (command)"
	case 0x05:
		return "Request Response (response)"
	case 0x06:
		return "Read Without Encryption (command)"
	case 0x07:
		return "Read Without Encryption (response)"
	case 0x08:
		return "Write Without Encryption (command)"
	case 0x09:
		return "Write Without Encryption (response)"
	case 0x0A:
		return "Search Service Code (command)"
	case 0x0B:
		return "Search Service Code (response)"
	case 0x0C:
		return "Request System Code (command)"
	case 0x0D:
		return "Request System Code (response)"
	case 0x10:
		return "Authentication1 (command)"
	case 0x11:
		return "Authentication1 (response)"
	case 0x12:
		return "Authentication2 (command)"
	case 0x13:
		return "Authentication2 (response)"
	case 0x14:
		return "Read (command)"
	case 0x15:
		return "Read (response)"
	case 0x16:
		return "Write (command)"
	case 0x17:
		return "Write (response)"
	case 0x3C:
		return "Request Specification Version (command)"
	case 0x3D:
		return "Request Specification Version (response)"
	case 0x3E:
		return "Reset Mode (command)"
	case 0x3F:
		return "Reset Mode (response)"
	}
	return ""
}

func requestCodeName(c byte) string {
	switch c {
	case 0x00:
		return "no request"
	case 0x01:
		return "system code request"
	case 0x02:
		return "communication performance request"
	}
	return ""
}

// systemCodeName names a handful of well-known FeliCa System Codes; others
// are surfaced raw (the value space is large and vendor-allocated).
func systemCodeName(sc uint16) string {
	switch sc {
	case 0x12FC:
		return "NFC Forum Type 3 Tag (NDEF)"
	case 0x88B4:
		return "FeliCa Lite-S"
	case 0x0003:
		return "transit (Cyberne / Suica-family)"
	case 0xFE00:
		return "FeliCa Networks Common Area"
	case 0xFFFF:
		return "wildcard (any system)"
	}
	return ""
}

func hexUpper(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) }

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("felica: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("felica: input is not valid hex: %w", err)
	}
	return b, nil
}
