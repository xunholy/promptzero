// SPDX-License-Identifier: AGPL-3.0-or-later

package iso7816

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// CommandAPDU is a decoded ISO 7816-4 command APDU.
type CommandAPDU struct {
	CLA     string   `json:"cla"`
	INS     string   `json:"ins"`
	INSName string   `json:"ins_name,omitempty"`
	P1      string   `json:"p1"`
	P2      string   `json:"p2"`
	Case    string   `json:"case"` // ISO 7816-4 case: 1, 2S, 3S, 4S, 2E, 3E, 4E
	Lc      int      `json:"lc"`
	DataHex string   `json:"data_hex,omitempty"`
	Le      int      `json:"le,omitempty"` // expected response length (256/65536 when encoded as 0)
	Notes   []string `json:"notes,omitempty"`
}

// ResponseAPDU is a decoded ISO 7816-4 response APDU.
type ResponseAPDU struct {
	DataHex  string   `json:"data_hex,omitempty"`
	SW       string   `json:"sw"` // SW1SW2, e.g. "9000"
	SW1      string   `json:"sw1"`
	SW2      string   `json:"sw2"`
	Status   string   `json:"status"`
	Category string   `json:"category"` // "success" | "warning" | "error"
	Success  bool     `json:"success"`
	Notes    []string `json:"notes,omitempty"`
}

// insNames are the interindustry ISO 7816-4 instruction bytes. Surfaced as a
// best-effort label for an interindustry CLA only; a proprietary CLA reuses
// these INS values for its own commands, so the name is withheld there.
var insNames = map[byte]string{
	0x04: "DEACTIVATE FILE",
	0x0E: "ERASE BINARY",
	0x20: "VERIFY",
	0x22: "MANAGE SECURITY ENVIRONMENT",
	0x24: "CHANGE REFERENCE DATA",
	0x2A: "PERFORM SECURITY OPERATION",
	0x2C: "RESET RETRY COUNTER",
	0x44: "ACTIVATE FILE",
	0x46: "GENERATE ASYMMETRIC KEY PAIR",
	0x70: "MANAGE CHANNEL",
	0x82: "EXTERNAL / MUTUAL AUTHENTICATE",
	0x84: "GET CHALLENGE",
	0x88: "INTERNAL AUTHENTICATE",
	0xA4: "SELECT",
	0xB0: "READ BINARY",
	0xB2: "READ RECORD(S)",
	0xC0: "GET RESPONSE",
	0xC2: "ENVELOPE",
	0xCA: "GET DATA",
	0xCB: "GET DATA (odd)",
	0xD0: "WRITE BINARY",
	0xD6: "UPDATE BINARY",
	0xDA: "PUT DATA",
	0xDC: "UPDATE RECORD",
	0xE2: "APPEND RECORD",
}

// swExact maps fully-specified status words to their meaning.
var swExact = map[uint16]string{
	0x9000: "Success — normal processing",
	0x6200: "Warning — no information given (state of non-volatile memory unchanged)",
	0x6281: "Warning — returned data may be corrupted",
	0x6282: "Warning — end of file/record reached before reading Le bytes",
	0x6283: "Warning — selected file deactivated/invalidated",
	0x6284: "Warning — file control information not formatted per spec",
	0x6285: "Warning — selected file in termination state",
	0x6300: "Warning — verification failed",
	0x6381: "Warning — file filled up by the last write",
	0x6400: "Error — execution error (state of non-volatile memory unchanged)",
	0x6401: "Error — immediate response required by the card",
	0x6500: "Error — execution error (state of non-volatile memory changed)",
	0x6581: "Error — memory failure",
	0x6700: "Error — wrong length (Lc/Le incorrect)",
	0x6800: "Error — function in CLA not supported",
	0x6881: "Error — logical channel not supported",
	0x6882: "Error — secure messaging not supported",
	0x6883: "Error — last command of the chain expected",
	0x6884: "Error — command chaining not supported",
	0x6900: "Error — command not allowed",
	0x6981: "Error — command incompatible with file structure",
	0x6982: "Error — security status not satisfied",
	0x6983: "Error — authentication method blocked",
	0x6984: "Error — referenced data invalidated/blocked",
	0x6985: "Error — conditions of use not satisfied",
	0x6986: "Error — command not allowed (no current EF)",
	0x6987: "Error — expected secure messaging data objects missing",
	0x6988: "Error — incorrect secure messaging data objects",
	0x6A80: "Error — incorrect parameters in the command data field",
	0x6A81: "Error — function not supported",
	0x6A82: "Error — file or application not found",
	0x6A83: "Error — record not found",
	0x6A84: "Error — not enough memory space in the file",
	0x6A85: "Error — Lc inconsistent with TLV structure",
	0x6A86: "Error — incorrect parameters P1-P2",
	0x6A87: "Error — Lc inconsistent with P1-P2",
	0x6A88: "Error — referenced data or reference data not found",
	0x6A89: "Error — file already exists",
	0x6A8A: "Error — DF name already exists",
	0x6B00: "Error — wrong parameters P1-P2 (offset outside the EF)",
	0x6D00: "Error — instruction (INS) not supported or invalid",
	0x6E00: "Error — class (CLA) not supported",
	0x6F00: "Error — no precise diagnosis",
}

// lookupSW resolves a status word, handling the parameterised families
// (61XX / 6CXX / 63CX / 62XX / 64XX / 65XX) before the exact table.
func lookupSW(sw1, sw2 byte) (status, category string) {
	sw := uint16(sw1)<<8 | uint16(sw2)
	switch sw1 {
	case 0x61:
		return fmt.Sprintf("Success — %d (0x%02X) more response byte(s) available; issue GET RESPONSE", sw2, sw2), "success"
	case 0x6C:
		return fmt.Sprintf("Wrong Le — exactly %d (0x%02X) byte(s) available; re-issue with that Le", sw2, sw2), "error"
	case 0x63:
		if sw2&0xF0 == 0xC0 {
			return fmt.Sprintf("Warning — verification failed, %d PIN/key retry attempt(s) remaining", sw2&0x0F), "warning"
		}
	}
	if name, ok := swExact[sw]; ok {
		cat := "error"
		switch {
		case sw == 0x9000 || sw1 == 0x61:
			cat = "success"
		case sw1 == 0x62 || sw1 == 0x63:
			cat = "warning"
		}
		return name, cat
	}
	// Unknown — surface the SW raw with the coarse class meaning, no guess.
	switch sw1 {
	case 0x62, 0x63:
		return fmt.Sprintf("Warning — unmapped status word 0x%04X (62xx/63xx = warning class)", sw), "warning"
	case 0x90:
		return fmt.Sprintf("Success — proprietary 0x%04X", sw), "success"
	default:
		return fmt.Sprintf("Unmapped status word 0x%04X — surfaced raw (proprietary or out of the ISO 7816-4 table)", sw), "error"
	}
}

// DecodeResponseAPDU decodes a response APDU: optional data followed by the
// SW1 SW2 status word (always the last two bytes). The status word is the
// headline — its decode (success / PIN retries remaining / security status /
// file not found / …) is what drives smart-card interaction analysis.
func DecodeResponseAPDU(b []byte) (*ResponseAPDU, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("iso7816: response APDU needs at least the 2-byte SW1 SW2; got %d", len(b))
	}
	sw1, sw2 := b[len(b)-2], b[len(b)-1]
	status, category := lookupSW(sw1, sw2)
	r := &ResponseAPDU{
		SW:       fmt.Sprintf("%02X%02X", sw1, sw2),
		SW1:      fmt.Sprintf("%02X", sw1),
		SW2:      fmt.Sprintf("%02X", sw2),
		Status:   status,
		Category: category,
		Success:  category == "success",
	}
	if len(b) > 2 {
		r.DataHex = strings.ToUpper(hex.EncodeToString(b[:len(b)-2]))
	}
	return r, nil
}

// DecodeCommandAPDU decodes a command APDU: the 4-byte CLA INS P1 P2 header
// followed by one of the ISO 7816-4 length cases (1 / 2S / 3S / 4S, plus the
// extended-length 2E / 3E / 4E). Ambiguous or inconsistent length encodings
// are rejected rather than mis-parsed.
func DecodeCommandAPDU(b []byte) (*CommandAPDU, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("iso7816: command APDU needs at least the 4-byte CLA INS P1 P2 header; got %d", len(b))
	}
	cla, ins, p1, p2 := b[0], b[1], b[2], b[3]
	ca := &CommandAPDU{
		CLA: fmt.Sprintf("%02X", cla),
		INS: fmt.Sprintf("%02X", ins),
		P1:  fmt.Sprintf("%02X", p1),
		P2:  fmt.Sprintf("%02X", p2),
	}
	// INS naming only for an interindustry CLA (proprietary CLA, high bit set,
	// reuses these INS values for its own meanings).
	if cla&0x80 == 0 {
		if n, ok := insNames[ins]; ok {
			ca.INSName = n
		}
	} else {
		ca.Notes = append(ca.Notes, "proprietary CLA (high bit set) — INS naming withheld (application-specific)")
	}
	if cla&0x10 != 0 {
		ca.Notes = append(ca.Notes, "command chaining bit set (CLA bit 5)")
	}

	body := b[4:]
	switch {
	case len(body) == 0:
		ca.Case = "1"
	case len(body) == 1:
		ca.Case = "2S"
		ca.Le = leValue(int(body[0]), 256)
	default:
		if body[0] != 0 {
			lc := int(body[0])
			switch len(body) {
			case 1 + lc:
				ca.Case = "3S"
				ca.Lc = lc
				ca.DataHex = strings.ToUpper(hex.EncodeToString(body[1:]))
			case 2 + lc:
				ca.Case = "4S"
				ca.Lc = lc
				ca.DataHex = strings.ToUpper(hex.EncodeToString(body[1 : 1+lc]))
				ca.Le = leValue(int(body[1+lc]), 256)
			default:
				return nil, fmt.Errorf("iso7816: inconsistent short APDU — Lc=%d but %d body byte(s)", lc, len(body))
			}
		} else {
			// Extended length: body[0] == 0x00.
			if len(body) == 3 {
				ca.Case = "2E"
				ca.Le = leValue(int(body[1])<<8|int(body[2]), 65536)
				break
			}
			if len(body) < 3 {
				return nil, fmt.Errorf("iso7816: malformed extended-length APDU (%d body bytes)", len(body))
			}
			lc := int(body[1])<<8 | int(body[2])
			switch len(body) {
			case 3 + lc:
				ca.Case = "3E"
				ca.Lc = lc
				ca.DataHex = strings.ToUpper(hex.EncodeToString(body[3:]))
			case 5 + lc:
				ca.Case = "4E"
				ca.Lc = lc
				ca.DataHex = strings.ToUpper(hex.EncodeToString(body[3 : 3+lc]))
				ca.Le = leValue(int(body[3+lc])<<8|int(body[4+lc]), 65536)
			default:
				return nil, fmt.Errorf("iso7816: inconsistent extended APDU — Lc=%d but %d body byte(s)", lc, len(body))
			}
		}
	}
	return ca, nil
}

// leValue maps an encoded Le of 0 to its "maximum" meaning (256 short, 65536
// extended), per ISO 7816-4.
func leValue(encoded, max int) int {
	if encoded == 0 {
		return max
	}
	return encoded
}
