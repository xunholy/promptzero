// SPDX-License-Identifier: AGPL-3.0-or-later

package emv

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// CVMRule is one Cardholder Verification Method rule from a CVM List (tag 8E):
// a method byte + a condition byte.
type CVMRule struct {
	Raw                     string `json:"raw"` // the 2 bytes, hex
	MethodByte              string `json:"method_byte"`
	MethodCode              int    `json:"method_code"` // low 6 bits
	Method                  string `json:"method"`
	ApplyNextIfUnsuccessful bool   `json:"apply_next_if_unsuccessful"` // bit 7 (0x40): else fail CVM
	ConditionByte           string `json:"condition_byte"`
	Condition               string `json:"condition"`
}

// CVMList is a decoded EMV Cardholder Verification Method List (tag 8E): two
// 4-byte amount fields (X and Y, referenced by the per-rule conditions) and a
// sequence of 2-byte rules.
type CVMList struct {
	AmountX uint32    `json:"amount_x"`
	AmountY uint32    `json:"amount_y"`
	Rules   []CVMRule `json:"rules"`
	Notes   []string  `json:"notes,omitempty"`
}

// cvmMethods maps the low-6-bit CVM method code to its EMV Book 3 name. Codes
// absent from the table are payment-system-specific or RFU and are surfaced
// raw rather than guessed.
var cvmMethods = map[int]string{
	0x00: "Fail CVM processing",
	0x01: "Plaintext PIN verification performed by ICC",
	0x02: "Enciphered PIN verified online",
	0x03: "Plaintext PIN verification performed by ICC and signature",
	0x04: "Enciphered PIN verification performed by ICC",
	0x05: "Enciphered PIN verification performed by ICC and signature",
	0x1E: "Signature (paper)",
	0x1F: "No CVM required",
}

// cvmConditions maps the CVM condition byte to its EMV Book 3 name.
var cvmConditions = map[byte]string{
	0x00: "Always",
	0x01: "If unattended cash",
	0x02: "If not unattended cash and not manual cash and not purchase with cashback",
	0x03: "If terminal supports the CVM",
	0x04: "If manual cash",
	0x05: "If purchase with cashback",
	0x06: "If transaction is in the application currency and is under X value",
	0x07: "If transaction is in the application currency and is over X value",
	0x08: "If transaction is in the application currency and is under Y value",
	0x09: "If transaction is in the application currency and is over Y value",
}

// DecodeCVMList decodes the raw bytes of EMV tag 8E (CVM List). The layout is
// fixed — 4-byte Amount X, 4-byte Amount Y, then 2-byte rules — so it is gated
// structurally: at least the 8-byte amount header must be present and the
// remaining bytes must be an even number of rule bytes. Each rule's method and
// condition bytes are always surfaced raw; the EMV-table name is added as a
// best-effort label, with codes outside the table flagged rather than guessed.
func DecodeCVMList(raw []byte) (*CVMList, error) {
	if len(raw) < 8 {
		return nil, fmt.Errorf("emv: CVM List too short (%d bytes); need at least the 8-byte X/Y amount header", len(raw))
	}
	if (len(raw)-8)%2 != 0 {
		return nil, fmt.Errorf("emv: CVM List has %d trailing byte(s) after the amounts — rules must be 2-byte pairs", len(raw)-8)
	}
	out := &CVMList{
		AmountX: binary.BigEndian.Uint32(raw[0:4]),
		AmountY: binary.BigEndian.Uint32(raw[4:8]),
	}
	for i := 8; i+1 < len(raw); i += 2 {
		code, cond := raw[i], raw[i+1]
		methodCode := int(code & 0x3F)
		method, ok := cvmMethods[methodCode]
		if !ok {
			method = fmt.Sprintf("RFU / payment-system-specific (0x%02X)", methodCode)
		}
		condition, ok := cvmConditions[cond]
		if !ok {
			condition = fmt.Sprintf("RFU / payment-system-specific (0x%02X)", cond)
		}
		out.Rules = append(out.Rules, CVMRule{
			Raw:                     fmt.Sprintf("%02X%02X", code, cond),
			MethodByte:              fmt.Sprintf("0x%02X", code),
			MethodCode:              methodCode,
			Method:                  method,
			ApplyNextIfUnsuccessful: code&0x40 != 0,
			ConditionByte:           fmt.Sprintf("0x%02X", cond),
			Condition:               condition,
		})
	}
	if len(out.Rules) == 0 {
		out.Notes = append(out.Notes, "no CVM rules present (only the X/Y amount header)")
	}
	return out, nil
}

// DecodeCVMListHex is the hex-string convenience wrapper.
func DecodeCVMListHex(s string) (*CVMList, error) {
	b, err := hex.DecodeString(stripSeparators(s))
	if err != nil {
		return nil, fmt.Errorf("emv: invalid hex: %w", err)
	}
	return DecodeCVMList(b)
}
