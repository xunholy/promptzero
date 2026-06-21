// SPDX-License-Identifier: AGPL-3.0-or-later

package emv

import (
	"encoding/hex"
	"fmt"
)

// CVMResults is a decoded EMV Cardholder Verification Method Results (tag
// 9F34): the 3-byte field recording which CVM the terminal actually performed
// and its outcome. It is the companion to the CVM List (tag 8E,
// nfc_emv_cvm_decode): the List is what the card asks for, the Results are what
// happened. The CVM-Performed and CVM-Condition bytes use the same encoding as
// a CVM List rule (EMV Book 3); the 1-byte result is EMV Book 4.
type CVMResults struct {
	Raw string `json:"raw"` // the 3 bytes, hex

	CVMPerformedByte        string `json:"cvm_performed_byte"`
	CVMCode                 int    `json:"cvm_code"` // low 6 bits
	CVMPerformed            string `json:"cvm_performed"`
	ApplyNextIfUnsuccessful bool   `json:"apply_next_if_unsuccessful"` // bit 7 (0x40)

	CVMConditionByte string `json:"cvm_condition_byte"`
	CVMCondition     string `json:"cvm_condition"`

	ResultByte string `json:"result_byte"`
	Result     string `json:"result"` // Unknown / Failed / Successful

	Notes []string `json:"notes,omitempty"`
}

// cvmResultNames maps the third byte (CVM Result) to its EMV Book 4 meaning.
var cvmResultNames = map[byte]string{
	0x00: "Unknown",
	0x01: "Failed",
	0x02: "Successful",
}

// DecodeCVMResults decodes the raw bytes of EMV tag 9F34 (CVM Results). The
// layout is fixed — CVM Performed, CVM Condition, CVM Result — so it is gated
// to exactly 3 bytes. The method and condition reuse the same EMV Book 3 tables
// as the CVM List decoder; a code outside the standard table is flagged
// RFU/payment-system-specific rather than guessed (no confidently-wrong
// output).
func DecodeCVMResults(raw []byte) (*CVMResults, error) {
	if len(raw) != 3 {
		return nil, fmt.Errorf("emv: CVM Results (tag 9F34) must be exactly 3 bytes, got %d", len(raw))
	}
	performed, cond, result := raw[0], raw[1], raw[2]

	methodCode := int(performed & 0x3F)
	method, ok := cvmMethods[methodCode]
	if !ok {
		method = fmt.Sprintf("RFU / payment-system-specific (0x%02X)", methodCode)
	}
	condition, ok := cvmConditions[cond]
	if !ok {
		condition = fmt.Sprintf("RFU / payment-system-specific (0x%02X)", cond)
	}
	resultName, ok := cvmResultNames[result]
	if !ok {
		resultName = fmt.Sprintf("RFU (0x%02X)", result)
	}

	out := &CVMResults{
		Raw:                     fmt.Sprintf("%02X%02X%02X", performed, cond, result),
		CVMPerformedByte:        fmt.Sprintf("0x%02X", performed),
		CVMCode:                 methodCode,
		CVMPerformed:            method,
		ApplyNextIfUnsuccessful: performed&0x40 != 0,
		CVMConditionByte:        fmt.Sprintf("0x%02X", cond),
		CVMCondition:            condition,
		ResultByte:              fmt.Sprintf("0x%02X", result),
		Result:                  resultName,
	}
	return out, nil
}

// DecodeCVMResultsHex is the hex-string convenience wrapper.
func DecodeCVMResultsHex(s string) (*CVMResults, error) {
	b, err := hex.DecodeString(stripSeparators(s))
	if err != nil {
		return nil, fmt.Errorf("emv: invalid hex: %w", err)
	}
	return DecodeCVMResults(b)
}
