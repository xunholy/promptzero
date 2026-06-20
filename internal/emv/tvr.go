// SPDX-License-Identifier: AGPL-3.0-or-later

package emv

import (
	"encoding/hex"
	"fmt"
)

// TVR is a decoded EMV Terminal Verification Results (tag 95): the 5-byte
// bitfield in which the terminal records the outcome of every check it ran
// during a transaction — which offline-authentication, application-usage,
// cardholder-verification, risk-management and issuer-script steps passed,
// failed or were skipped. Every set bit is an exception the terminal flagged,
// so a TVR of all zeroes means a clean transaction. The bit meanings are
// defined in EMV 4.3 Book 3, Annex C5; all five bytes are terminal-defined and
// stable across payment systems (no contactless-kernel reinterpretation).
type TVR struct {
	Raw   string   `json:"raw"`   // the 5 bytes, hex
	Bytes []string `json:"bytes"` // each byte, 0xNN

	// Clean reports that no exception bit is set across all 5 bytes — the
	// terminal flagged nothing.
	Clean bool `json:"clean"`

	// Each group lists the set bits for one functional byte (omitted when
	// that byte is zero). Grouped per EMV Book 3 Annex C5's own byte layout.
	OfflineDataAuthentication []string `json:"offline_data_authentication,omitempty"` // byte 1
	ApplicationUsage          []string `json:"application_usage,omitempty"`           // byte 2
	CardholderVerification    []string `json:"cardholder_verification,omitempty"`     // byte 3
	TerminalRiskManagement    []string `json:"terminal_risk_management,omitempty"`    // byte 4
	IssuerScriptProcessing    []string `json:"issuer_script_processing,omitempty"`    // byte 5

	// Indications is the flat list of every set defined bit, in byte/bit
	// order — a one-glance read of everything the terminal flagged.
	Indications []string `json:"indications"`

	Notes []string `json:"notes,omitempty"`
}

// tvrBit pairs a bit mask with its EMV Book 3 Annex C5 meaning.
type tvrBit struct {
	mask byte
	name string
}

// The five TVR byte definitions, EMV 4.3 Book 3 Annex C5. Bits absent from a
// byte's table are RFU and are surfaced via a note rather than named.
var (
	tvrByte1 = []tvrBit{
		{0x80, "Offline data authentication was not performed"},
		{0x40, "SDA failed"},
		{0x20, "ICC data missing"},
		{0x10, "Card appears on terminal exception file"},
		{0x08, "DDA failed"},
		{0x04, "CDA failed"},
		{0x02, "SDA selected"},
	}
	tvrByte2 = []tvrBit{
		{0x80, "ICC and terminal have different application versions"},
		{0x40, "Expired application"},
		{0x20, "Application not yet effective"},
		{0x10, "Requested service not allowed for card product"},
		{0x08, "New card"},
	}
	tvrByte3 = []tvrBit{
		{0x80, "Cardholder verification was not successful"},
		{0x40, "Unrecognised CVM"},
		{0x20, "PIN Try Limit exceeded"},
		{0x10, "PIN entry required and PIN pad not present or not working"},
		{0x08, "PIN entry required, PIN pad present, but PIN was not entered"},
		{0x04, "Online PIN entered"},
	}
	tvrByte4 = []tvrBit{
		{0x80, "Transaction exceeds floor limit"},
		{0x40, "Lower consecutive offline limit exceeded"},
		{0x20, "Upper consecutive offline limit exceeded"},
		{0x10, "Transaction selected randomly for online processing"},
		{0x08, "Merchant forced transaction online"},
	}
	tvrByte5 = []tvrBit{
		{0x80, "Default TDOL used"},
		{0x40, "Issuer authentication failed"},
		{0x20, "Script processing failed before final GENERATE AC"},
		{0x10, "Script processing failed after final GENERATE AC"},
	}
)

// definedMask is the OR of every named bit in a byte table — the complement is
// the RFU mask for that byte.
func definedMask(bits []tvrBit) byte {
	var m byte
	for _, b := range bits {
		m |= b.mask
	}
	return m
}

// setBits returns the names of every table bit set in b, in table (high-to-low)
// order.
func setBits(b byte, table []tvrBit) []string {
	var out []string
	for _, t := range table {
		if b&t.mask != 0 {
			out = append(out, t.name)
		}
	}
	return out
}

// DecodeTVR decodes the raw bytes of EMV tag 95 (Terminal Verification
// Results). The TVR is a fixed 5-byte bitfield, so it is gated structurally:
// exactly 5 bytes must be present. Each byte's defined bits are decoded per EMV
// Book 3 Annex C5; any RFU bit that is set is surfaced via a note rather than
// named (no confidently-wrong output).
func DecodeTVR(raw []byte) (*TVR, error) {
	if len(raw) != 5 {
		return nil, fmt.Errorf("emv: TVR (tag 95) must be exactly 5 bytes, got %d", len(raw))
	}
	out := &TVR{
		Raw: fmt.Sprintf("%010X", raw),
		Bytes: []string{
			fmt.Sprintf("0x%02X", raw[0]),
			fmt.Sprintf("0x%02X", raw[1]),
			fmt.Sprintf("0x%02X", raw[2]),
			fmt.Sprintf("0x%02X", raw[3]),
			fmt.Sprintf("0x%02X", raw[4]),
		},
	}

	groups := []struct {
		b     byte
		table []tvrBit
		dst   *[]string
		label string
	}{
		{raw[0], tvrByte1, &out.OfflineDataAuthentication, "byte 1"},
		{raw[1], tvrByte2, &out.ApplicationUsage, "byte 2"},
		{raw[2], tvrByte3, &out.CardholderVerification, "byte 3"},
		{raw[3], tvrByte4, &out.TerminalRiskManagement, "byte 4"},
		{raw[4], tvrByte5, &out.IssuerScriptProcessing, "byte 5"},
	}
	for _, g := range groups {
		names := setBits(g.b, g.table)
		*g.dst = names
		out.Indications = append(out.Indications, names...)
		if rfu := g.b &^ definedMask(g.table); rfu != 0 {
			out.Notes = append(out.Notes, fmt.Sprintf(
				"%s has RFU bit(s) set (0x%02X) — reserved for future use in EMV Book 3, surfaced raw",
				g.label, rfu))
		}
	}

	out.Clean = len(out.Indications) == 0
	if out.Clean {
		out.Indications = []string{} // stable empty list, not null, in JSON
	}
	return out, nil
}

// DecodeTVRHex is the hex-string convenience wrapper.
func DecodeTVRHex(s string) (*TVR, error) {
	b, err := hex.DecodeString(stripSeparators(s))
	if err != nil {
		return nil, fmt.Errorf("emv: invalid hex: %w", err)
	}
	return DecodeTVR(b)
}
