// SPDX-License-Identifier: AGPL-3.0-or-later

package emv

import (
	"encoding/hex"
	"fmt"
)

// AIP is a decoded EMV Application Interchange Profile (tag 82): the 2-byte
// bitfield in which the card advertises which authentication and verification
// capabilities it supports. Byte 1's bits are defined unambiguously in EMV 4.3
// Book 3, Annex C1 (Table 41); byte 2 is RFU in the contact profile and is
// repurposed by individual contactless kernels, so it is surfaced raw and not
// interpreted.
type AIP struct {
	Raw   string `json:"raw"`   // the 2 bytes, hex
	Byte1 string `json:"byte1"` // 0xNN
	Byte2 string `json:"byte2"` // 0xNN

	// Byte-1 capability bits (EMV Book 3 Annex C1).
	SDA                    bool `json:"sda_supported"`                        // bit 7 (0x40)
	DDA                    bool `json:"dda_supported"`                        // bit 6 (0x20)
	CardholderVerification bool `json:"cardholder_verification_supported"`    // bit 5 (0x10)
	TerminalRiskManagement bool `json:"terminal_risk_management_to_perform"`  // bit 4 (0x08)
	IssuerAuthentication   bool `json:"issuer_authentication_supported"`      // bit 3 (0x04)
	OnDeviceCVM            bool `json:"on_device_cardholder_verif_supported"` // bit 2 (0x02), EMV 4.3+
	CDA                    bool `json:"cda_supported"`                        // bit 1 (0x01)

	// Capabilities is the human-readable list of the set byte-1 bits, in
	// bit order, for a quick read of what the card advertises.
	Capabilities []string `json:"capabilities"`

	// OfflineDataAuthentication summarises the SDA/DDA/CDA story — the
	// single most security-relevant takeaway from an AIP.
	OfflineDataAuthentication string `json:"offline_data_authentication"`

	Notes []string `json:"notes,omitempty"`
}

// aipBit pairs a byte-1 mask with its EMV Book 3 capability name, in bit order
// (high to low) so the Capabilities list reads top-down.
var aipBits = []struct {
	mask byte
	name string
}{
	{0x40, "Static Data Authentication (SDA) supported"},
	{0x20, "Dynamic Data Authentication (DDA) supported"},
	{0x10, "Cardholder verification is supported"},
	{0x08, "Terminal risk management is to be performed"},
	{0x04, "Issuer authentication is supported"},
	{0x02, "On-device cardholder verification is supported"},
	{0x01, "Combined DDA / Application Cryptogram generation (CDA) supported"},
}

// DecodeAIP decodes the raw bytes of EMV tag 82 (Application Interchange
// Profile). The AIP is a fixed 2-byte bitfield, so it is gated structurally:
// exactly 2 bytes must be present. Byte 1's seven defined capability bits are
// decoded per EMV Book 3 Annex C1; byte 1 bit 8 and the whole of byte 2 are
// RFU in the contact profile and are surfaced raw with a note rather than
// guessed (no confidently-wrong output).
func DecodeAIP(raw []byte) (*AIP, error) {
	if len(raw) != 2 {
		return nil, fmt.Errorf("emv: AIP (tag 82) must be exactly 2 bytes, got %d", len(raw))
	}
	b1, b2 := raw[0], raw[1]
	out := &AIP{
		Raw:                    fmt.Sprintf("%02X%02X", b1, b2),
		Byte1:                  fmt.Sprintf("0x%02X", b1),
		Byte2:                  fmt.Sprintf("0x%02X", b2),
		SDA:                    b1&0x40 != 0,
		DDA:                    b1&0x20 != 0,
		CardholderVerification: b1&0x10 != 0,
		TerminalRiskManagement: b1&0x08 != 0,
		IssuerAuthentication:   b1&0x04 != 0,
		OnDeviceCVM:            b1&0x02 != 0,
		CDA:                    b1&0x01 != 0,
	}
	for _, b := range aipBits {
		if b1&b.mask != 0 {
			out.Capabilities = append(out.Capabilities, b.name)
		}
	}

	// Offline data authentication is the headline: which (if any) of
	// SDA/DDA/CDA the card offers. CDA is the strongest, then DDA, then SDA.
	switch {
	case out.CDA:
		out.OfflineDataAuthentication = "CDA (strongest — combined DDA + cryptogram)"
	case out.DDA:
		out.OfflineDataAuthentication = "DDA"
	case out.SDA:
		out.OfflineDataAuthentication = "SDA only (weakest — replayable; clone-prone)"
	default:
		out.OfflineDataAuthentication = "none advertised — card relies on online authorization"
	}

	if b1&0x80 != 0 {
		out.Notes = append(out.Notes,
			"byte 1 bit 8 (0x80) is set but reserved for future use (RFU) in EMV Book 3")
	}
	if b2 != 0 {
		out.Notes = append(out.Notes, fmt.Sprintf(
			"byte 2 (0x%02X) is RFU in the EMV Book 3 contact profile; contactless kernels "+
				"(Visa payWave / Mastercard PayPass) repurpose these bits — surfaced raw, not interpreted",
			b2))
	}
	return out, nil
}

// DecodeAIPHex is the hex-string convenience wrapper.
func DecodeAIPHex(s string) (*AIP, error) {
	b, err := hex.DecodeString(stripSeparators(s))
	if err != nil {
		return nil, fmt.Errorf("emv: invalid hex: %w", err)
	}
	return DecodeAIP(b)
}
