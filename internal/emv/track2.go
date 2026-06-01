// SPDX-License-Identifier: AGPL-3.0-or-later

package emv

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Track2 is the decoded contents of EMV tag 57 (Track 2 Equivalent Data) /
// ISO 7813 track 2. The BER-TLV walker in this package surfaces tag 57's raw
// value bytes but leaves the nibble-packed track structure untouched;
// DecodeTrack2 cracks it into the security-relevant fields.
type Track2 struct {
	PAN                string   `json:"pan"`
	PANMasked          string   `json:"pan_masked"`
	Expiry             string   `json:"expiry"`       // raw YYMM as encoded
	ExpiryFormatted    string   `json:"expiry_mm_yy"` // MM/YY
	ServiceCode        string   `json:"service_code"` // 3 digits
	ServiceCodeMeaning string   `json:"service_code_meaning,omitempty"`
	Discretionary      string   `json:"discretionary_data,omitempty"`
	LuhnValid          bool     `json:"luhn_valid"`
	Notes              []string `json:"notes,omitempty"`
}

// DecodeTrack2 decodes the raw bytes of EMV tag 57 (Track 2 Equivalent Data).
// The format is nibble-packed BCD: <PAN> 'D' <YYMM expiry> <3-digit service
// code> <discretionary data> with an optional trailing 'F' pad nibble. The
// PAN's trailing Luhn check digit is the verification anchor — the decode is
// reported with luhn_valid so a misframed blob is surfaced, never asserted as
// a valid card number.
func DecodeTrack2(raw []byte) (*Track2, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("emv: empty track 2 data")
	}
	// Expand to nibbles. Track 2 uses 'D' (0xD) as the field separator and
	// 'F' (0xF) as the trailing pad; all other nibbles are decimal digits.
	nibbles := make([]byte, 0, len(raw)*2)
	for _, b := range raw {
		nibbles = append(nibbles, hexNibble(b>>4), hexNibble(b&0x0F))
	}
	s := string(nibbles)

	sep := strings.IndexByte(s, 'D')
	if sep < 0 {
		return nil, fmt.Errorf("emv: no 'D' field separator — not Track 2 Equivalent Data")
	}
	pan := s[:sep]
	rest := s[sep+1:]
	if !allDigits(pan) {
		return nil, fmt.Errorf("emv: PAN contains non-decimal nibble %q", pan)
	}
	if len(pan) < 8 || len(pan) > 19 {
		return nil, fmt.Errorf("emv: PAN length %d outside ISO 7812 range (8-19)", len(pan))
	}
	if len(rest) < 7 {
		return nil, fmt.Errorf("emv: track 2 truncated after separator (need expiry+service code)")
	}

	expiry := rest[:4]
	service := rest[4:7]
	disc := strings.TrimRight(rest[7:], "F") // strip the trailing pad nibble(s)

	if !allDigits(expiry) {
		return nil, fmt.Errorf("emv: expiry %q is not 4 BCD digits", expiry)
	}
	if !allDigits(service) {
		return nil, fmt.Errorf("emv: service code %q is not 3 BCD digits", service)
	}

	t := &Track2{
		PAN:                pan,
		PANMasked:          maskPAN(pan),
		Expiry:             expiry,
		ExpiryFormatted:    expiry[2:4] + "/" + expiry[0:2], // YYMM -> MM/YY
		ServiceCode:        service,
		ServiceCodeMeaning: serviceCodeMeaning(service),
		Discretionary:      disc,
		LuhnValid:          luhnValid(pan),
	}
	if !t.LuhnValid {
		t.Notes = append(t.Notes, "PAN fails the Luhn check digit — misframed track or non-standard PAN; treat the decode as unverified")
	}
	return t, nil
}

// DecodeTrack2Hex is the hex-string convenience wrapper.
func DecodeTrack2Hex(s string) (*Track2, error) {
	b, err := hex.DecodeString(stripSeparators(s))
	if err != nil {
		return nil, fmt.Errorf("emv: invalid hex: %w", err)
	}
	return DecodeTrack2(b)
}

func hexNibble(n byte) byte {
	const h = "0123456789ABCDEF"
	return h[n&0x0F]
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// luhnValid runs the ISO 7812 Luhn checksum over the full PAN (the check
// digit is the PAN's last digit).
func luhnValid(pan string) bool {
	sum := 0
	alt := false
	for i := len(pan) - 1; i >= 0; i-- {
		d := int(pan[i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// maskPAN renders a PCI-style masked PAN: BIN (first 6) + last 4 visible, the
// middle replaced with '*'. Short PANs keep only the last 4.
func maskPAN(pan string) string {
	if len(pan) <= 10 {
		if len(pan) <= 4 {
			return pan
		}
		return strings.Repeat("*", len(pan)-4) + pan[len(pan)-4:]
	}
	return pan[:6] + strings.Repeat("*", len(pan)-10) + pan[len(pan)-4:]
}

// serviceCodeMeaning expands the 3-digit ISO 7813 service code. Each digit is
// an independent field; an unrecognised digit is left blank rather than
// guessed.
func serviceCodeMeaning(sc string) string {
	if len(sc) != 3 {
		return ""
	}
	d1 := map[byte]string{
		'1': "international interchange",
		'2': "international interchange, IC preferred",
		'5': "national interchange",
		'6': "national interchange, IC preferred",
		'7': "private",
		'9': "test",
	}[sc[0]]
	d2 := map[byte]string{
		'0': "normal authorisation",
		'2': "online authorisation only",
		'4': "online authorisation except under bilateral agreement",
	}[sc[1]]
	d3 := map[byte]string{
		'0': "no restrictions, PIN required",
		'1': "no restrictions",
		'2': "goods and services only",
		'3': "ATM only, PIN required",
		'4': "cash only",
		'5': "goods and services only, PIN required",
		'6': "no restrictions, prompt for PIN if PED present",
		'7': "goods and services only, prompt for PIN if PED present",
	}[sc[2]]
	parts := make([]string, 0, 3)
	for _, p := range []string{d1, d2, d3} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, "; ")
}
