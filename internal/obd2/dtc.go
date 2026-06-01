// SPDX-License-Identifier: AGPL-3.0-or-later

package obd2

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// DTC is one decoded Diagnostic Trouble Code.
type DTC struct {
	Code                 string `json:"code"`                  // canonical form, e.g. "P0143"
	Category             string `json:"category"`              // Powertrain | Chassis | Body | Network
	Raw                  string `json:"raw"`                   // the 2 source bytes as hex
	Generic              bool   `json:"generic"`               // SAE/ISO-controlled (first digit 0)
	ManufacturerSpecific bool   `json:"manufacturer_specific"` // manufacturer-controlled (first digit 1)
}

// dtcCategory maps the top 2 bits of the first DTC byte to the code letter
// and the human category name (SAE J2012).
var dtcCategory = [4]struct {
	letter string
	name   string
}{
	{"P", "Powertrain"},
	{"C", "Chassis"},
	{"B", "Body"},
	{"U", "Network"},
}

// DecodeDTC unpacks a 2-byte Diagnostic Trouble Code into its canonical
// J2012 form. Byte A's top two bits select the category letter (P/C/B/U),
// the next two bits are the first digit (0-3), A's low nibble is the second
// digit, and byte B's two nibbles are the third and fourth digits.
//
//	A = 0x01, B = 0x43  ->  "P0143"
//	A = 0x04, B = 0x20  ->  "P0420"
func DecodeDTC(aByte, bByte byte) DTC {
	cat := dtcCategory[(aByte>>6)&0x03]
	first := (aByte >> 4) & 0x03
	second := aByte & 0x0F
	code := fmt.Sprintf("%s%X%X%02X", cat.letter, first, second, bByte)
	return DTC{
		Code:                 code,
		Category:             cat.name,
		Raw:                  strings.ToUpper(hex.EncodeToString([]byte{aByte, bByte})),
		Generic:              first == 0,
		ManufacturerSpecific: first == 1,
	}
}

// DTCResponse is the decoded view of a stored/pending/permanent DTC response.
type DTCResponse struct {
	Mode     int      `json:"mode,omitempty"`      // 0x43 / 0x47 / 0x4A when a service byte was present
	ModeName string   `json:"mode_name,omitempty"` // human service name
	Count    int      `json:"count"`               // number of trouble codes decoded
	DTCs     []DTC    `json:"dtcs"`
	Notes    []string `json:"notes,omitempty"`
}

var dtcModeNames = map[int]string{
	0x43: "Mode 03 — stored DTCs",
	0x47: "Mode 07 — pending DTCs (current/last drive cycle)",
	0x4A: "Mode 0A — permanent DTCs",
}

// DecodeDTCResponse parses a Mode-03/07/0A DTC response into its trouble
// codes. The input may be the response payload prefixed with the service
// byte (0x43 / 0x47 / 0x4A) or the bare stream of 2-byte DTCs. All-zero
// pairs (0x0000) are padding and are skipped. Separators and a 0x prefix
// are tolerated.
func DecodeDTCResponse(hexStr string) (*DTCResponse, error) {
	clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "", "\n", "", "\t", "").Replace(strings.TrimSpace(hexStr))
	if strings.HasPrefix(strings.ToLower(clean), "0x") {
		clean = clean[2:]
	}
	if clean == "" {
		return nil, fmt.Errorf("obd2: empty input")
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("obd2: invalid hex: %w", err)
	}

	out := &DTCResponse{}
	// Strip a leading Mode-03/07/0A service byte if present.
	if len(b) > 0 {
		if name, ok := dtcModeNames[int(b[0])]; ok {
			out.Mode = int(b[0])
			out.ModeName = name
			b = b[1:]
		}
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("obd2: no DTC bytes after the service byte")
	}
	if len(b)%2 != 0 {
		out.Notes = append(out.Notes,
			fmt.Sprintf("odd DTC byte count (%d); the trailing byte is ignored", len(b)))
		b = b[:len(b)-1]
	}
	for i := 0; i+1 < len(b); i += 2 {
		if b[i] == 0x00 && b[i+1] == 0x00 {
			continue // padding / empty slot
		}
		out.DTCs = append(out.DTCs, DecodeDTC(b[i], b[i+1]))
	}
	out.Count = len(out.DTCs)
	if out.Count == 0 {
		out.Notes = append(out.Notes, "no trouble codes (all slots empty) — system reports no faults")
	}
	return out, nil
}
