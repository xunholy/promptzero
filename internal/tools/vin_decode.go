// vin_decode.go — host-side Vehicle Identification Number decoder/validator
// Spec, delegating to internal/vin.
//
// Wrap-vs-native: native — the VIN check-digit algorithm (transliteration
// table + position weights, mod 11), the ISO 3780 region ranges, and the
// 30-character model-year cycle are public fixed specs over a 17-byte string.
// It is the offline complement to the automotive stack: a VIN is what UDS
// ReadDataByIdentifier (DID 0xF190) and OBD-II Mode 09 PID 02 return, so a VIN
// read over CAN can be validated and broken down here. Offline read, no
// hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/vin"
)

func init() { //nolint:gochecknoinits
	Register(vinDecodeSpec)
}

var vinDecodeSpec = Spec{
	Name: "vin_decode",
	Description: "Decode and validate a 17-character Vehicle Identification Number (ISO 3779 / ISO 3780) " +
		"— the offline complement to the automotive diagnostic tools. A VIN is what UDS " +
		"ReadDataByIdentifier (DID 0xF190, i.e. the 22 F1 90 request) and OBD-II Mode 09 PID 02 return, " +
		"so a VIN read off the bus can be validated and broken down here without further bus access.\n\n" +
		"Recomputes the position-9 check digit (the transliteration-table + position-weight mod-11 " +
		"algorithm) and reports whether it matches — the verification anchor. Because the check digit is " +
		"mandatory only in North America and China, a mismatch is reported as advisory (check_digit_valid " +
		"+ a note), not asserted as an invalid VIN. Also returns the ISO 3780 region (from the first " +
		"character), the candidate model years (the position-10 code is a 30-year cycle, so candidates " +
		"are returned, not a single year), the plant code, and the structural split (WMI / VDS / VIS). " +
		"The WMI is surfaced raw — the manufacturer registry is a large proprietary table, so a " +
		"manufacturer name is deliberately not guessed (no confidently-wrong output). The I/O/Q exclusion " +
		"and length are validated.\n\n" +
		"Offline transform — reads a string, transmits nothing, so it is Low risk. Wrap-vs-native: " +
		"native — fixed-table arithmetic over a 17-byte string, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"vin":{"type":"string","description":"17-character VIN. ' ' / '-' / '_' separators tolerated; case-insensitive."}
		},
		"required":["vin"]
	}`),
	Required:  []string{"vin"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   vinDecodeHandler,
}

func vinDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "vin")) == "" {
		return "", fmt.Errorf("vin_decode: 'vin' is required")
	}
	res, err := vin.Decode(str(p, "vin"))
	if err != nil {
		return "", fmt.Errorf("vin_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
