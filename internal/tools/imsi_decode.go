// imsi_decode.go — host-side IMSI (cellular subscriber identity) decoder
// Spec, delegating to internal/imsi.
//
// Wrap-vs-native: native — the IMSI structure (MCC + MNC + MSIN, 3GPP TS
// 23.003 / ITU-T E.212) is a fixed digit-field split and the MCC→country
// map is public ITU data (code-generated from python-stdnum's imsi.dat).
// The subscriber-identity companion to imei_decode: both are harvested by
// an IMSI-catcher and visible in a gsmtap capture. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/imsi"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(imsiDecodeSpec)
}

var imsiDecodeSpec = Spec{
	Name: "imsi_decode",
	Description: "Decode an **IMSI** — the International Mobile Subscriber Identity, the up-to-15-digit number " +
		"on a SIM/USIM that uniquely names a cellular subscriber. The subscriber-identity companion to " +
		"`imei_decode` (the device identity): both are disclosed in plaintext in a GSM/LTE Identity " +
		"Response — the message an **IMSI-catcher** / cell-site simulator forces a handset to send, visible " +
		"in a gsmtap capture — so an identity read off the air can be broken down here.\n\n" +
		"Splits the IMSI into:\n" +
		"- **MCC** (Mobile Country Code, first 3 digits) → **country**, via the authoritative ITU-T E.212 " +
		"assignment table.\n" +
		"- **MNC** (Mobile Network Code, 2 or 3 digits — the length is country-determined) → the operator's " +
		"numeric code.\n" +
		"- **MSIN** (the remaining subscriber digits).\n\n" +
		"The MCC→country mapping is authoritative and unambiguous. The MNC/MSIN split was verified against " +
		"the python-stdnum reference library across all 2543 assigned MNCs of the 215 single-MNC-length " +
		"countries (zero mismatches); for the 22 countries that assign **both** 2- and 3-digit MNCs (e.g. " +
		"USA 310, India 405) the split uses the predominant length and is **flagged** (`mnc_length_assumed`) " +
		"rather than asserted. The operator (MNC→carrier name) lookup is deliberately **deferred** — that " +
		"data is proprietary and churns as carriers rename/merge, so the numeric MNC is surfaced rather " +
		"than a possibly-wrong carrier name (no confidently-wrong output). IMSI carries no check digit, so " +
		"validity is structural (length + a known MCC).\n\n" +
		"Offline transform — reads a digit string, transmits nothing, so it is Low risk. ' ' / '-' / ':' " +
		"separators tolerated. Source: docs/catalog/gap-analysis.md (cellular subscriber-identity decode — " +
		"the IMSI gap deferred by imei_decode). Wrap-vs-native: native — table lookup + digit-field split, " +
		"stdlib only, no new go.mod dep; the MCC table is code-generated from python-stdnum's imsi.dat.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"imsi":{"type":"string","description":"Up-to-15-digit IMSI. ' ' / '-' / ':' separators tolerated."}
		},
		"required":["imsi"]
	}`),
	Required:  []string{"imsi"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   imsiDecodeHandler,
}

func imsiDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "imsi")) == "" {
		return "", fmt.Errorf("imsi_decode: 'imsi' is required")
	}
	res, err := imsi.Decode(str(p, "imsi"))
	if err != nil {
		return "", fmt.Errorf("imsi_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
