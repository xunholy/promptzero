// iccid_decode.go — host-side ICCID (SIM card serial) decoder Spec,
// delegating to internal/iccid.
//
// Wrap-vs-native: native — the ICCID structure (89 MII + E.164 country
// code + issuer/account + Luhn check, ITU-T E.118 / ISO-IEC 7812) is a
// fixed digit-field layout; Luhn arithmetic + a prefix-table lookup. The
// SIM-card leg of the cellular identifier triad with imei_decode (device)
// and imsi_decode (subscriber). Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/iccid"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(iccidDecodeSpec)
}

var iccidDecodeSpec = Spec{
	Name: "iccid_decode",
	Description: "Decode an **ICCID** — the Integrated Circuit Card Identifier, the serial number printed on " +
		"and stored in a SIM/USIM card (ITU-T E.118 / ISO-IEC 7812). The **SIM-card leg of the cellular " +
		"identifier triad** with `imei_decode` (the device) and `imsi_decode` (the subscriber) — the three " +
		"identities a SIM-swap / forensic seizure / IMSI-catcher engagement enumerates.\n\n" +
		"Breaks the ICCID into:\n" +
		"- **MII** — the Major Industry Identifier (the leading `89` = telecommunications); a non-89 MII is " +
		"flagged.\n" +
		"- **Country code** — the E.164 calling code (1-3 digits) after the MII → issuing **country / ISO " +
		"region**. E.164 codes are a prefix-free set, so the code is parsed unambiguously by longest valid " +
		"prefix; a code shared by several territories (the NANP `+1`, the `+44` British-Isles group) is " +
		"flagged with its primary country.\n" +
		"- **Issuer + account** — the remaining digits (surfaced combined; see below).\n" +
		"- **Luhn check digit** — recomputed and compared (`luhn_valid`).\n\n" +
		"The **Luhn check digit is the verification anchor**: a mismatch is reported as `luhn_valid=false` " +
		"with a note (a mistyped digit, or a card whose printed form omits the check digit), never asserted " +
		"as a definitively fake card. The issuer identifier and the individual account number are **not " +
		"split** from each other — the issuer-identifier length varies by operator with no public fixed " +
		"rule, so they are surfaced combined rather than guessed (the same reason `imei_decode` defers the " +
		"TAC→device lookup and `imsi_decode` defers the operator name). No confidently-wrong output.\n\n" +
		"Offline transform — reads a digit string, transmits nothing, so it is Low risk. ' ' / '-' / ':' " +
		"separators tolerated. Source: docs/catalog/gap-analysis.md (SIM-card identifier decode — completes " +
		"the IMEI/IMSI/ICCID triad). Wrap-vs-native: native — Luhn + a prefix-table lookup, stdlib only, no " +
		"new go.mod dep; the E.164 calling-code → country table is code-generated from Google libphonenumber.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"iccid":{"type":"string","description":"19-20 digit ICCID (SIM serial). ' ' / '-' / ':' separators tolerated."}
		},
		"required":["iccid"]
	}`),
	Required:  []string{"iccid"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   iccidDecodeHandler,
}

func iccidDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "iccid")) == "" {
		return "", fmt.Errorf("iccid_decode: 'iccid' is required")
	}
	res, err := iccid.Decode(str(p, "iccid"))
	if err != nil {
		return "", fmt.Errorf("iccid_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
