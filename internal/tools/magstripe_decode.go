// magstripe_decode.go — host-side magnetic-stripe swipe decoder Spec,
// delegating to internal/emv.DecodeMagstripe.
//
// Wrap-vs-native: native — parses the raw ASCII track data a card reader / MSR
// / skimmer emits (ISO 7813 Track 1 "%B…?" and Track 2 ";…?"), distinct from
// nfc_emv_track2_decode which handles the EMV chip's tag-57 BCD Track-2-
// Equivalent. Track 1 is the only track carrying the cardholder name. The PAN's
// Luhn check digit is the verification anchor and the 3-digit service code is
// expanded from the documented ISO 7813 table; the bit-level LRC is surfaced
// raw but not validated (a wrong verdict is worse than none). Pure offline
// transform over an operator-supplied swipe string; no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/emv"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(magstripeDecodeSpec)
}

var magstripeDecodeSpec = Spec{
	Name: "magstripe_decode",
	Description: "Decode a raw magnetic-stripe swipe — the ASCII track data a card reader / MSR / skimmer " +
		"emits — into structured fields. Parses ISO 7813 **Track 1** (`%B<PAN>^<NAME>^<YYMM><service>…?`, the " +
		"only track with the cardholder name) and **Track 2** (`;<PAN>=<YYMM><service>…?`), in either order; " +
		"pass one or both. The offline analysis complement to nfc_emv_track2_decode (which handles the EMV " +
		"chip's tag-57 BCD Track-2-Equivalent) — useful for skimmer-dump / payment- and access-card triage.\n\n" +
		"Returns PAN (also masked, BIN + last 4), cardholder name (surname / given), expiry (MM/YY), the " +
		"3-digit service code with its decoded ISO 7813 meaning (chip-preferred, PIN required, etc.), and " +
		"discretionary data. The PAN's Luhn check digit is validated and reported as luhn_valid, so a " +
		"misframed swipe is surfaced with a note rather than asserted as a real card number. The trailing " +
		"LRC character is surfaced raw but not validated (its check is on the bit-level encoding, a layer " +
		"below the ASCII string a reader gives you).\n\n" +
		"Offline transform over an operator-supplied string — no hardware, transmits nothing, so it is Low " +
		"risk. Verified in-tree against Luhn-valid test PANs (Visa 4111…, Mastercard 5555…). Wrap-vs-native: " +
		"native — deterministic ISO 7813 field parsing + Luhn, standard-library only.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"track":{"type":"string","description":"The raw swipe string: Track 1 (starts '%', ends '?'), Track 2 (starts ';', ends '?'), or both concatenated."}
		},
		"required":["track"]
	}`),
	Required:  []string{"track"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   magstripeDecodeHandler,
}

func magstripeDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	track := str(p, "track")
	if strings.TrimSpace(track) == "" {
		return "", fmt.Errorf("magstripe_decode: 'track' is required")
	}
	res, err := emv.DecodeMagstripe(track)
	if err != nil {
		return "", fmt.Errorf("magstripe_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
