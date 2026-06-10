// macaroon_decode.go — host-side generic macaroon decoder Spec, delegating to
// internal/macaroon.
//
// Wrap-vs-native: native — exposes the in-tree libmacaroons binary parser
// (internal/macaroon, gold-vector-verified) for any macaroon, not just PyPI
// tokens: Lightning L402 / LSAT HTTP-402 auth tokens, Google / Ubuntu SSO
// macaroons, and other delegated-authorization credentials. Surfaces the
// location, identifier, caveats (the attenuations restricting the token), and
// signature so an operator can triage a captured macaroon offline. Offline; no
// network or device.

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/xunholy/promptzero/internal/macaroon"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(macaroonDecodeSpec)
}

var macaroonDecodeSpec = Spec{
	Name: "macaroon_decode",
	Description: "Decode a **macaroon** authorization credential into its location, identifier, caveats, and " +
		"signature. Macaroons are delegated-authorization tokens (Google's design) used by **Lightning L402 / " +
		"LSAT** paid-API auth, **PyPI** API tokens, Ubuntu SSO, and others; their power is that the **caveats " +
		"— the attenuations restricting what the token can do — are readable without the issuing secret**. " +
		"This decodes the libmacaroons binary serialization (both v1 packet and v2 binary formats) and " +
		"surfaces every field so a captured token can be triaged **offline, with no network call**.\n\n" +
		"Accepts the base64 macaroon (URL-safe or standard), optionally prefixed with an `L402 ` / `LSAT ` " +
		"scheme and/or suffixed with `:<preimage>` (the L402 header shape) — the macaroon part is decoded and " +
		"the preimage surfaced separately. Each caveat is reported as first- or third-party with its ID (as " +
		"text when printable, else hex), and the signature is shown as hex. **No confidently-wrong output**: " +
		"it asserts the macaroon's **structure only** — it does **not** verify the signature chain (that needs " +
		"the issuing root key, absent from a captured token) and never claims the token is valid or live. For " +
		"a PyPI token (`pypi-…`), `pypi_token_decode` additionally **interprets** the caveat JSON into a named " +
		"scope. No network, no device, transmits nothing — Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (credential forensics). Wrap-vs-native: native — wraps the " +
		"in-tree internal/macaroon parser (anchored to the pymacaroons cross-implementation v1/v2 vectors), " +
		"stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"macaroon":{"type":"string","description":"The base64 macaroon (optionally an 'L402 <mac>:<preimage>' / 'LSAT …' token)."}
		},
		"required":["macaroon"]
	}`),
	Required:  []string{"macaroon"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   macaroonDecodeHandler,
}

// macaroonCaveatView is the JSON presentation of one caveat.
type macaroonCaveatView struct {
	Location   string `json:"location,omitempty"`
	ID         string `json:"id,omitempty"`
	IDHex      string `json:"id_hex,omitempty"`
	VIDHex     string `json:"vid_hex,omitempty"`
	FirstParty bool   `json:"first_party"`
}

// macaroonView is the JSON presentation of a decoded macaroon.
type macaroonView struct {
	Version       int                  `json:"version"`
	Location      string               `json:"location,omitempty"`
	Identifier    string               `json:"identifier,omitempty"`
	IdentifierHex string               `json:"identifier_hex,omitempty"`
	Caveats       []macaroonCaveatView `json:"caveats"`
	SignatureHex  string               `json:"signature_hex"`
	Preimage      string               `json:"l402_preimage,omitempty"`
	Note          string               `json:"note"`
}

func macaroonDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := strings.TrimSpace(str(p, "macaroon"))
	if raw == "" {
		return "", fmt.Errorf("macaroon_decode: 'macaroon' is required")
	}
	body, preimage := splitL402(raw)
	m, err := macaroon.DecodeBase64(body)
	if err != nil {
		return "", fmt.Errorf("macaroon_decode: %w", err)
	}

	view := macaroonView{
		Version:      m.Version,
		Location:     m.Location,
		SignatureHex: hex.EncodeToString(m.Signature),
		Caveats:      make([]macaroonCaveatView, 0, len(m.Caveats)),
		Preimage:     preimage,
		Note: "Structure only — the signature chain is not verified (needs the issuing root key) and the " +
			"token is not checked for liveness. For a PyPI token use pypi_token_decode for the caveat scope.",
	}
	view.Identifier, view.IdentifierHex = textAndHex(m.Identifier)
	for _, c := range m.Caveats {
		cv := macaroonCaveatView{Location: c.Location, FirstParty: c.FirstParty()}
		cv.ID, cv.IDHex = textAndHex(c.ID)
		if len(c.VID) > 0 {
			cv.VIDHex = hex.EncodeToString(c.VID)
		}
		view.Caveats = append(view.Caveats, cv)
	}

	out, _ := json.MarshalIndent(view, "", "  ")
	return string(out), nil
}

// splitL402 strips an optional "L402 " / "LSAT " scheme prefix and splits the
// "<macaroon>:<preimage>" form, returning the macaroon body and any preimage.
func splitL402(in string) (body, preimage string) {
	for _, scheme := range []string{"L402 ", "LSAT "} {
		if len(in) >= len(scheme) && strings.EqualFold(in[:len(scheme)], scheme) {
			in = strings.TrimSpace(in[len(scheme):])
			break
		}
	}
	// Base64 (std + URL-safe) never contains ':', so a colon delimits the
	// optional L402 preimage suffix.
	if i := strings.IndexByte(in, ':'); i >= 0 {
		return strings.TrimSpace(in[:i]), strings.TrimSpace(in[i+1:])
	}
	return in, ""
}

// textAndHex returns b as a string when it is printable UTF-8, and always as
// hex, so binary identifiers/caveats are never rendered as mojibake.
func textAndHex(b []byte) (text, hexStr string) {
	hexStr = hex.EncodeToString(b)
	if utf8.Valid(b) && isPrintable(b) {
		text = string(b)
	}
	return text, hexStr
}

// isPrintable reports whether every byte is a printable / space ASCII or
// multibyte UTF-8 lead/continuation — used to decide whether to show text.
func isPrintable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			return false
		}
	}
	return true
}
