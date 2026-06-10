// Package pypitoken decodes a PyPI API token into the blast radius it carries.
//
// A PyPI token is "pypi-" + a base64-serialized macaroon (pypi/warehouse and
// the pypitoken library). The macaroon's first-party caveats are JSON-encoded
// restrictions that *narrow* what the token can do — to specific projects, a
// time window, or a user — and crucially they remain readable without the
// issuing secret. Decoding them turns a leaked token from "some PyPI secret"
// into "an account-wide upload token" vs "scoped to package foo, expires
// 2026-01-01" — the difference that drives incident response.
//
// No confidently-wrong output: this decodes structure only. It surfaces the
// macaroon location/identifier and each restriction; it never claims the token
// is live or valid against PyPI (that needs an API call) and never verifies the
// macaroon signature (that needs the root key). An unrecognised caveat is
// returned with its raw JSON rather than guessed.
//
// Wrap-vs-native: native — delegates the binary parse to internal/macaroon and
// interprets the caveats with encoding/json; no new go.mod dep. Caveat tags and
// JSON shapes are taken from pypi/warehouse and the pypitoken library
// (restrictions.py): new-format tags 0=date, 1=project-names, 2=project-ids,
// 3=user-id, plus the three legacy object forms.
package pypitoken

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/xunholy/promptzero/internal/macaroon"
)

// Restriction is one decoded PyPI caveat.
type Restriction struct {
	// Kind is one of: "noop", "project_names", "project_ids", "date",
	// "user_id", or "unknown".
	Kind string `json:"kind"`
	// Legacy is true for the pre-2022 JSON-object caveat forms.
	Legacy bool `json:"legacy"`
	// Projects holds normalized project names (project_names) or project IDs
	// (project_ids).
	Projects []string `json:"projects,omitempty"`
	// UserID is set for a user_id restriction.
	UserID string `json:"user_id,omitempty"`
	// NotBefore / Expires are Unix timestamps for a date restriction (0 = unset).
	NotBefore int64 `json:"not_before,omitempty"`
	Expires   int64 `json:"expires,omitempty"`
	// Raw is the verbatim caveat JSON, always populated.
	Raw string `json:"raw"`
}

// Result is the decoded PyPI token.
type Result struct {
	Type            string        `json:"type"`
	Location        string        `json:"location"`
	Identifier      string        `json:"identifier"`
	IdentifierHex   string        `json:"identifier_hex,omitempty"`
	MacaroonVersion int           `json:"macaroon_version"`
	Restrictions    []Restriction `json:"restrictions"`
	// Scope is a one-line human summary of the blast radius.
	Scope string `json:"scope"`
	// WellFormed is true when the token parses as a macaroon scoped to a PyPI
	// location (pypi.org / test.pypi.org). It asserts structure, not liveness.
	WellFormed bool   `json:"well_formed"`
	Note       string `json:"note"`
}

// Decode parses a PyPI token ("pypi-...") into its restrictions and a summary of
// the access it grants. It returns an error for a missing prefix or a token that
// does not parse as a macaroon.
func Decode(token string) (*Result, error) {
	token = strings.TrimSpace(token)
	rest, ok := strings.CutPrefix(token, "pypi-")
	if !ok {
		return nil, fmt.Errorf("not a PyPI token: missing %q prefix", "pypi-")
	}
	if rest == "" {
		return nil, fmt.Errorf("PyPI token has empty macaroon body")
	}
	m, err := macaroon.DecodeBase64(rest)
	if err != nil {
		return nil, fmt.Errorf("decode macaroon: %w", err)
	}

	res := &Result{
		Type:            "PyPI API token",
		Location:        m.Location,
		MacaroonVersion: m.Version,
		Restrictions:    make([]Restriction, 0, len(m.Caveats)),
		Note: "Structure only — not checked against PyPI (liveness needs an API call) " +
			"and the macaroon signature is not verified (needs the issuing secret).",
	}
	setIdentifier(res, m.Identifier)
	res.WellFormed = m.Location == "pypi.org" || m.Location == "test.pypi.org"

	for _, c := range m.Caveats {
		// PyPI uses first-party caveats only; a third-party caveat would be
		// unexpected, so surface it raw rather than misinterpret it.
		res.Restrictions = append(res.Restrictions, parseCaveat(c.ID))
	}
	res.Scope = summarize(res.Restrictions)
	return res, nil
}

// setIdentifier records the macaroon identifier as a UTF-8 string when it is one
// (PyPI uses a UUID/macaroon-id string), and always as hex for the binary case.
func setIdentifier(res *Result, id []byte) {
	if utf8.Valid(id) {
		res.Identifier = string(id)
	}
	res.IdentifierHex = hex.EncodeToString(id)
}

// parseCaveat interprets a single first-party caveat's JSON. New-format caveats
// are JSON arrays whose first element is an integer tag; legacy caveats are JSON
// objects. Anything else is returned as Kind "unknown" with its raw bytes.
func parseCaveat(raw []byte) Restriction {
	r := Restriction{Kind: "unknown", Raw: string(raw)}

	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
		return parseNewCaveat(arr, r)
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err == nil {
		return parseLegacyCaveat(obj, r)
	}
	return r
}

// parseNewCaveat handles the post-2022 array form: [tag, ...].
func parseNewCaveat(arr []json.RawMessage, r Restriction) Restriction {
	var tag int
	if err := json.Unmarshal(arr[0], &tag); err != nil {
		return r
	}
	switch tag {
	case 0: // [0, not_after, not_before]
		r.Kind = "date"
		if len(arr) >= 3 {
			_ = json.Unmarshal(arr[1], &r.Expires)
			_ = json.Unmarshal(arr[2], &r.NotBefore)
		}
	case 1: // [1, [names]]
		r.Kind = "project_names"
		if len(arr) >= 2 {
			_ = json.Unmarshal(arr[1], &r.Projects)
		}
	case 2: // [2, [ids]]
		r.Kind = "project_ids"
		if len(arr) >= 2 {
			_ = json.Unmarshal(arr[1], &r.Projects)
		}
	case 3: // [3, user_id]
		r.Kind = "user_id"
		if len(arr) >= 2 {
			_ = json.Unmarshal(arr[1], &r.UserID)
		}
	}
	return r
}

// parseLegacyCaveat handles the pre-2022 object forms.
func parseLegacyCaveat(obj map[string]json.RawMessage, r Restriction) Restriction {
	r.Legacy = true
	// {"nbf":..,"exp":..}
	if _, hasNbf := obj["nbf"]; hasNbf {
		r.Kind = "date"
		_ = json.Unmarshal(obj["nbf"], &r.NotBefore)
		_ = json.Unmarshal(obj["exp"], &r.Expires)
		return r
	}
	perm, ok := obj["permissions"]
	if !ok {
		return r
	}
	// {"version":1,"permissions":"user"} — account-wide.
	var s string
	if err := json.Unmarshal(perm, &s); err == nil {
		if s == "user" {
			r.Kind = "noop"
		}
		return r
	}
	// {"version":1,"permissions":{"projects":[...]}}
	var pp struct {
		Projects []string `json:"projects"`
	}
	if err := json.Unmarshal(perm, &pp); err == nil && pp.Projects != nil {
		r.Kind = "project_names"
		r.Projects = pp.Projects
	}
	return r
}

// summarize renders the token's blast radius in one line: which restrictions
// actually narrow it, or that it is account-wide.
func summarize(rs []Restriction) string {
	var parts []string
	accountWide := true
	for _, r := range rs {
		switch r.Kind {
		case "noop":
			// explicit account-wide marker — does not narrow scope
		case "project_names":
			accountWide = false
			parts = append(parts, "projects: "+strings.Join(r.Projects, ", "))
		case "project_ids":
			accountWide = false
			parts = append(parts, "project IDs: "+strings.Join(r.Projects, ", "))
		case "user_id":
			accountWide = false
			parts = append(parts, "user: "+r.UserID)
		case "date":
			accountWide = false
			parts = append(parts, fmt.Sprintf("valid window nbf=%d exp=%d", r.NotBefore, r.Expires))
		default:
			accountWide = false
			parts = append(parts, "unrecognised restriction")
		}
	}
	if accountWide {
		return "account-wide (no project/date/user restriction) — can upload to ANY project owned by the account"
	}
	return strings.Join(parts, "; ")
}
