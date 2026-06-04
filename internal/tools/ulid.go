// ulid.go — host-side ULID decoder Spec, delegating to internal/ulid.
//
// Wrap-vs-native: native — a ULID is Crockford base32 over a fixed 128-bit
// layout (48-bit ms timestamp + 80-bit randomness); decoding is a base-32
// decode + a uint48 read. Surfaces the embedded creation timestamp (the recon
// value). Completes the identifier-timestamp triad with uuid_decode /
// objectid_decode. Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/ulid"
)

func init() { //nolint:gochecknoinits
	Register(ulidDecodeSpec)
}

var ulidDecodeSpec = Spec{
	Name: "ulid_decode",
	Description: "Decode a ULID (Universally Unique Lexicographically Sortable Identifier) into its " +
		"embedded **creation timestamp** and randomness. A ULID is a 26-character Crockford-base32 string " +
		"encoding 128 bits — a 48-bit millisecond Unix timestamp followed by 80 bits of randomness — widely " +
		"used by modern backends as a sortable, UUID-sized identifier (the spec's answer to UUIDv4, a peer " +
		"of UUIDv7). Like a UUIDv1/v7 or a MongoDB ObjectId, a ULID is **not opaque**: it leaks the " +
		"creation time of whatever it identifies (in tokens, URLs, API parameters, logs, DB keys), and its " +
		"lexicographic sortability aids record enumeration. Completes the identifier-timestamp triad with " +
		"`uuid_decode` and `objectid_decode`.\n\n" +
		"Returns the timestamp (UTC + unix milliseconds) and the 80-bit randomness (hex). Input must be " +
		"exactly 26 Crockford-base32 characters (case-insensitive; no I/L/O/U) whose first character is " +
		"0-7 (a larger first character would overflow 128 bits — the spec's maximum ULID is " +
		"`7ZZZZZZZZZZZZZZZZZZZZZZZZZ`); anything else is rejected. No network, no device, transmits " +
		"nothing, so it is Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (identifier info-leak triage — sibling of uuid_decode / " +
		"objectid_decode). Wrap-vs-native: native — Crockford base-32 + a uint48 read, stdlib only, no new " +
		"go.mod dep. Anchored to python-ulid (and a hand-verified Crockford decode): " +
		"01ARZ3NDEKTSV4RRFFQ69G5FAV → 2016-07-30T23:54:10.259Z (1469922850259 ms).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"ulid":{"type":"string","description":"A ULID — 26 Crockford-base32 characters (case-insensitive)."}
		},
		"required":["ulid"]
	}`),
	Required:  []string{"ulid"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ulidDecodeHandler,
}

func ulidDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	in := strings.TrimSpace(str(p, "ulid"))
	if in == "" {
		return "", fmt.Errorf("ulid_decode: 'ulid' is required")
	}
	res, err := ulid.Decode(in)
	if err != nil {
		return "", fmt.Errorf("ulid_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
