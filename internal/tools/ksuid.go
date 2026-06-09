// ksuid.go — host-side KSUID decoder Spec, delegating to internal/ksuid.
//
// Wrap-vs-native: native — a KSUID is a base62 → 160-bit conversion then a
// 4-byte big-endian read + an epoch add. Surfaces the embedded creation
// timestamp (the OSINT / forensic value). The K-Sortable-ID counterpart to
// uuid_decode / objectid_decode / ulid_decode / snowflake_decode. Offline; no
// network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ksuid"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ksuidDecodeSpec)
}

var ksuidDecodeSpec = Spec{
	Name: "ksuid_decode",
	Description: "Decode a KSUID (K-Sortable Unique IDentifier — the segmentio/ksuid format) into its " +
		"embedded **creation timestamp** and random payload. A KSUID is a 27-character base62 string " +
		"encoding 20 bytes: a 4-byte big-endian timestamp (seconds since a custom 2014 epoch) + 16 bytes " +
		"of randomness. Like a UUIDv1/v7, a MongoDB ObjectId, a ULID, or a Snowflake, a KSUID is **not " +
		"opaque** — its leading bytes leak the creation time of whatever it identifies (request IDs, " +
		"tokens, database keys, URLs, logs), and its lexicographic sortability aids record enumeration. " +
		"Widely used by Go backends (Segment and others). Completes the identifier info-leak family with " +
		"`uuid_decode` / `objectid_decode` / `ulid_decode` / `snowflake_decode`.\n\n" +
		"Returns the UTC timestamp + unix seconds, the raw 32-bit timestamp field, and the 16-byte " +
		"payload (hex). Unlike a Snowflake, a KSUID is **unambiguous** (one published format, one epoch), " +
		"so the timestamp is a single asserted answer. Input must be exactly 27 base62 characters whose " +
		"160-bit value fits in 20 bytes; a wrong length, an out-of-alphabet character, or an out-of-range " +
		"value is rejected rather than mis-decoded. No network, no device, transmits nothing — Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (identifier info-leak triage — the K-Sortable sibling of " +
		"uuid/objectid/ulid/snowflake). Wrap-vs-native: native — base62 + a big-endian read + an epoch " +
		"add, stdlib only, no new go.mod dep. Anchored to segmentio/ksuid's documented example: " +
		"0ujtsYcgvSTl8PAuAdqWYSMnLOv → 2017-10-10T04:00:47Z, payload B5A1CD34B5F99D1154FB6853345C9735.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"ksuid":{"type":"string","description":"The KSUID as its 27-character base62 string (e.g. 0ujtsYcgvSTl8PAuAdqWYSMnLOv)."}
		},
		"required":["ksuid"]
	}`),
	Required:  []string{"ksuid"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ksuidDecodeHandler,
}

func ksuidDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	id := strings.TrimSpace(str(p, "ksuid"))
	if id == "" {
		return "", fmt.Errorf("ksuid_decode: 'ksuid' is required")
	}
	res, err := ksuid.Decode(id)
	if err != nil {
		return "", fmt.Errorf("ksuid_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
