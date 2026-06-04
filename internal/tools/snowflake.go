// snowflake.go — host-side Snowflake-ID decoder Spec, delegating to
// internal/snowflake.
//
// Wrap-vs-native: native — a Snowflake is (id >> 22) + epoch plus a few low-bit
// masks. Surfaces the embedded creation timestamp (the OSINT value) under each
// known platform epoch. The integer/social-media counterpart to uuid_decode /
// objectid_decode / ulid_decode. Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/snowflake"
)

func init() { //nolint:gochecknoinits
	Register(snowflakeDecodeSpec)
}

var snowflakeDecodeSpec = Spec{
	Name: "snowflake_decode",
	Description: "Decode a Snowflake ID — the 64-bit identifier used by Discord, Twitter/X, Instagram and " +
		"others — into its embedded **creation timestamp**. A Snowflake packs a 41-bit millisecond " +
		"timestamp (from a platform-specific epoch) in its high bits, then machine/worker + sequence bits. " +
		"Decoding one is a standard OSINT technique: a Discord user / message / channel / guild ID, or a " +
		"tweet / X-post ID, reveals exactly **when the object was created** — account age, message timing, " +
		"enumeration. The integer / social-media counterpart to `uuid_decode` / `objectid_decode` / " +
		"`ulid_decode`.\n\n" +
		"A bare Snowflake does **not** identify its platform, and the same integer yields a different " +
		"timestamp under each platform's epoch — so the tool reports a **labelled candidate per platform** " +
		"(Discord, epoch 2015-01-01; Twitter/X, epoch 2010-11-04) and asserts none; pick the candidate " +
		"matching where you found the ID. Each candidate gives the UTC timestamp + unix milliseconds and " +
		"the low-bit fields (Discord: worker + process + increment; Twitter/X: machine id + sequence). " +
		"Pass `platform` (discord / twitter) to get just one. Instagram and other Snowflake variants use a " +
		"different bit layout and are deliberately not decoded (a wrong field split would be " +
		"confidently-wrong). A non-numeric / out-of-range input is rejected. No network, no device, " +
		"transmits nothing, so it is Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (identifier info-leak triage — the social-media-OSINT sibling " +
		"of uuid/objectid/ulid). Wrap-vs-native: native — a shift + add + masks, stdlib only, no new go.mod " +
		"dep. Anchored to Discord's documented example: 175928847299117063 → 2016-04-30T11:18:25.796Z.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"id":{"type":"string","description":"The Snowflake ID as a decimal string (use a string — 64-bit IDs exceed JSON number precision)."},
			"platform":{"type":"string","description":"Optional: discord or twitter/x. Omit to get all candidates."}
		},
		"required":["id"]
	}`),
	Required:  []string{"id"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   snowflakeDecodeHandler,
}

func snowflakeDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	id := strings.TrimSpace(str(p, "id"))
	if id == "" {
		return "", fmt.Errorf("snowflake_decode: 'id' is required")
	}
	res, err := snowflake.Decode(id, str(p, "platform"))
	if err != nil {
		return "", fmt.Errorf("snowflake_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
