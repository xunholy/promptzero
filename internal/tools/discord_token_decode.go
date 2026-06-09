// discord_token_decode.go — host-side Discord token decoder Spec, delegating to
// internal/discordtoken.
//
// Wrap-vs-native: native — a Discord token is base64url(userID).base64url(mint).
// HMAC; the account decode is a Base64 decode + the in-tree snowflake decoder.
// Identifies the owning account + its creation time from a leaked token offline
// (no Discord API call) — infostealer / IR forensics. Offline; no network or
// device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/discordtoken"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(discordTokenDecodeSpec)
}

var discordTokenDecodeSpec = Spec{
	Name: "discord_token_decode",
	Description: "Decode a **Discord authentication token** into the account it belongs to. A Discord token is " +
		"the **single most common credential in infostealer / RAT logs** (RedLine, Raccoon, et al. harvest " +
		"them en masse), and a captured token is **not opaque**: its first segment is the account's user ID, " +
		"from which the **account creation time** falls straight out of the Discord snowflake. Identifying " +
		"the owning account + its age — **offline, with no API call to Discord, no token use, no " +
		"detection** — is standard IR / OSINT triage.\n\n" +
		"Decodes user / bot tokens to the **user ID** and **account creation time**. **No confidently-wrong " +
		"output**: the token mint timestamp (segment 2) is surfaced **raw and uninterpreted** — Discord's " +
		"epoch offset for it is documented as uncertain, so converting it to a date would be a guess; the " +
		"HMAC (segment 3) is opaque; an `mfa.`-prefixed token carries no embedded user ID and is identified " +
		"as such; a string whose first segment does not decode to ASCII digits (e.g. a JWT) is rejected. No " +
		"network, no device, transmits nothing — Low risk. Pairs with `secret_identify` and `snowflake_decode`.\n\n" +
		"Source: docs/catalog/gap-analysis.md (credential forensics — the dominant infostealer artifact). " +
		"Wrap-vs-native: native — Base64 decode + the in-tree snowflake decoder, stdlib + an existing " +
		"package, no new go.mod dep. The account decode chains through snowflake_decode, anchored to " +
		"Discord's documented example (175928847299117063 → 2016-04-30T11:18:25.796Z).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"token":{"type":"string","description":"The Discord token (base64url(userID).base64url(mint).HMAC, or an mfa.… token)."}
		},
		"required":["token"]
	}`),
	Required:  []string{"token"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   discordTokenDecodeHandler,
}

func discordTokenDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	token := strings.TrimSpace(str(p, "token"))
	if token == "" {
		return "", fmt.Errorf("discord_token_decode: 'token' is required")
	}
	res, err := discordtoken.Decode(token)
	if err != nil {
		return "", fmt.Errorf("discord_token_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
