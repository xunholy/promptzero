// shadow_decode.go — host-side /etc/shadow credential-triage Spec, delegating to
// internal/shadow.
//
// Wrap-vs-native: native — a field split over the documented shadow(5) / crypt(5)
// formats; stdlib only, no new go.mod dep. /etc/shadow is the highest-value
// Linux post-exploitation artifact; this answers "which accounts are crackable,
// with which hashcat mode, and which have no password?" offline. Offline; no
// network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/shadow"
)

func init() { //nolint:gochecknoinits
	Register(shadowDecodeSpec)
}

var shadowDecodeSpec = Spec{
	Name: "shadow_decode",
	Description: "Triage a Linux **`/etc/shadow`** file — the **single highest-value Linux post-exploitation " +
		"artifact**: it holds every local account's password hash. This parses a looted shadow file **offline** " +
		"and, **per user**, classifies the password field: the **hashing scheme** (sha512crypt / sha256crypt / " +
		"md5crypt / bcrypt / yescrypt / descrypt / …), the matching **crack mode** (hashcat **`-m`** mode + John " +
		"format) to feed straight into the cracker, the account **status** (active / locked / no-password / " +
		"disabled), and the password-aging fields. It surfaces the two findings that matter most: accounts with " +
		"a **crackable hash** and accounts with **NO password** at all (plus per-file counts).\n\n" +
		"**No confidently-wrong output**: the password field is classified only by its documented crypt id " +
		"(`$6$`, `$2y$`, …) or shape (13-char descrypt, status markers `*` / `!` / empty); an unrecognised " +
		"field is reported scheme **unknown** with no crack mode, never guessed; a hashcat mode is emitted only " +
		"for schemes hashcat supports **natively** (yescrypt / gost-yescrypt are reported **John-only**). A " +
		"**locked** account whose hash is still present (`!$6$…`) is flagged **locked _and_ crackable** — the " +
		"lock only disables login, the hash is still recoverable. A passwd-style `x` placeholder is reported " +
		"**shadowed**, not a hash; input with no shadow-shaped line is rejected. No network, no device, " +
		"transmits nothing — Low risk. Pairs with `hash_identify` / `sha512crypt` / `bcrypt` (the per-hash " +
		"crackers).\n\n" +
		"Source: docs/catalog/gap-analysis.md (credential forensics). Wrap-vs-native: native — a field split " +
		"over shadow(5) / crypt(5), no new go.mod dep; crack modes per the hashcat / John format tables.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"shadow":{"type":"string","description":"The /etc/shadow file contents (user:hash:aging… lines)."}
		},
		"required":["shadow"]
	}`),
	Required:  []string{"shadow"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   shadowDecodeHandler,
}

func shadowDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	in := strings.TrimSpace(str(p, "shadow"))
	if in == "" {
		return "", fmt.Errorf("shadow_decode: 'shadow' is required")
	}
	res, err := shadow.Decode(in)
	if err != nil {
		return "", fmt.Errorf("shadow_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
