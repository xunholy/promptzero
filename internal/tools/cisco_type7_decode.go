// cisco_type7_decode.go — host-side Cisco IOS type-7 password decoder Spec,
// delegating to internal/ciscopw.
//
// Wrap-vs-native: native — Cisco type 7 is reversible obfuscation (a fixed-key
// XOR with a leading salt index), not a hash; the plaintext is recovered
// directly. Ubiquitous in router/switch config loot from
// `service password-encryption`. Complements hash_identify's Cisco type 8/9
// detection (those are real KDFs to crack; type 7 is just decoded). Offline.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ciscopw"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ciscoType7DecodeSpec)
}

var ciscoType7DecodeSpec = Spec{
	Name: "cisco_type7_decode",
	Description: "Decode a Cisco IOS type-7 password to plaintext — the weak, reversible obfuscation " +
		"produced by `service password-encryption`, ubiquitous in router/switch configuration loot. " +
		"Unlike a hash, type 7 is fully reversible (a fixed-key XOR with a leading salt index), so this " +
		"recovers the password directly — no cracking. It complements hash_identify, which flags Cisco " +
		"type 8 ($8$, PBKDF2) and type 9 ($9$, scrypt) as real KDFs that must be cracked; type 7 is the " +
		"one you simply decode.\n\n" +
		"Field: **value** — the type-7 string as it appears in the config (e.g. `password 7 02050D480809`; " +
		"pass just the hex part, 02050D480809). The 2-digit salt and hex byte pairs are validated; a " +
		"malformed value is rejected, not mis-decoded. Offline transform — reads a string, transmits " +
		"nothing, so it is Low risk. The key + algorithm are pinned in-tree against published vectors " +
		"(02050D480809 and 060506324F41 both decode to 'cisco'). Wrap-vs-native: native — XOR over a " +
		"published 53-byte key.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"value":{"type":"string","description":"Cisco type-7 string (the hex part, e.g. 02050D480809). A leading 'password 7 ' / '7 ' is stripped."}
		},
		"required":["value"]
	}`),
	Required:  []string{"value"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ciscoType7DecodeHandler,
}

func ciscoType7DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	v := strings.TrimSpace(str(p, "value"))
	if v == "" {
		return "", fmt.Errorf("cisco_type7_decode: 'value' is required")
	}
	// Tolerate a copied config fragment: strip a leading "password 7 " / "7 ".
	v = strings.TrimSpace(v)
	for _, pfx := range []string{"password 7 ", "secret 7 ", "7 "} {
		if strings.HasPrefix(strings.ToLower(v), pfx) {
			v = strings.TrimSpace(v[len(pfx):])
			break
		}
	}
	plain, err := ciscopw.DecodeType7(v)
	if err != nil {
		return "", fmt.Errorf("cisco_type7_decode: %w", err)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"encoded":   v,
		"plaintext": plain,
	}, "", "  ")
	return string(out), nil
}
