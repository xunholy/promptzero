// kdbx_decode.go — host-side KeePass database header decoder Spec, delegating to
// internal/kdbx.
//
// Wrap-vs-native: native — encoding/binary over the documented KDBX outer-header
// format + KDBX4 VariantDictionary; no new go.mod dep. Turns a captured .kdbx
// into its crack-triage facts (version / cipher / KDF + cost) so an operator
// knows whether it is worth attacking and which hashcat mode to use. Offline; no
// network or device.

package tools

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/kdbx"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(kdbxDecodeSpec)
}

var kdbxDecodeSpec = Spec{
	Name: "kdbx_decode",
	Description: "Decode the header of a **KeePass database** (`.kdbx`) into the crack-triage facts that decide " +
		"whether it is worth attacking. A `.kdbx` is one of the highest-value loot artifacts, and its " +
		"crackability hinges almost entirely on the **key-derivation function**: a legacy **AES-KDF** database " +
		"with a low transform-round count is tractable, whereas a modern **KDBX4** file using memory-hard " +
		"**Argon2** (e.g. 64 MiB × 14 iterations) throttles GPU cracking by orders of magnitude. This decodes " +
		"the outer header **offline** and reports the format version, the encryption **cipher** (AES-256 / " +
		"ChaCha20 / Twofish), the **KDF and its cost parameters** (AES-KDF transform rounds, or Argon2 " +
		"iterations / memory / parallelism), and names the **hashcat mode** (13400) so the result feeds the " +
		"project's hash/cracking tooling.\n\n" +
		"Provide the `.kdbx` file **base64-encoded** (or hex). **No confidently-wrong output**: the magic " +
		"signature is validated, an unknown cipher/KDF UUID is surfaced as **raw hex** rather than guessed, " +
		"and malformed input is rejected. It parses the **outer header only** — it does **not** derive the " +
		"master key, decrypt the database, or emit the `keepass2john` `$keepass$` hash (that needs the " +
		"encrypted payload and is out of scope); it surfaces the parameters that determine crack cost, never a " +
		"claim that the database is crackable. No network, no device, transmits nothing — Low risk. Pairs with " +
		"`hash_identify` and the hashcat tooling.\n\n" +
		"Source: docs/catalog/gap-analysis.md (credential forensics / crack triage). Wrap-vs-native: native — " +
		"encoding/binary over the documented KDBX header + KDBX4 VariantDictionary, no new go.mod dep; anchored " +
		"to a real pykeepass-generated KDBX4 file.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"data":{"type":"string","description":"The .kdbx file contents, base64-encoded (or hex)."}
		},
		"required":["data"]
	}`),
	Required:  []string{"data"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   kdbxDecodeHandler,
}

func kdbxDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	in := strings.TrimSpace(str(p, "data"))
	if in == "" {
		return "", fmt.Errorf("kdbx_decode: 'data' is required")
	}
	raw, err := decodeBinaryInput(in)
	if err != nil {
		return "", fmt.Errorf("kdbx_decode: %w", err)
	}
	res, err := kdbx.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("kdbx_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}

// decodeBinaryInput accepts a binary blob as base64 (std/url, padded or not) or
// hex, returning the raw bytes.
func decodeBinaryInput(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	compact := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
	// Hex if it is all hex digits and even length.
	if len(compact)%2 == 0 && isHexString(compact) {
		if b, err := hex.DecodeString(compact); err == nil {
			return b, nil
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(compact); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("input is neither valid base64 nor hex")
}

// isHexString reports whether s is non-empty and all hex digits.
func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
