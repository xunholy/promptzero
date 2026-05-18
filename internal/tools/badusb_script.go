// badusb_script.go — host-side DuckyScript parser/validator
// Spec, delegating to the internal/badusb package for the
// parser proper.
//
// Wrap-vs-native judgement: DuckyScript v1 is a public language.
// The parser is a line-based lexer + command-dispatch table.
// Wrapping a FAP for this would add an SD-card install step +
// a firmware-fork dependency for a pure parser. Native delivers
// pre-deployment syntax checking — operators paste a BadUSB
// script and get line-numbered diagnostics for unknown commands,
// invalid argument types, and an estimated total execution time.
//
// Pairs with the existing badusb_validate (which scans for
// malicious patterns via internal/validator) — together they
// cover the syntactic + semantic validation surface for
// operator-authored BadUSB payloads.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/badusb"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(badusbScriptParseSpec)
}

var badusbScriptParseSpec = Spec{
	Name: "badusb_script_parse",
	Description: "Parse a DuckyScript / BadUSB payload script into a structured line-by-line " +
		"view with per-line syntactic validation. For each non-blank, non-comment line, " +
		"identifies the command and validates its arguments:\n\n" +
		"- **DELAY / DEFAULTDELAY**: must have a non-negative integer (milliseconds).\n" +
		"- **STRING / STRINGLN**: must have text to type.\n" +
		"- **REPEAT**: must have a positive integer.\n" +
		"- **Single-key commands** (ENTER / TAB / ESC / BACKSPACE / SPACE / DELETE / F1-F12 / " +
		"navigation keys / lock keys / etc.): must have no arguments.\n" +
		"- **Modifier commands** (GUI / WINDOWS / META / CTRL / ALT / SHIFT / OPTION / " +
		"COMMAND / compound combos like CTRL-ALT-DEL): can stand alone or take a single-key " +
		"argument (e.g. `GUI r` for Win+R).\n" +
		"- **REM**: comment line, content preserved.\n" +
		"- Unknown commands flagged with an Issue.\n\n" +
		"Returns line-numbered diagnostics + total estimated execution time " +
		"(DELAY + DEFAULTDELAY accumulated between commands + 1 ms per STRING character).\n\n" +
		"Pairs with the existing badusb_validate (which scans for malicious patterns) — this " +
		"Spec catches syntactic mistakes before deployment.\n\n" +
		"Pure offline parser — no Flipper required. Source: docs/catalog/gap-analysis.md " +
		"(BadUSB decode space). Wrap-vs-native: native — DuckyScript v1 is a public language, " +
		"the walker is a line-based lexer with a ~50-command dispatch table.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"script":{"type":"string","description":"DuckyScript / BadUSB source. Lines are newline-separated commands; '\\r\\n' Windows line endings tolerated."}
		},
		"required":["script"]
	}`),
	Required:  []string{"script"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   badusbScriptParseHandler,
}

func badusbScriptParseHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	src := str(p, "script")
	if strings.TrimSpace(src) == "" {
		return "", fmt.Errorf("badusb_script_parse: 'script' is required")
	}
	res := badusb.Parse(src)
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
