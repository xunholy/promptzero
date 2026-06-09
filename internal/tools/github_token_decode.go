// github_token_decode.go — host-side GitHub token identifier/validator Spec,
// delegating to internal/githubtoken.
//
// Wrap-vs-native: native — a GitHub token is a prefix + Base62 entropy + a
// 6-char Base62 CRC32 checksum; validation is a stdlib hash/crc32 + a base
// conversion. Confirms a leaked token is genuine/well-formed offline (no GitHub
// API call) — secret-scanning / leak triage. Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/githubtoken"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(githubTokenDecodeSpec)
}

var githubTokenDecodeSpec = Spec{
	Name: "github_token_decode",
	Description: "Identify and **validate a GitHub authentication token** — the prefixed, checksummed formats " +
		"GitHub adopted in April 2021 (`ghp_` PAT classic, `gho_` OAuth, `ghu_` user-to-server, `ghs_` " +
		"server-to-server, `ghr_` refresh, `github_pat_` fine-grained). A leaked GitHub token is the single " +
		"**most common secret** found in repos, dumps, logs, and CI configs, and the format carries a " +
		"**CRC32 checksum** that confirms **offline — with no API call to GitHub** — whether a captured " +
		"string is a **genuine, well-formed token** vs. a redaction, a typo, or a fabricated lookalike. That " +
		"is a positive secret-scanning detection from the token alone.\n\n" +
		"For the five classic types it reports the token kind and the **checksum validity**; for a " +
		"fine-grained `github_pat_` it identifies the prefix but does not assert a checksum (its internal " +
		"structure differs and is not vector-verified here). **No confidently-wrong output**: a token whose " +
		"checksum does not validate is reported as such (not asserted genuine); an unrecognised prefix or a " +
		"non-Base62 body is rejected. No network, no device, transmits nothing — Low risk. Pairs with the " +
		"credential tooling (`aws_key_decode` / `jwt_decode` / `hash_identify`).\n\n" +
		"Source: docs/catalog/gap-analysis.md (secret / credential forensics). Wrap-vs-native: native — " +
		"hash/crc32 + Base62, stdlib only, no new go.mod dep. Anchored to the canonical example (entropy " +
		"zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ → CRC32 equals the Base62-decoded checksum 0mLq17).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"token":{"type":"string","description":"The GitHub token (e.g. ghp_… / gho_… / github_pat_…)."}
		},
		"required":["token"]
	}`),
	Required:  []string{"token"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   githubTokenDecodeHandler,
}

func githubTokenDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	token := strings.TrimSpace(str(p, "token"))
	if token == "" {
		return "", fmt.Errorf("github_token_decode: 'token' is required")
	}
	res, err := githubtoken.Decode(token)
	if err != nil {
		return "", fmt.Errorf("github_token_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
