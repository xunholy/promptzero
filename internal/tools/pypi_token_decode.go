// pypi_token_decode.go — host-side PyPI API token decoder Spec, delegating to
// internal/pypitoken (which decodes the embedded macaroon via internal/macaroon).
//
// Wrap-vs-native: native — a PyPI token is "pypi-" + a base64 macaroon whose
// first-party caveats are JSON restrictions readable without the issuing secret;
// decode is internal/macaroon (stdlib varint) + encoding/json, no new go.mod
// dep. Turns a leaked token into its blast radius (account-wide vs scoped to a
// project / time window / user) for supply-chain leak triage. Offline; no
// network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/pypitoken"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(pypiTokenDecodeSpec)
}

var pypiTokenDecodeSpec = Spec{
	Name: "pypi_token_decode",
	Description: "Decode a **PyPI API token** (`pypi-…`) into the **blast radius it carries**. A leaked PyPI " +
		"upload token is a supply-chain primitive — it can publish a malicious release of a package — and the " +
		"single question incident response needs answered is *how much* it can do: any project the account " +
		"owns, or one scoped package until next week? A PyPI token is `pypi-` + a base64-serialized " +
		"**macaroon**, and the macaroon's first-party caveats are **JSON restrictions that remain readable " +
		"without the issuing secret**. This tool parses the macaroon and those caveats **offline — with no " +
		"call to PyPI** — and reports the token identifier and each restriction.\n\n" +
		"Recognises every documented PyPI caveat: the modern array forms (date window, project-names, " +
		"project-IDs, user-ID) and the three legacy object forms (noop / project-names / date); summarises " +
		"the result as one line — `account-wide` when nothing narrows it, or the specific projects / window / " +
		"user otherwise. **No confidently-wrong output**: it asserts the token's *structure and scope only* — " +
		"never that the token is live (that needs an API call) and never verifying the macaroon signature " +
		"(that needs the root key, which a captured token does not carry); an unrecognised caveat is returned " +
		"with its raw JSON, not guessed. No network, no device, transmits nothing — Low risk. Pairs with the " +
		"credential tooling (`secret_identify` / `github_token_decode` / `jwt_decode`).\n\n" +
		"Source: docs/catalog/gap-analysis.md (secret / credential forensics). Wrap-vs-native: native — " +
		"internal/macaroon (stdlib varint) + encoding/json, no new go.mod dep. Caveat tags and JSON shapes " +
		"taken from pypi/warehouse + the pypitoken library; decoder anchored to real pypitoken-generated " +
		"tokens and the pymacaroons cross-implementation binary vectors.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"token":{"type":"string","description":"The PyPI token (pypi-…)."}
		},
		"required":["token"]
	}`),
	Required:  []string{"token"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   pypiTokenDecodeHandler,
}

func pypiTokenDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	token := strings.TrimSpace(str(p, "token"))
	if token == "" {
		return "", fmt.Errorf("pypi_token_decode: 'token' is required")
	}
	res, err := pypitoken.Decode(token)
	if err != nil {
		return "", fmt.Errorf("pypi_token_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
