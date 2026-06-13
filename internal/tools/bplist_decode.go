// bplist_decode.go — host-side Apple binary-property-list decoder Spec,
// delegating to internal/bplist.
//
// Wrap-vs-native: native — a recursive-descent walk of the documented
// CFBinaryPlist layout, stdlib only, no new go.mod dep. Binary plists are
// pervasive in iOS/macOS loot (preferences, .mobileconfig, NSKeyedArchiver);
// this turns one into a readable tree. Offline; no network or device.

package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/bplist"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(bplistDecodeSpec)
}

var bplistDecodeSpec = Spec{
	Name: "bplist_decode",
	Description: "Decode an **Apple binary property list** (`bplist00`) into a readable tree — the **bplist " +
		"sibling** of `cbor_decode` / `msgpack_decode` / `bson_decode` for the **iOS / macOS** domain. Binary " +
		"plists are pervasive in Apple loot: app **preferences** (`Library/Preferences/*.plist`), " +
		"**`.mobileconfig`** configuration profiles, **`NSKeyedArchiver`** blobs, and many forensic artifacts " +
		"are stored in this binary format (not the XML variant), so an operator pulling files off a device or " +
		"backup gets an opaque blob. This recursively decodes every type — dict / array / set, string " +
		"(ASCII + UTF-16), int (1/2/4/8/16-byte), real, **bool**, **date** (→ RFC 3339, the 2001 epoch), " +
		"**data** (→ hex), and the **`NSKeyedArchiver` UID** (→ `{\"$uid\": n}`).\n\n" +
		"**No confidently-wrong output**: recognised only by its `bplist00` magic; the object / offset tables " +
		"and the trailer are **bounds-checked**; an out-of-range reference or a malformed marker is an error, " +
		"never a guess; recursion is **depth- and node-budget-capped** against a hostile self-referential " +
		"plist. No network, no device, transmits nothing — Low risk. Pairs with the other serialization " +
		"decoders.\n\n" +
		"Provide the plist **base64-encoded** (it is binary). Source: docs/catalog/gap-analysis.md (Apple / " +
		"mobile forensics). Wrap-vs-native: native — a recursive-descent CFBinaryPlist walk, no new go.mod dep; " +
		"anchored byte-for-byte to Python's stdlib `plistlib`. Only the v0 (`bplist00`) format is handled.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"bplist_base64":{"type":"string","description":"The Apple binary property list (bplist00), base64-encoded (it is binary)."}
		},
		"required":["bplist_base64"]
	}`),
	Required:  []string{"bplist_base64"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   bplistDecodeHandler,
}

func bplistDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	b64 := strings.TrimSpace(str(p, "bplist_base64"))
	if b64 == "" {
		return "", fmt.Errorf("bplist_decode: 'bplist_base64' is required")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("bplist_decode: 'bplist_base64' is not valid base64: %w", err)
	}
	res, err := bplist.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("bplist_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
