// nskeyedarchiver_decode.go — host-side NSKeyedArchiver resolver Spec,
// delegating to internal/nskeyed.
//
// Wrap-vs-native: native — a graph walk over the bplist tree (composes
// internal/bplist), stdlib only, no new go.mod dep. NSKeyedArchiver is the
// dominant iOS/macOS object serialization; this resolves the $objects/UID graph
// into the actual object, the resolution layer on top of bplist_decode.
// Offline; no network or device.

package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/nskeyed"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(nskeyedArchiverDecodeSpec)
}

var nskeyedArchiverDecodeSpec = Spec{
	Name: "nskeyedarchiver_decode",
	Description: "Resolve an **NSKeyedArchiver** plist into the **logical object** it serialises — the resolution " +
		"layer on top of `bplist_decode`. **NSKeyedArchiver** is the dominant serialization for complex " +
		"Objective-C / Swift objects on **iOS / macOS**: NSUserDefaults values, app state, document formats, " +
		"and countless forensic artifacts are stored as a keyed archive (itself a binary plist). The raw plist " +
		"is nearly unreadable — a flat **`$objects`** array of fragments wired together by integer **UID** " +
		"references, with NS-class containers (NSDictionary / NSArray / NSData / NSDate …) encoded " +
		"structurally. This walks the **`$archiver` / `$objects` / `$top`** graph and reconstructs the actual " +
		"nested object: NSDictionary → object, NSArray/NSSet → list, NSString → string, **NSData → hex**, " +
		"**NSDate → RFC 3339** (the 2001 epoch), `$null` → null.\n\n" +
		"**No confidently-wrong output**: it composes the bounds-checked bplist decoder; the top-level dict must " +
		"declare `\"$archiver\": \"NSKeyedArchiver\"`; a UID outside `$objects`, a missing `$class`, or a " +
		"reference **cycle** is surfaced as a labelled marker (`<uid out of range>` / `<cycle>`), never a wrong " +
		"guess; a node budget bounds a hostile fan-out; an **unmapped class** is surfaced with its `$class` " +
		"name + resolved fields rather than dropped. No network, no device, transmits nothing — Low risk. " +
		"Pairs with `bplist_decode` (the raw-structure view).\n\n" +
		"Provide the archive **base64-encoded** (it is a binary plist). Source: docs/catalog/gap-analysis.md " +
		"(Apple / mobile forensics). Wrap-vs-native: native — a graph walk over the bplist tree, no new go.mod " +
		"dep; anchored to real bpylist2-produced archives.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"archive_base64":{"type":"string","description":"The NSKeyedArchiver binary plist, base64-encoded (it is binary)."}
		},
		"required":["archive_base64"]
	}`),
	Required:  []string{"archive_base64"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   nskeyedArchiverDecodeHandler,
}

func nskeyedArchiverDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	b64 := strings.TrimSpace(str(p, "archive_base64"))
	if b64 == "" {
		return "", fmt.Errorf("nskeyedarchiver_decode: 'archive_base64' is required")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("nskeyedarchiver_decode: 'archive_base64' is not valid base64: %w", err)
	}
	res, err := nskeyed.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("nskeyedarchiver_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
