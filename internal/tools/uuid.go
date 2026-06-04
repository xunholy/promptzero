// uuid.go — host-side UUID/GUID structure + info-leak decoder Spec, delegating
// to internal/uuidinfo.
//
// Wrap-vs-native: native — a UUID is 16 bytes with a fixed RFC 9562 bit layout;
// decoding is hex + field extraction + a gregorian->unix epoch shift. Surfaces
// the version/variant and, for v1/v6, the leaked host MAC + creation time
// (v7: a unix-ms timestamp). Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/uuidinfo"
)

func init() { //nolint:gochecknoinits
	Register(uuidDecodeSpec)
}

var uuidDecodeSpec = Spec{
	Name: "uuid_decode",
	Description: "Decode a UUID/GUID into its structure and — crucially for recon — any information it " +
		"leaks. UUIDs show up in tokens, API responses, email Message-IDs, filenames, database keys and " +
		"session identifiers, and some versions are not opaque:\n\n" +
		"- **version 1 / version 6** (time-based) embed the **generating host's MAC address** and the " +
		"**creation timestamp** — the classic `UUIDv1 leaks the MAC + time` info-disclosure finding. The " +
		"tool surfaces the timestamp (UTC), the node as a colon-MAC, and a `node_is_mac` assessment gated " +
		"on the IEEE multicast bit (a randomized node is never reported as a hardware address), plus the " +
		"clock sequence.\n" +
		"- **version 7** (unix-time-ordered, modern) embeds a millisecond **creation timestamp** (UTC) — " +
		"useful for time-ordering / enumerating records even without a MAC.\n" +
		"- **version 3 / 5** (name-based MD5 / SHA-1) and **version 4** (random) carry no recoverable " +
		"timestamp or node — reported as such, never guessed.\n\n" +
		"Also reports the **variant** (RFC 4122/9562, NCS, Microsoft GUID, future) and recognises the nil " +
		"and max UUIDs. Accepts any common form: 8-4-4-4-12 dashed, 32 bare hex, `urn:uuid:`-prefixed, or " +
		"`{brace}`-wrapped. A non-UUID string is rejected. No network, no device, transmits nothing, so it " +
		"is Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (identifier info-leak triage — companion to the data " +
		"decoders where UUIDs appear). Distinct from bluetooth_gatt_uuid_lookup (Bluetooth GATT service " +
		"UUIDs). Wrap-vs-native: native — RFC 9562 bit-layout extraction, stdlib only, no new go.mod dep. " +
		"Anchored to Python's reference `uuid` module: the v1 example → 2006-06-10T10:48:31.013993Z, node " +
		"00:11:24:44:be:1e; the v7 example → 2022-02-22T19:22:22Z.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"uuid":{"type":"string","description":"A UUID/GUID in any common form (dashed, bare hex, urn:uuid:, or {braced})."}
		},
		"required":["uuid"]
	}`),
	Required:  []string{"uuid"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   uuidDecodeHandler,
}

func uuidDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	in := strings.TrimSpace(str(p, "uuid"))
	if in == "" {
		return "", fmt.Errorf("uuid_decode: 'uuid' is required")
	}
	res, err := uuidinfo.Decode(in)
	if err != nil {
		return "", fmt.Errorf("uuid_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
