// msgpack.go — host-side MessagePack dissector Spec, delegating to the
// internal/msgpack package for the walker proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/msgpack"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(msgpackDecodeSpec)
}

var msgpackDecodeSpec = Spec{
	Name: "msgpack_decode",
	Description: "Decode a MessagePack value (https://msgpack.org) to a structured tree — the compact " +
		"binary serialization used by Redis internals, msgpack-RPC, many web/API backends, mobile-sync " +
		"protocols, and game-server traffic. The binary-serialization sibling of cbor_decode: paste the hex " +
		"of a captured msgpack blob (a packet payload, a cache value, a stored token) and get the decoded " +
		"structure without writing a throwaway script. Decodes:\n\n" +
		"- **Scalars**: nil, true/false, positive/negative fixint, uint8/16/32/64, int8/16/32/64 " +
		"(sign-extended), float32, float64.\n" +
		"- **str** (fixstr / str8 / str16 / str32) rendered as UTF-8 text (a non-UTF-8 str payload is " +
		"surfaced as hex with a note, never an invalid string), and **bin** (bin8/16/32) rendered as hex.\n" +
		"- **array** (fixarray / array16 / array32) and **map** (fixmap / map16 / map32), recursively, " +
		"preserving key order and duplicate keys.\n" +
		"- **ext** (fixext1..16 / ext8/16/32): extension type byte + data hex; the Timestamp extension " +
		"(type -1) is flagged but surfaced raw (time decode deferred to avoid a confidently-wrong value).\n\n" +
		"Each node reports its wire `format` (e.g. `uint16`, `fixstr`, `array16`) so the exact encoding is " +
		"visible. Pure offline parser — a truncated or malformed blob is rejected with an error (never a " +
		"partial/guessed decode), the reserved 0xc1 tag is rejected, hostile huge length fields are bounded, " +
		"and any trailing bytes after the top-level value are surfaced as `trailing_bytes_hex` rather than " +
		"ignored. No network, no device, transmits nothing, so it is Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (binary-serialization decode space — the msgpack sibling of " +
		"cbor_decode / protobuf_decode). Wrap-vs-native: native — MessagePack is a fully public byte-tag " +
		"format; a recursive-descent walk over a byte cursor, no third-party dependency. Every format family " +
		"is gated byte-for-byte against the reference msgpack library's output.\n\n" +
		"Accepts ':' / '-' / '_' / whitespace separators and a leading '0x' prefix.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded MessagePack data. ':' / '-' / '_' / whitespace separators tolerated; '0x' prefix tolerated. Trailing bytes after the first complete value are surfaced, not rejected."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   msgpackDecodeHandler,
}

func msgpackDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("msgpack_decode: 'hex' is required")
	}
	res, err := msgpack.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("msgpack_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
