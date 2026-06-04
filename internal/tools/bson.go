// bson.go — host-side BSON document dissector Spec, delegating to the
// internal/bson package for the walker proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/bson"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(bsonDecodeSpec)
}

var bsonDecodeSpec = Spec{
	Name: "bson_decode",
	Description: "Decode a BSON document (bsonspec.org) to a structured tree — the binary serialization " +
		"MongoDB stores and that `mongodump` writes to `.bson` files. It is the document-format complement " +
		"to mongodb_decode (which dissects the MongoDB wire protocol and only shallowly extracts a command " +
		"name + a few argument fields): this **fully, recursively decodes a standalone BSON document** — " +
		"every element type, nested documents and arrays — the way cbor_decode / msgpack_decode handle " +
		"their formats. Paste the hex of a `.bson` record (mongodump loot, a stored document, a captured " +
		"payload) and get the full structure without a MongoDB driver. Decodes:\n\n" +
		"- **Scalars**: double, int32, int64, bool, null, UTC datetime (→ RFC 3339 + unix ms), and " +
		"timestamp (increment + seconds).\n" +
		"- **string** (UTF-8, length-validated), **ObjectId** (12-byte → hex), and **binary** (length + " +
		"subtype byte → subtype name: generic / function / UUID / MD5 / encrypted-CSFLE / compressed / " +
		"user-defined + data hex).\n" +
		"- **embedded document** and **array**, recursively, preserving field order.\n" +
		"- **regex** (pattern + options), **JavaScript** code (and code-with-scope), the deprecated " +
		"**symbol** / **DBPointer** / **undefined**, **min/max key**, and **Decimal128** (surfaced as raw " +
		"16 bytes — the IEEE 754-2008 decimal-string decode is deferred to avoid a confidently-wrong " +
		"value).\n\n" +
		"Each value reports its BSON `type`. Pure offline parser — a truncated or malformed document is " +
		"rejected with an error (never a partial/guessed decode), length fields are bounds-checked, nesting " +
		"is depth-capped, and any trailing bytes after the document are surfaced as `trailing_bytes_hex`. " +
		"No network, no device, transmits nothing, so it is Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (binary-serialization decode space — the BSON sibling of " +
		"cbor_decode / msgpack_decode / protobuf_decode; complements mongodb_decode's wire-protocol view). " +
		"Wrap-vs-native: native — BSON is a fully public little-endian length-prefixed format; a " +
		"recursive-descent walk over a byte cursor, no third-party dependency. Every element type is gated " +
		"byte-for-byte against the reference PyMongo `bson` library's output.\n\n" +
		"Accepts ':' / '-' / '_' / whitespace separators and a leading '0x' prefix.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded BSON document (e.g. a mongodump .bson record). ':' / '-' / '_' / whitespace separators tolerated; '0x' prefix tolerated. Trailing bytes after the document are surfaced, not rejected."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   bsonDecodeHandler,
}

func bsonDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("bson_decode: 'hex' is required")
	}
	res, err := bson.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("bson_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
