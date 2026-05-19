// protobuf.go — host-side Protobuf wire-format dissector
// Spec, delegating to the internal/protobufdecode package
// for the walker proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/protobufdecode"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(protobufDecodeSpec)
}

var protobufDecodeSpec = Spec{
	Name: "protobuf_decode",
	Description: "Decode raw Protocol Buffers wire-format bytes without needing the .proto " +
		"schema — the equivalent of `protoc --decode_raw`. gRPC, Google APIs, mobile apps, " +
		"modern microservices, and Faultier's own command framing all carry protobuf bytes; " +
		"operators routinely have hex blobs of unknown messages and want the field-number " +
		"/ wire-type / value breakdown without hunting down the right .proto file. Decodes:\n\n" +
		"- **Tag decoding**: field_number + wire_type extracted from the leading varint of " +
		"each field.\n" +
		"- **6 wire types**:\n" +
		"  - **0 VARINT** — surfaced as raw uint64, zigzag-decoded int64 (for sint32 / " +
		"sint64 schema fields), and bool interpretation (0/1).\n" +
		"  - **1 I64** — raw uint64 + float64 interpretation (for double / fixed64 / " +
		"sfixed64).\n" +
		"  - **2 LEN** — length-prefixed bytes with the operator-friendly heuristic: try " +
		"to decode as a nested message; if that succeeds and consumes all bytes, use the " +
		"nested view; otherwise fall back to UTF-8 string (if all bytes are printable) or " +
		"raw hex.\n" +
		"  - **3 SGROUP** / **4 EGROUP** — deprecated; named but no body decode.\n" +
		"  - **5 I32** — raw uint32 + float32 interpretation (for float / fixed32 / " +
		"sfixed32).\n" +
		"- **Varint reader** with continuation-bit handling and a max-10-byte guard " +
		"(uint64 max).\n" +
		"- **Recursive nested-message detection**: LEN fields whose body is a valid " +
		"protobuf message are decoded depth-first; the entire field tree is surfaced as a " +
		"nested JSON structure.\n\n" +
		"Pure offline parser — operators paste a hex blob from `grpcurl -d` output, a " +
		"Wireshark gRPC dissector, an Android app traffic capture, an mitmproxy export, " +
		"or any protobuf-emitting tool, and inspect every nested message without needing " +
		"the .proto file. Pairs with jwt_decode + cbor_decode for the modern API-encoding " +
		"decode stack: JSON for human-readable web APIs, JWT/JOSE for cleartext auth " +
		"tokens, CBOR/COSE for binary IoT tokens, Protobuf/gRPC for binary RPC traffic.\n\n" +
		"Out of scope (deferred to future iterations): schema-aware decode (field names + " +
		"strongly-typed values require the .proto; this Spec surfaces field numbers + " +
		"wire types + best-effort value interpretation); packed repeated field detection " +
		"(without schema knowledge, a packed repeated LEN body falls through to the " +
		"nested-message / string / hex heuristics); gRPC HTTP/2 message framing (the " +
		"5-byte compression-flag + 4-byte length prefix is the caller's responsibility " +
		"to strip); proto3 default-value semantics (this is a wire-level decoder, not a " +
		"semantic one).\n\n" +
		"Source: docs/catalog/gap-analysis.md (modern API-encoding decode space). " +
		"Wrap-vs-native: native — the Protobuf wire format is fully public, every field " +
		"is a tag varint + wire-type-specific value, dispatch is a switch.\n\n" +
		"Accepts ':' / '-' / '_' / whitespace separators and a leading '0x' prefix.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded Protobuf wire-format bytes. Strip the gRPC HTTP/2 framing (1-byte compression flag + 4-byte big-endian length) before passing in. Trailing bytes after the last field are rejected. ':' / '-' / '_' / whitespace separators tolerated; '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   protobufDecodeHandler,
}

func protobufDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("protobuf_decode: 'hex' is required")
	}
	res, err := protobufdecode.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("protobuf_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
