// grpcdecode.go — host-side gRPC Length-Prefixed Message decoder Spec.
// Wraps the internal/grpcdecode walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/grpcdecode"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(grpcDecodeSpec)
}

var grpcDecodeSpec = Spec{
	Name: "grpc_decode",
	Description: "Decode a gRPC Length-Prefixed Message payload per the gRPC " +
		"wire-protocol specification. gRPC uses HTTP/2 as transport; " +
		"this tool focuses on the gRPC-specific framing layer that sits " +
		"inside HTTP/2 DATA frames. Common ports: TCP/443 (TLS, most " +
		"cloud services), TCP/80 (cleartext h2c, internal meshes), " +
		"TCP/50051 (canonical insecure dev default). Compatible with " +
		"Google gRPC, gRPC-Go, gRPC-Java, grpc-gateway, Envoy, Istio, " +
		"Linkerd, Connect-RPC, and gRPC-Web variants.\n\n" +
		"Security relevance: Default gRPC has NO authentication " +
		"(insecure.NewCredentials()); many internal microservice meshes " +
		"run without TLS or auth. gRPC reflection service " +
		"(grpc.reflection.v1alpha) exposes the full service/method " +
		"schema when enabled — canonical pentest recon. Method paths " +
		"(/package.Service/Method) leak internal API structure as " +
		"cleartext HTTP/2 headers. Protobuf messages are binary but " +
		"NOT encrypted — field values are visible with schema; field " +
		"numbers + wire types are always visible without schema. " +
		"gRPC status codes (grpc-status trailer) distinguish OK from " +
		"authentication/authorization failures. gRPC-Web (HTTP/1.1 " +
		"variant) sometimes exposed publicly without auth.\n\n" +
		"gRPC Length-Prefixed Message format (5-byte header):\n" +
		"- compressed_flag (1 byte): 0=not compressed, 1=compressed\n" +
		"- message_length (4 BE): byte count of following protobuf\n" +
		"- message_bytes[message_length]: serialized protobuf payload\n\n" +
		"Protobuf wire format (best-effort surface scan):\n" +
		"Each field tag is a varint: (field_number << 3) | wire_type. " +
		"wire_type 0=varint, 1=64-bit, 2=length-delimited, 5=32-bit. " +
		"Walks first few fields per message; surfaces field_number + " +
		"wire_type + wire_type_name without decoding field values.\n\n" +
		"gRPC status codes (grpc-status header/trailer):\n" +
		"0=OK, 1=CANCELLED, 2=UNKNOWN, 3=INVALID_ARGUMENT, " +
		"4=DEADLINE_EXCEEDED, 5=NOT_FOUND, 6=ALREADY_EXISTS, " +
		"7=PERMISSION_DENIED, 8=RESOURCE_EXHAUSTED, " +
		"9=FAILED_PRECONDITION, 10=ABORTED, 11=OUT_OF_RANGE, " +
		"12=UNIMPLEMENTED, 13=INTERNAL, 14=UNAVAILABLE, " +
		"15=DATA_LOSS, 16=UNAUTHENTICATED.\n\n" +
		"Decodes:\n" +
		"- gRPC Length-Prefixed Message 5-byte header (compressed_flag " +
		"+ message_length)\n" +
		"- Multiple concatenated messages (streaming gRPC)\n" +
		"- Best-effort protobuf field count + first field numbers and " +
		"wire types (without .proto schema)\n" +
		"- total_bytes + message_count\n\n" +
		"Pure offline parser — paste the HTTP/2 DATA frame payload hex " +
		"(the gRPC framing bytes, not the full HTTP/2 frame) from " +
		"tcpdump / Wireshark gRPC dissector and get per-message " +
		"breakdown.\n\n" +
		"Out of scope: HTTP/2 frame parsing (use http2_frame_decode); " +
		"HPACK header decompression (use hpack_decode); full protobuf " +
		"value decoding (use protobuf_decode); gzip/deflate " +
		"decompression of compressed messages; gRPC-Web envelope " +
		"(different framing byte).\n\n" +
		"Source: gap analysis (microservice RPC backbone — pairs with " +
		"http2_frame_decode + hpack_decode + protobuf_decode for the " +
		"complete gRPC pentest stack; gRPC reflection enumeration + " +
		"insecure channel detection + field-number surface mapping " +
		"without schema).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"gRPC Length-Prefixed Message payload bytes as hex (the HTTP/2 DATA frame payload — the gRPC framing bytes, not the full HTTP/2 frame). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated. May contain multiple concatenated messages for streaming gRPC captures."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   grpcDecodeHandler,
}

func grpcDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("grpc_decode: 'hex' is required")
	}
	res, err := grpcdecode.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("grpc_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
