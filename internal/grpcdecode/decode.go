// Package grpcdecode decodes gRPC Length-Prefixed Messages per the gRPC
// wire-protocol specification. gRPC uses HTTP/2 as its transport; this
// package focuses on the gRPC-specific framing layer that sits inside
// HTTP/2 DATA frames.
//
// # gRPC Length-Prefixed Message format (5-byte header)
//
//   - compressed_flag  (1 byte) : 0 = not compressed, 1 = compressed
//   - message_length   (4 BE)   : byte count of the following payload
//   - message_bytes[message_length]: serialized protobuf (not decoded)
//
// gRPC runs over HTTP/2 on TCP/443 (TLS, most cloud services), TCP/80
// (cleartext h2c, internal microservice meshes), and TCP/50051 (canonical
// insecure dev default). gRPC-Web (HTTP/1.1 variant) is sometimes exposed
// publicly on TCP/8080 / TCP/443 without authentication.
//
// Security relevance
//
//   - Default gRPC has NO authentication (insecure.NewCredentials()).
//     Many internal microservice meshes run without TLS or auth.
//   - gRPC reflection service (grpc.reflection.v1alpha) exposes the
//     full service/method schema when enabled — canonical pentest recon.
//   - Method paths (/package.Service/Method) leak internal API structure
//     as cleartext HTTP/2 headers.
//   - Protobuf messages are binary but NOT encrypted — field values are
//     visible if the .proto schema is known; field numbers + wire types
//     are always visible without the schema.
//   - gRPC status codes (grpc-status trailer) distinguish OK from
//     authentication / authorization failures.
//
// # Protobuf wire format (best-effort surface scan)
//
// Each field tag is a varint: (field_number << 3) | wire_type.
// Wire types: 0=varint, 1=64-bit, 2=length-delimited, 5=32-bit.
// This package walks the first few fields and counts them; it does NOT
// recursively decode nested messages or extract field values.
//
// # gRPC status codes
//
// 0=OK, 1=CANCELLED, 2=UNKNOWN, 3=INVALID_ARGUMENT, 4=DEADLINE_EXCEEDED,
// 5=NOT_FOUND, 6=ALREADY_EXISTS, 7=PERMISSION_DENIED,
// 8=RESOURCE_EXHAUSTED, 9=FAILED_PRECONDITION, 10=ABORTED,
// 11=OUT_OF_RANGE, 12=UNIMPLEMENTED, 13=INTERNAL, 14=UNAVAILABLE,
// 15=DATA_LOSS, 16=UNAUTHENTICATED.
//
// What this package covers
//
//   - gRPC Length-Prefixed Message 5-byte header detection
//   - compressed_flag + message_length extraction
//   - Best-effort protobuf field count + first field numbers/wire types
//   - Multiple concatenated messages (streaming gRPC)
//   - total_bytes
//
// What this package does NOT cover (deliberately out of scope)
//
//   - HTTP/2 frame parsing (use internal/http2)
//   - HPACK header decompression (use internal/hpack)
//   - Full protobuf value decoding (use the protobuf_decode tool)
//   - gzip/deflate decompression of compressed messages
//   - gRPC-Web envelope (different framing byte)
package grpcdecode

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// maxFieldScan is the maximum number of protobuf fields walked per message.
const maxFieldScan = 8

// ProtoField is a single best-effort protobuf field tag decoded from the
// message payload.
type ProtoField struct {
	FieldNumber  int    `json:"field_number"`
	WireType     int    `json:"wire_type"`
	WireTypeName string `json:"wire_type_name"`
}

// Message is the decode of a single gRPC Length-Prefixed Message.
type Message struct {
	Compressed         bool         `json:"compressed"`
	MessageLength      int          `json:"message_length"`
	ProtobufFieldCount int          `json:"protobuf_field_count"`
	ProtobufFields     []ProtoField `json:"protobuf_fields,omitempty"`
}

// Result is the structured decode of a gRPC Length-Prefixed payload which
// may contain one or more concatenated messages (streaming gRPC).
type Result struct {
	TotalBytes   int       `json:"total_bytes"`
	MessageCount int       `json:"message_count"`
	Messages     []Message `json:"messages"`
}

// Decode parses a gRPC Length-Prefixed payload from a hex string.
// The input is the raw bytes of the gRPC framing layer (the payload of
// HTTP/2 DATA frames), not the full HTTP/2 frame.
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if len(clean) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex (%d nibbles)", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	// A valid gRPC length-prefixed message requires at least 5 bytes
	// (1 compressed_flag + 4 message_length).
	if len(b) < 5 {
		return nil, fmt.Errorf("grpc frame truncated (%d bytes; need at least 5)", len(b))
	}

	r := &Result{TotalBytes: len(b)}
	off := 0
	for off < len(b) {
		if off+5 > len(b) {
			// Trailing bytes that cannot form a complete header — stop.
			break
		}
		compressedFlag := b[off]
		if compressedFlag != 0 && compressedFlag != 1 {
			// Not a valid gRPC compressed flag; stop walking.
			break
		}
		msgLen := int(binary.BigEndian.Uint32(b[off+1 : off+5]))
		off += 5

		msg := Message{
			Compressed:    compressedFlag == 1,
			MessageLength: msgLen,
		}

		// Walk protobuf fields from the message payload (best-effort).
		end := off + msgLen
		if end > len(b) {
			end = len(b)
		}
		payload := b[off:end]
		if !msg.Compressed {
			msg.ProtobufFields, msg.ProtobufFieldCount = scanProtoFields(payload)
		}

		r.Messages = append(r.Messages, msg)
		r.MessageCount++

		if off+msgLen > len(b) {
			// Message payload extends beyond available bytes; stop.
			break
		}
		off += msgLen
	}

	if r.MessageCount == 0 {
		return nil, fmt.Errorf("grpc frame truncated (%d bytes; need at least 5)", len(b))
	}

	return r, nil
}

// scanProtoFields performs a best-effort walk of the first few protobuf
// field tags in buf. It returns the decoded fields and a total field count
// (which may be larger than len(fields) if the payload has more than
// maxFieldScan fields, though this implementation caps both the walk and
// the count at maxFieldScan for simplicity).
func scanProtoFields(buf []byte) ([]ProtoField, int) {
	var fields []ProtoField
	off := 0
	for off < len(buf) && len(fields) < maxFieldScan {
		tag, n := decodeVarint(buf[off:])
		if n == 0 {
			break
		}
		off += n

		wireType := int(tag & 0x7)
		fieldNumber := int(tag >> 3)
		if fieldNumber == 0 {
			break
		}

		fields = append(fields, ProtoField{
			FieldNumber:  fieldNumber,
			WireType:     wireType,
			WireTypeName: wireTypeName(wireType),
		})

		// Advance past the field value so we can find the next tag.
		switch wireType {
		case 0: // varint
			_, n = decodeVarint(buf[off:])
			if n == 0 {
				goto done
			}
			off += n
		case 1: // 64-bit
			off += 8
		case 2: // length-delimited
			length, n := decodeVarint(buf[off:])
			if n == 0 {
				goto done
			}
			off += n + int(length)
		case 5: // 32-bit
			off += 4
		default:
			// Unknown wire type — stop scanning.
			goto done
		}
		if off > len(buf) {
			break
		}
	}
done:
	return fields, len(fields)
}

// decodeVarint decodes a protobuf-style base-128 varint from b.
// Returns (value, bytesConsumed). bytesConsumed is 0 on error.
func decodeVarint(b []byte) (uint64, int) {
	var x uint64
	for i, byt := range b {
		if i >= 10 {
			return 0, 0
		}
		x |= uint64(byt&0x7F) << (7 * uint(i))
		if byt&0x80 == 0 {
			return x, i + 1
		}
	}
	return 0, 0
}

// wireTypeName returns the canonical name for a protobuf wire type.
func wireTypeName(wt int) string {
	switch wt {
	case 0:
		return "varint"
	case 1:
		return "64-bit"
	case 2:
		return "length-delimited"
	case 5:
		return "32-bit"
	default:
		return fmt.Sprintf("wire_type_%d", wt)
	}
}

// GRPCStatusName returns the canonical gRPC status code name for code c.
func GRPCStatusName(c int) string {
	switch c {
	case 0:
		return "OK"
	case 1:
		return "CANCELLED"
	case 2:
		return "UNKNOWN"
	case 3:
		return "INVALID_ARGUMENT"
	case 4:
		return "DEADLINE_EXCEEDED"
	case 5:
		return "NOT_FOUND"
	case 6:
		return "ALREADY_EXISTS"
	case 7:
		return "PERMISSION_DENIED"
	case 8:
		return "RESOURCE_EXHAUSTED"
	case 9:
		return "FAILED_PRECONDITION"
	case 10:
		return "ABORTED"
	case 11:
		return "OUT_OF_RANGE"
	case 12:
		return "UNIMPLEMENTED"
	case 13:
		return "INTERNAL"
	case 14:
		return "UNAVAILABLE"
	case 15:
		return "DATA_LOSS"
	case 16:
		return "UNAUTHENTICATED"
	default:
		return fmt.Sprintf("grpc_status_%d", c)
	}
}

func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', ':', '-', '_':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
