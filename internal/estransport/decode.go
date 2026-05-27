// Package estransport decodes Elasticsearch internal transport protocol
// frames. The transport protocol runs on TCP/9300 and is used for
// inter-node communication within an Elasticsearch cluster — NOT the
// HTTP REST API on TCP/9200.
//
// Elasticsearch transport protocol is the binary protocol that cluster
// nodes use to exchange cluster state, shard assignments, search
// results, and index operations. It is distinct from the HTTP REST
// API (TCP/9200) that clients use.
//
// The transport protocol (ES 7.x+) uses the following framing:
//
//   - total_size (4 BE): total message size including all following bytes
//   - "ES" marker (2 bytes): 0x45 0x53 — magic prefix
//   - header_size (VInt encoded): size of the variable header
//   - request_id (8 BE): long — monotonically increasing per connection
//   - status (1 byte): bit flags
//     bit 0 (0x01) — request
//     bit 1 (0x02) — response
//     bit 2 (0x04) — error
//     bit 3 (0x08) — compressed
//     bit 4 (0x10) — handshake
//   - version (VInt encoded): transport protocol version (internal versioning)
//   - action name (length-prefixed string): operation identifier
//
// Action names reveal the internal operation being performed.
// Examples:
//
//	"internal:cluster/state"     — cluster state sync
//	"internal:cluster/nodes"     — node discovery
//	"indices:data/read/search"   — search request
//	"indices:data/write/index"   — document indexing
//	"indices:admin/create"       — index creation
//	"cluster:monitor/nodes/info" — node info query
//
// Security relevance:
//
//   - ES transport (TCP/9300) has NO authentication in default configs
//   - Any node speaking the transport protocol can join the cluster
//   - Transport traffic contains index data, search queries, cluster state
//   - Action names reveal internal operations and API surface
//   - NOT the same as the REST API (TCP/9200)
//   - Misconfigured ES clusters frequently exposed to internet on TCP/9300
//   - Joining an ES cluster gives full read/write access to all indices
//
// Wrap-vs-native judgement
//
//	Native. The Elasticsearch transport framing is a deterministic
//	binary format with a fixed "ES" magic marker, BE integers, VInt
//	encoded fields, and length-prefixed strings. No crypto at the
//	parse layer.
//
// What this package covers
//
//   - "ES" (0x45 0x53) magic marker detection
//   - total_size (4 BE) frame size
//   - request_id (8 BE) long
//   - status byte flags: compressed, handshake, error, request, response
//   - transport_version (VInt)
//   - action_name string extraction (length-prefixed)
//   - Classification: is_cluster_state, is_search, is_index,
//     is_handshake, is_internal_action
//
// What this package does NOT cover (deliberately out of scope)
//
//   - ES 6.x and earlier transport framing variants
//   - Message body / response payload parsing
//   - TLS transport layer (ES 8.x xpack.security.transport.ssl)
//   - Cluster join protocol beyond handshake detection
//   - Credential extraction (ES transport does not carry credentials
//     in the frame header in default config)
package estransport

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the structured decode of an Elasticsearch transport frame.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	HasESMarker      bool   `json:"has_es_marker"`
	MessageSize      int    `json:"message_size,omitempty"`
	RequestID        int64  `json:"request_id,omitempty"`
	TransportVersion int    `json:"transport_version,omitempty"`
	ActionName       string `json:"action_name,omitempty"`

	// Status flags decoded from the status byte
	StatusFlags  int  `json:"status_flags,omitempty"`
	IsRequest    bool `json:"is_request"`
	IsResponse   bool `json:"is_response"`
	IsError      bool `json:"is_error"`
	IsCompressed bool `json:"is_compressed"`
	IsHandshake  bool `json:"is_handshake"`

	// Action classification
	IsClusterState   bool `json:"is_cluster_state"`
	IsSearch         bool `json:"is_search"`
	IsIndex          bool `json:"is_index"`
	IsHandshakeFrame bool `json:"is_handshake_frame"`
	IsInternalAction bool `json:"is_internal_action"`
}

// minFrameSize is the minimum parseable ES transport frame:
// total_size(4) + "ES"(2) + header_size_vint(1) + request_id(8) + status(1) = 16
const minFrameSize = 16

// Decode parses an Elasticsearch transport protocol frame from a hex string.
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
	if len(b) < minFrameSize {
		return nil, fmt.Errorf("es transport frame truncated (%d bytes; need %d)", len(b), minFrameSize)
	}

	r := &Result{TotalBytes: len(b)}

	// Expect total_size (4 BE) followed by "ES" marker.
	r.MessageSize = int(binary.BigEndian.Uint32(b[0:4]))

	// Check for "ES" magic prefix at offset 4.
	if b[4] != 0x45 || b[5] != 0x53 {
		return nil, fmt.Errorf("es transport magic marker not found (got 0x%02x 0x%02x, want 0x45 0x53)", b[4], b[5])
	}
	r.HasESMarker = true

	off := 6

	// Read VInt-encoded header size. We need to consume it but use it
	// only to bound subsequent reads.
	_, n := readVInt(b[off:])
	if n == 0 {
		return nil, fmt.Errorf("es transport header_size vint truncated at offset %d", off)
	}
	off += n

	// request_id (8 BE)
	if off+8 > len(b) {
		return nil, fmt.Errorf("es transport request_id truncated at offset %d", off)
	}
	r.RequestID = int64(binary.BigEndian.Uint64(b[off : off+8]))
	off += 8

	// status byte
	if off >= len(b) {
		return nil, fmt.Errorf("es transport status byte truncated at offset %d", off)
	}
	status := b[off]
	off++
	r.StatusFlags = int(status)
	r.IsRequest = status&0x01 != 0
	r.IsResponse = status&0x02 != 0
	r.IsError = status&0x04 != 0
	r.IsCompressed = status&0x08 != 0
	r.IsHandshake = status&0x10 != 0

	// transport_version (VInt)
	if off < len(b) {
		ver, n2 := readVInt(b[off:])
		if n2 > 0 {
			r.TransportVersion = ver
			off += n2
		}
	}

	// action name — length-prefixed string (2-byte BE length prefix)
	if off+2 <= len(b) {
		action, _ := readString(b[off:])
		r.ActionName = action
	}

	classifyFrame(r)

	return r, nil
}

func classifyFrame(r *Result) {
	r.IsHandshakeFrame = r.IsHandshake

	action := r.ActionName
	if strings.HasPrefix(action, "internal:") {
		r.IsInternalAction = true
	}
	if strings.Contains(action, "cluster/state") || strings.Contains(action, "cluster/nodes") {
		r.IsClusterState = true
	}
	if strings.Contains(action, "data/read/search") || strings.Contains(action, "/search") {
		r.IsSearch = true
	}
	if strings.Contains(action, "data/write") || strings.Contains(action, "admin/create") ||
		strings.Contains(action, "admin/delete") {
		r.IsIndex = true
	}
}

// readVInt reads a VInt-encoded integer (Elasticsearch variable-length int).
// Returns the decoded value and the number of bytes consumed (0 on failure).
// VInt uses 7 bits per byte, MSB set = more bytes follow.
func readVInt(b []byte) (int, int) {
	if len(b) == 0 {
		return 0, 0
	}
	var val int
	for i, byt := range b {
		if i >= 5 {
			// VInt should not exceed 5 bytes for a 32-bit value
			break
		}
		val |= int(byt&0x7f) << (7 * i)
		if byt&0x80 == 0 {
			return val, i + 1
		}
	}
	return 0, 0
}

// readString reads a length-prefixed string (2-byte BE length prefix).
func readString(b []byte) (string, int) {
	if len(b) < 2 {
		return "", 0
	}
	l := int(binary.BigEndian.Uint16(b[0:2]))
	if l < 0 {
		return "", 2
	}
	if 2+l > len(b) {
		return "", 2
	}
	return string(b[2 : 2+l]), 2 + l
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
