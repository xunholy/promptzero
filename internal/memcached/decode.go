// Package memcached decodes Memcached binary-protocol messages per
// the Memcached binary protocol specification. Runs on TCP/11211
// (default). Compatible with Memcached, Amazon ElastiCache
// (Memcached-compatible), Google Cloud Memorystore (Memcached-
// compatible), and Couchbase (Memcached-compatible binary
// protocol on the data port).
//
// Operationally, Memcached is a **high-value cache target** —
// caches session tokens, user data, API responses, and
// application state. Default Memcached ships with NO
// authentication and binds to all interfaces. Shodan finds tens
// of thousands of exposed Memcached instances on TCP/11211.
// Memcached has been weaponised for massive DDoS reflection/
// amplification attacks (CVE-2018-1000115, 51000x amplification
// factor via UDP).
//
// The wire format leaks:
//
//   - **Key names in cleartext** — every GET/SET/DELETE/INCR/
//     DECR/APPEND/PREPEND carries the cache key in cleartext.
//     Key names often encode application structure (e.g.
//     "session:abc123", "user:42:profile", "api:rate:10.0.0.1").
//
//   - **Cached values in cleartext** — SET/ADD/REPLACE carry
//     the value payload in cleartext. Often serialised user
//     sessions, API tokens, or application objects.
//
//   - **SASL authentication via 0x21 (SASL List Mechs) +
//     0x21 (SASL Auth) + 0x22 (SASL Step)** — when SASL is
//     configured (Couchbase, ElastiCache with auth). SASL
//     PLAIN = cleartext \0<username>\0<password>. The decoder
//     surfaces auth_bytes LENGTH only (privacy-preserving).
//
//   - **Stats command exposure** — the STAT opcode (0x10)
//     returns detailed server metadata: PID, version, uptime,
//     total connections, evictions, memory usage — canonical
//     version fingerprint + resource profiling.
//
// Wrap-vs-native judgement
//
//	Native. The Memcached binary protocol is publicly
//	documented. 24-byte fixed header: magic (1) + opcode (1) +
//	key_length (2 BE) + extras_length (1) + data_type (1) +
//	status/vbucket_id (2 BE) + total_body_length (4 BE) +
//	opaque (4 BE) + CAS (8 BE). No crypto at the parse layer.
//
// What this package covers
//
//   - **24-byte header walker**: magic (0x80 request / 0x81
//     response) + opcode + key_length + extras_length +
//     data_type + status (response) / vbucket_id (request) +
//     total_body_length + opaque + CAS.
//
//   - **35-entry opcode name table**: Get (0x00) / Set (0x01)
//     / Add (0x02) / Replace (0x03) / Delete (0x04) / Incr
//     (0x05) / Decr (0x06) / Quit (0x07) / Flush (0x08) /
//     GetQ (0x09) / Noop (0x0A) / Version (0x0B) / GetK
//     (0x0C) / GetKQ (0x0D) / Append (0x0E) / Prepend (0x0F)
//     / Stat (0x10) / SetQ (0x11) / AddQ (0x12) / ReplaceQ
//     (0x13) / DeleteQ (0x14) / IncrQ (0x15) / DecrQ (0x16)
//     / QuitQ (0x17) / FlushQ (0x18) / AppendQ (0x19) /
//     PrependQ (0x1A) / Verbosity (0x1B) / Touch (0x1C) /
//     GAT (0x1D) / GATQ (0x1E) / SASL ListMechs (0x20) /
//     SASL Auth (0x21) / SASL Step (0x22).
//
//   - **Key extraction**: cache key from request/response
//     body (key_length bytes after extras).
//
//   - **Value length computation**: total_body - key_length -
//     extras_length.
//
//   - **Response status decoder**: 15-entry status table
//     (0x00 No error through 0x86 Auth continue).
//
//   - **SET extras walker**: flags (4 BE) + expiration (4 BE)
//     from the extras section.
//
//   - **INCR/DECR extras walker**: delta (8 BE) + initial (8
//     BE) + expiration (4 BE).
//
//   - **SASL detection**: flags SASL Auth (0x21) with
//     auth_bytes length.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Memcached text protocol** — "get key\r\n" /
//     "set key 0 3600 5\r\n" text format; this decoder handles
//     the binary protocol only.
//   - **Value deserialization** — cached values may be
//     serialized objects (JSON, msgpack, application-specific
//     formats); the decoder surfaces value_length but does not
//     interpret the payload.
//   - **UDP Memcached** — the binary protocol over UDP adds
//     an 8-byte datagram header (request_id + seq_num +
//     num_datagrams + reserved); not handled.
//   - **TLS** — Memcached 1.5.13+ supports TLS; handle TLS
//     strip first.
//   - **Proxy protocol** — some load balancers prepend PROXY
//     protocol headers.
//   - **Credential extraction** — auth_bytes LENGTH only for
//     SASL; NEVER surfaces actual credentials or cached values.
package memcached

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

const headerSize = 24

// Result is the structured decode of a Memcached binary-protocol
// message.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	Magic        byte   `json:"magic"`
	MagicName    string `json:"magic_name"`
	Opcode       byte   `json:"opcode"`
	OpcodeName   string `json:"opcode_name"`
	KeyLength    int    `json:"key_length"`
	ExtrasLength int    `json:"extras_length"`
	DataType     byte   `json:"data_type"`
	Status       int    `json:"status,omitempty"`
	StatusName   string `json:"status_name,omitempty"`
	VBucketID    int    `json:"vbucket_id,omitempty"`
	TotalBodyLen int    `json:"total_body_length"`
	Opaque       uint32 `json:"opaque"`
	CAS          uint64 `json:"cas"`

	IsRequest  bool `json:"is_request"`
	IsResponse bool `json:"is_response"`

	// Extracted fields
	Key         string `json:"key,omitempty"`
	ValueLength int    `json:"value_length,omitempty"`

	// SET extras
	Flags      uint32 `json:"flags,omitempty"`
	Expiration uint32 `json:"expiration,omitempty"`

	// INCR/DECR extras
	Delta   uint64 `json:"delta,omitempty"`
	Initial uint64 `json:"initial,omitempty"`

	// SASL
	IsSASLAuth bool `json:"is_sasl_auth"`
	AuthBytes  int  `json:"auth_bytes,omitempty"`

	// Classification
	IsDataOp       bool `json:"is_data_operation"`
	IsAdminOp      bool `json:"is_admin_operation"`
	IsVersionProbe bool `json:"is_version_probe"`
}

// Decode parses a Memcached binary-protocol message from a hex
// string.
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
	if len(b) < headerSize {
		return nil, fmt.Errorf("memcached header truncated (%d bytes; need %d)", len(b), headerSize)
	}

	r := &Result{TotalBytes: len(b)}
	r.Magic = b[0]
	r.Opcode = b[1]
	r.KeyLength = int(binary.BigEndian.Uint16(b[2:4]))
	r.ExtrasLength = int(b[4])
	r.DataType = b[5]
	r.TotalBodyLen = int(binary.BigEndian.Uint32(b[8:12]))
	r.Opaque = binary.BigEndian.Uint32(b[12:16])
	r.CAS = binary.BigEndian.Uint64(b[16:24])

	switch r.Magic {
	case 0x80:
		r.IsRequest = true
		r.MagicName = "Request"
		r.VBucketID = int(binary.BigEndian.Uint16(b[6:8]))
	case 0x81:
		r.IsResponse = true
		r.MagicName = "Response"
		r.Status = int(binary.BigEndian.Uint16(b[6:8]))
		r.StatusName = statusName(r.Status)
	default:
		r.MagicName = fmt.Sprintf("unknown magic 0x%02x", r.Magic)
	}

	r.OpcodeName = opcodeName(r.Opcode)
	r.ValueLength = r.TotalBodyLen - r.KeyLength - r.ExtrasLength

	body := b[headerSize:]

	// Extract key
	keyStart := r.ExtrasLength
	if keyStart+r.KeyLength <= len(body) && r.KeyLength > 0 {
		r.Key = string(body[keyStart : keyStart+r.KeyLength])
	}

	// Walk extras for specific opcodes
	switch r.Opcode {
	case 0x01, 0x02, 0x03, 0x11, 0x12, 0x13: // Set/Add/Replace + Q variants
		if r.ExtrasLength >= 8 && len(body) >= 8 {
			r.Flags = binary.BigEndian.Uint32(body[0:4])
			r.Expiration = binary.BigEndian.Uint32(body[4:8])
		}
	case 0x05, 0x06, 0x15, 0x16: // Incr/Decr + Q variants
		if r.ExtrasLength >= 20 && len(body) >= 20 {
			r.Delta = binary.BigEndian.Uint64(body[0:8])
			r.Initial = binary.BigEndian.Uint64(body[8:16])
			r.Expiration = binary.BigEndian.Uint32(body[16:20])
		}
	}

	classify(r)
	return r, nil
}

func classify(r *Result) {
	switch r.Opcode {
	case 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Get/Set/Add/Replace/Delete/Incr/Decr
		0x09, 0x0C, 0x0D, 0x0E, 0x0F, // GetQ/GetK/GetKQ/Append/Prepend
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, // Q variants
		0x19, 0x1A, 0x1C, 0x1D, 0x1E: // AppendQ/PrependQ/Touch/GAT/GATQ
		r.IsDataOp = true
	case 0x07, 0x08, 0x10, 0x17, 0x18, 0x1B: // Quit/Flush/Stat/QuitQ/FlushQ/Verbosity
		r.IsAdminOp = true
	case 0x0B: // Version
		r.IsVersionProbe = true
	case 0x21: // SASL Auth
		r.IsSASLAuth = true
		r.AuthBytes = r.ValueLength
	case 0x22: // SASL Step
		r.IsSASLAuth = true
		r.AuthBytes = r.ValueLength
	}
}

func opcodeName(op byte) string {
	switch op {
	case 0x00:
		return "Get"
	case 0x01:
		return "Set"
	case 0x02:
		return "Add"
	case 0x03:
		return "Replace"
	case 0x04:
		return "Delete"
	case 0x05:
		return "Increment"
	case 0x06:
		return "Decrement"
	case 0x07:
		return "Quit"
	case 0x08:
		return "Flush"
	case 0x09:
		return "GetQ (quiet)"
	case 0x0A:
		return "No-op"
	case 0x0B:
		return "Version"
	case 0x0C:
		return "GetK (get with key)"
	case 0x0D:
		return "GetKQ (get with key, quiet)"
	case 0x0E:
		return "Append"
	case 0x0F:
		return "Prepend"
	case 0x10:
		return "Stat"
	case 0x11:
		return "SetQ (quiet)"
	case 0x12:
		return "AddQ (quiet)"
	case 0x13:
		return "ReplaceQ (quiet)"
	case 0x14:
		return "DeleteQ (quiet)"
	case 0x15:
		return "IncrementQ (quiet)"
	case 0x16:
		return "DecrementQ (quiet)"
	case 0x17:
		return "QuitQ (quiet)"
	case 0x18:
		return "FlushQ (quiet)"
	case 0x19:
		return "AppendQ (quiet)"
	case 0x1A:
		return "PrependQ (quiet)"
	case 0x1B:
		return "Verbosity"
	case 0x1C:
		return "Touch"
	case 0x1D:
		return "GAT (get and touch)"
	case 0x1E:
		return "GATQ (get and touch, quiet)"
	case 0x20:
		return "SASL List Mechanisms"
	case 0x21:
		return "SASL Authenticate"
	case 0x22:
		return "SASL Step"
	}
	return fmt.Sprintf("opcode 0x%02x", op)
}

func statusName(s int) string {
	switch s {
	case 0x0000:
		return "No error"
	case 0x0001:
		return "Key not found"
	case 0x0002:
		return "Key exists"
	case 0x0003:
		return "Value too large"
	case 0x0004:
		return "Invalid arguments"
	case 0x0005:
		return "Item not stored"
	case 0x0006:
		return "Incr/Decr on non-numeric value"
	case 0x0007:
		return "VBucket belongs to another server"
	case 0x0008:
		return "Authentication error"
	case 0x0009:
		return "Authentication continue"
	case 0x0081:
		return "Unknown command"
	case 0x0082:
		return "Out of memory"
	case 0x0083:
		return "Not supported"
	case 0x0084:
		return "Internal error"
	case 0x0085:
		return "Busy"
	case 0x0086:
		return "Temporary failure"
	}
	return fmt.Sprintf("status 0x%04x", s)
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
