// Package amqp091 decodes AMQP 0-9-1 wire-protocol frames per the
// AMQP 0-9-1 specification. Runs on TCP/5672 (plaintext) and
// TCP/5671 (AMQPS — TLS-wrapped). The canonical implementation
// is RabbitMQ; also used by LavinMQ, Apache Qpid, Azure Service
// Bus (AMQP 1.0 but accepts 0-9-1 connections), VMware Tanzu
// RabbitMQ, and CloudAMQP (hosted RabbitMQ).
//
// Operationally, RabbitMQ is a **high-value enterprise messaging
// target** — it brokers inter-service communication in
// microservice architectures, event-driven systems, and async
// job queues. Default RabbitMQ ships with a "guest/guest"
// account restricted to localhost, but many deployments expose
// TCP/5672 with weak or reused credentials, and the management
// UI on TCP/15672 (HTTP API) often reveals vhost / queue / user
// topology.
//
// The wire format leaks:
//
//   - **Server product + version + platform via
//     Connection.Start** — the server sends a
//     Connection.Start method immediately after receiving the
//     protocol header. The server-properties table includes
//     `product` (e.g. "RabbitMQ"), `version` (e.g. "3.13.0"),
//     `platform` (e.g. "Erlang/OTP 26.2.1"), `cluster_name`,
//     `copyright`, and `information`. The `mechanisms` field
//     lists supported SASL mechanisms: PLAIN (cleartext — the
//     default), AMQPLAIN (RabbitMQ legacy), EXTERNAL (client
//     cert), RABBIT-CR-DEMO (challenge-response demo —
//     should never be in production). Canonical version
//     fingerprint for CVE selection.
//
//   - **Cleartext credentials via Connection.StartOk with
//     PLAIN mechanism** — the most common auth path. SASL
//     PLAIN response format is: \0<username>\0<password> — both
//     user and password transmitted in cleartext inside the
//     AMQP frame on unencrypted TCP/5672. The decoder surfaces
//     the mechanism name + response length (privacy-preserving
//     — never extracts the actual credentials, but flags the
//     cleartext exposure).
//
//   - **Virtual-host disclosure via Connection.Open** —
//     reveals the target vhost name (e.g. "/" default, or
//     application-specific vhosts like "production",
//     "staging"). Vhost names disclose environment topology.
//
//   - **Exchange + routing-key disclosure via
//     Basic.Publish** — reveals the target exchange name and
//     routing key, exposing message routing topology.
//
//   - **Queue name disclosure via Queue.Declare /
//     Queue.Bind / Basic.Consume** — reveals queue names and
//     binding topology.
//
//   - **Connection tuning parameters via Connection.Tune /
//     TuneOk** — channel-max, frame-max, heartbeat interval.
//     Reveals broker configuration and can inform resource
//     exhaustion attacks.
//
// Wrap-vs-native judgement
//
//	Native. The AMQP 0-9-1 wire format is publicly specified
//	in the AMQP 0-9-1 specification (amqp.org). Frames are a
//	fixed 7-byte header (type + channel + size) + payload +
//	0xCE frame-end marker. Method frames carry classId +
//	methodId (2+2 bytes BE) followed by method-specific
//	arguments. No crypto at the parse layer.
//
// What this package covers
//
//   - **Protocol header detection**: "AMQP\x00\x00\x09\x01"
//     magic (client-sent protocol negotiation header).
//
//   - **7-byte frame header walker**: type (1 — Method=1 /
//     ContentHeader=2 / ContentBody=3 / Heartbeat=4) /
//     channel (2 BE) / size (4 BE — payload size excluding
//     header and frame-end).
//
//   - **Frame-end 0xCE validation**.
//
//   - **Method frame class+method decoder**: 7 classes ×
//     key methods — Connection (10) / Channel (20) /
//     Exchange (40) / Queue (50) / Basic (60) / Tx (90) /
//     Confirm (85). Method name table maps (classId,
//     methodId) → human-readable name.
//
//   - **Connection.Start argument walker**: version-major +
//     version-minor + server-properties table + mechanisms
//     long-string + locales long-string. Extracts product /
//     version / platform / cluster_name from server-properties.
//
//   - **Connection.StartOk argument walker**: client-
//     properties table + mechanism short-string + response
//     long-string (length only — privacy-preserving) + locale
//     short-string. Flags PLAIN cleartext exposure.
//
//   - **Connection.Tune / TuneOk walker**: channel-max +
//     frame-max + heartbeat.
//
//   - **Connection.Open walker**: virtual-host short-string.
//
//   - **Connection.Close walker**: reply-code + reply-text +
//     failing class-id + method-id.
//
//   - **Exchange.Declare walker**: exchange name + type.
//
//   - **Queue.Declare walker**: queue name.
//
//   - **Queue.Bind walker**: queue + exchange + routing-key.
//
//   - **Basic.Publish walker**: exchange + routing-key.
//
//   - **Basic.Consume walker**: queue name.
//
//   - **Basic.Deliver walker**: exchange + routing-key.
//
//   - **AMQP table walker**: 4-byte length + field entries
//     (short-string key + type tag + value). Supports string
//     ('S'), long-int ('I'), boolean ('t'), and nested table
//     ('F') types.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Content header property parsing** — content header
//     frames (type 2) carry class-specific properties
//     (content-type, delivery-mode, headers, etc.) as a
//     property-flags bitfield + property values. The decoder
//     identifies the frame type but does not walk the
//     property values.
//   - **Content body reassembly** — content body frames
//     (type 3) carry raw message payload data. The decoder
//     identifies the frame type and size but does not
//     interpret the payload content.
//   - **AMQP 1.0** — a completely different wire protocol
//     (ISO/IEC 19464); not binary-compatible with 0-9-1.
//   - **TLS handshake** — AMQPS (TCP/5671) wraps the AMQP
//     connection in TLS; handle the TLS strip first.
//   - **RabbitMQ management HTTP API** — TCP/15672 REST API
//     for queue/exchange/user management; separate HTTP
//     concern.
//   - **RabbitMQ Streams protocol** — separate binary
//     protocol on TCP/5552 for streaming consumers.
//   - **STOMP / MQTT plugin protocols** — RabbitMQ supports
//     STOMP (TCP/61613) and MQTT (TCP/1883) via plugins;
//     separate protocol concerns.
//   - **Credential extraction** — the decoder surfaces
//     response_bytes LENGTH only for SASL PLAIN/AMQPLAIN
//     auth; it NEVER extracts or surfaces actual username/
//     password values.
package amqp091

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the structured decode of an AMQP 0-9-1 frame or
// protocol header.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// Protocol header (if detected)
	IsProtocolHeader bool   `json:"is_protocol_header"`
	ProtocolMajor    int    `json:"protocol_major,omitempty"`
	ProtocolMinor    int    `json:"protocol_minor,omitempty"`
	ProtocolRevision int    `json:"protocol_revision,omitempty"`
	ProtocolID       string `json:"protocol_id,omitempty"`

	// Frame header
	FrameType     int    `json:"frame_type,omitempty"`
	FrameTypeName string `json:"frame_type_name,omitempty"`
	Channel       int    `json:"channel,omitempty"`
	PayloadSize   int    `json:"payload_size,omitempty"`
	FrameEndValid bool   `json:"frame_end_valid,omitempty"`

	// Method frame
	ClassID    int    `json:"class_id,omitempty"`
	MethodID   int    `json:"method_id,omitempty"`
	ClassName  string `json:"class_name,omitempty"`
	MethodName string `json:"method_name,omitempty"`

	// Connection.Start
	ServerProduct  string `json:"server_product,omitempty"`
	ServerVersion  string `json:"server_version,omitempty"`
	ServerPlatform string `json:"server_platform,omitempty"`
	ClusterName    string `json:"cluster_name,omitempty"`
	Mechanisms     string `json:"mechanisms,omitempty"`
	Locales        string `json:"locales,omitempty"`

	// Connection.StartOk
	ClientProduct string `json:"client_product,omitempty"`
	ClientVersion string `json:"client_version,omitempty"`
	SASLMechanism string `json:"sasl_mechanism,omitempty"`
	ResponseBytes int    `json:"response_bytes,omitempty"`
	Locale        string `json:"locale,omitempty"`

	// Connection.Tune / TuneOk
	ChannelMax int `json:"channel_max,omitempty"`
	FrameMax   int `json:"frame_max,omitempty"`
	Heartbeat  int `json:"heartbeat,omitempty"`

	// Connection.Open
	VirtualHost string `json:"virtual_host,omitempty"`

	// Connection.Close
	ReplyCode    int    `json:"reply_code,omitempty"`
	ReplyText    string `json:"reply_text,omitempty"`
	FailClassID  int    `json:"fail_class_id,omitempty"`
	FailMethodID int    `json:"fail_method_id,omitempty"`

	// Exchange / Queue / Basic routing
	ExchangeName string `json:"exchange_name,omitempty"`
	ExchangeType string `json:"exchange_type,omitempty"`
	QueueName    string `json:"queue_name,omitempty"`
	RoutingKey   string `json:"routing_key,omitempty"`

	// Security flags
	IsCleartextAuth     bool   `json:"is_cleartext_auth"`
	CleartextAuthFlag   string `json:"cleartext_auth_flag,omitempty"`
	IsVersionDisclosure bool   `json:"is_version_disclosure"`
}

const (
	frameHeaderSize = 7
	frameEndByte    = 0xCE
)

// Decode parses an AMQP 0-9-1 frame or protocol header from a
// hex string.
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

	r := &Result{TotalBytes: len(b)}

	if len(b) >= 8 && string(b[0:4]) == "AMQP" {
		r.IsProtocolHeader = true
		r.ProtocolID = string(b[0:4])
		r.ProtocolMajor = int(b[5])
		r.ProtocolMinor = int(b[6])
		r.ProtocolRevision = int(b[7])
		return r, nil
	}

	if len(b) < frameHeaderSize {
		return nil, fmt.Errorf("amqp frame truncated (%d bytes; need 7)", len(b))
	}

	r.FrameType = int(b[0])
	r.FrameTypeName = frameTypeName(r.FrameType)
	r.Channel = int(binary.BigEndian.Uint16(b[1:3]))
	r.PayloadSize = int(binary.BigEndian.Uint32(b[3:7]))

	frameEnd := frameHeaderSize + r.PayloadSize
	if frameEnd < len(b) {
		r.FrameEndValid = b[frameEnd] == frameEndByte
	}

	payload := b[frameHeaderSize:]
	if r.PayloadSize < len(payload) {
		payload = payload[:r.PayloadSize]
	}

	if r.FrameType == 1 && len(payload) >= 4 {
		r.ClassID = int(binary.BigEndian.Uint16(payload[0:2]))
		r.MethodID = int(binary.BigEndian.Uint16(payload[2:4]))
		r.ClassName = className(r.ClassID)
		r.MethodName = methodName(r.ClassID, r.MethodID)
		decodeMethodArgs(r, payload[4:])
	}

	return r, nil
}

func decodeMethodArgs(r *Result, args []byte) {
	switch r.ClassID {
	case 10: // Connection
		switch r.MethodID {
		case 10:
			decodeConnectionStart(r, args)
		case 11:
			decodeConnectionStartOk(r, args)
		case 30:
			decodeConnectionTune(r, args)
		case 31:
			decodeConnectionTune(r, args) // TuneOk same shape
		case 40:
			decodeConnectionOpen(r, args)
		case 50:
			decodeConnectionClose(r, args)
		}
	case 40: // Exchange
		if r.MethodID == 10 {
			decodeExchangeDeclare(r, args)
		}
	case 50: // Queue
		switch r.MethodID {
		case 10:
			decodeQueueDeclare(r, args)
		case 20:
			decodeQueueBind(r, args)
		}
	case 60: // Basic
		switch r.MethodID {
		case 20:
			decodeBasicConsume(r, args)
		case 40:
			decodeBasicPublish(r, args)
		case 60:
			decodeBasicDeliver(r, args)
		}
	}
}

func decodeConnectionStart(r *Result, args []byte) {
	if len(args) < 2 {
		return
	}
	r.IsVersionDisclosure = true
	off := 2 // skip version-major + version-minor

	// server-properties table
	props, n := readTable(args[off:])
	off += n
	if props != nil {
		if v, ok := props["product"]; ok {
			r.ServerProduct = v
		}
		if v, ok := props["version"]; ok {
			r.ServerVersion = v
		}
		if v, ok := props["platform"]; ok {
			r.ServerPlatform = v
		}
		if v, ok := props["cluster_name"]; ok {
			r.ClusterName = v
		}
	}

	// mechanisms (long-string)
	s, n := readLongString(args[off:])
	r.Mechanisms = s
	off += n

	// locales (long-string)
	s, _ = readLongString(args[off:])
	r.Locales = s
}

func decodeConnectionStartOk(r *Result, args []byte) {
	off := 0

	// client-properties table
	props, n := readTable(args[off:])
	off += n
	if props != nil {
		if v, ok := props["product"]; ok {
			r.ClientProduct = v
		}
		if v, ok := props["version"]; ok {
			r.ClientVersion = v
		}
	}

	// mechanism (short-string)
	s, n := readShortString(args[off:])
	r.SASLMechanism = s
	off += n

	// response (long-string) — length only. respLen is an untrusted 32-bit
	// length from the wire; advancing off by it blindly would let a crafted
	// value push off past len(args) and panic the locale slice below, so the
	// skip is gated on the body actually fitting (overflow-safe comparison).
	respValid := false
	if off+4 <= len(args) {
		respLen := int(binary.BigEndian.Uint32(args[off : off+4]))
		r.ResponseBytes = respLen
		off += 4
		if respLen >= 0 && respLen <= len(args)-off {
			off += respLen
			respValid = true
		}
	}

	if r.SASLMechanism == "PLAIN" {
		r.IsCleartextAuth = true
		r.CleartextAuthFlag = "SASL PLAIN — credentials transmitted as \\0<username>\\0<password> in cleartext; offline capture yields immediate credential access"
	}

	// locale (short-string) — only when the response body was within bounds.
	if respValid {
		s, _ = readShortString(args[off:])
		r.Locale = s
	}
}

func decodeConnectionTune(r *Result, args []byte) {
	if len(args) < 8 {
		return
	}
	r.ChannelMax = int(binary.BigEndian.Uint16(args[0:2]))
	r.FrameMax = int(binary.BigEndian.Uint32(args[2:6]))
	r.Heartbeat = int(binary.BigEndian.Uint16(args[6:8]))
}

func decodeConnectionOpen(r *Result, args []byte) {
	s, _ := readShortString(args)
	r.VirtualHost = s
}

func decodeConnectionClose(r *Result, args []byte) {
	if len(args) < 2 {
		return
	}
	r.ReplyCode = int(binary.BigEndian.Uint16(args[0:2]))
	off := 2

	s, n := readShortString(args[off:])
	r.ReplyText = s
	off += n

	if off+4 <= len(args) {
		r.FailClassID = int(binary.BigEndian.Uint16(args[off : off+2]))
		r.FailMethodID = int(binary.BigEndian.Uint16(args[off+2 : off+4]))
	}
}

func decodeExchangeDeclare(r *Result, args []byte) {
	if len(args) < 2 {
		return
	}
	off := 2 // skip ticket

	s, n := readShortString(args[off:])
	r.ExchangeName = s
	off += n

	s, _ = readShortString(args[off:])
	r.ExchangeType = s
}

func decodeQueueDeclare(r *Result, args []byte) {
	if len(args) < 2 {
		return
	}
	off := 2 // skip ticket

	s, _ := readShortString(args[off:])
	r.QueueName = s
}

func decodeQueueBind(r *Result, args []byte) {
	if len(args) < 2 {
		return
	}
	off := 2 // skip ticket

	s, n := readShortString(args[off:])
	r.QueueName = s
	off += n

	s, n = readShortString(args[off:])
	r.ExchangeName = s
	off += n

	s, _ = readShortString(args[off:])
	r.RoutingKey = s
}

func decodeBasicPublish(r *Result, args []byte) {
	if len(args) < 2 {
		return
	}
	off := 2 // skip ticket

	s, n := readShortString(args[off:])
	r.ExchangeName = s
	off += n

	s, _ = readShortString(args[off:])
	r.RoutingKey = s
}

func decodeBasicConsume(r *Result, args []byte) {
	if len(args) < 2 {
		return
	}
	off := 2 // skip ticket

	s, _ := readShortString(args[off:])
	r.QueueName = s
}

func decodeBasicDeliver(r *Result, args []byte) {
	off := 0

	// consumer-tag (short-string) — skip
	_, n := readShortString(args[off:])
	off += n

	// delivery-tag (8 bytes) + redelivered (1 byte)
	off += 9
	if off > len(args) {
		return
	}

	s, n := readShortString(args[off:])
	r.ExchangeName = s
	off += n

	s, _ = readShortString(args[off:])
	r.RoutingKey = s
}

// readShortString reads an AMQP short-string (1-byte length prefix).
func readShortString(b []byte) (string, int) {
	if len(b) < 1 {
		return "", 0
	}
	l := int(b[0])
	if 1+l > len(b) {
		return "", 1
	}
	return string(b[1 : 1+l]), 1 + l
}

// readLongString reads an AMQP long-string (4-byte BE length prefix).
func readLongString(b []byte) (string, int) {
	if len(b) < 4 {
		return "", 0
	}
	l := int(binary.BigEndian.Uint32(b[0:4]))
	if 4+l > len(b) {
		return "", 4
	}
	return string(b[4 : 4+l]), 4 + l
}

// readTable reads an AMQP field table and extracts string values.
func readTable(b []byte) (map[string]string, int) {
	if len(b) < 4 {
		return nil, 0
	}
	tableLen := int(binary.BigEndian.Uint32(b[0:4]))
	if 4+tableLen > len(b) {
		return nil, 4
	}
	result := make(map[string]string)
	off := 4
	end := 4 + tableLen
	for off < end {
		key, n := readShortString(b[off:])
		off += n
		if off >= end {
			break
		}
		tag := b[off]
		off++
		switch tag {
		case 'S': // long-string
			val, n := readLongString(b[off:])
			result[key] = val
			off += n
		case 'I': // long int
			off += 4
		case 't': // boolean
			off++
		case 'F': // nested table
			if off+4 <= len(b) {
				innerLen := int(binary.BigEndian.Uint32(b[off : off+4]))
				off += 4 + innerLen
			}
		default:
			return result, end
		}
	}
	return result, end
}

func frameTypeName(t int) string {
	switch t {
	case 1:
		return "Method"
	case 2:
		return "Content Header"
	case 3:
		return "Content Body"
	case 4:
		return "Heartbeat"
	}
	return fmt.Sprintf("unknown frame type %d", t)
}

func className(c int) string {
	switch c {
	case 10:
		return "Connection"
	case 20:
		return "Channel"
	case 40:
		return "Exchange"
	case 50:
		return "Queue"
	case 60:
		return "Basic"
	case 85:
		return "Confirm"
	case 90:
		return "Tx"
	}
	return fmt.Sprintf("class %d", c)
}

func methodName(classID, methodID int) string {
	switch classID {
	case 10: // Connection
		switch methodID {
		case 10:
			return "Connection.Start"
		case 11:
			return "Connection.StartOk"
		case 20:
			return "Connection.Secure"
		case 21:
			return "Connection.SecureOk"
		case 30:
			return "Connection.Tune"
		case 31:
			return "Connection.TuneOk"
		case 40:
			return "Connection.Open"
		case 41:
			return "Connection.OpenOk"
		case 50:
			return "Connection.Close"
		case 51:
			return "Connection.CloseOk"
		case 60:
			return "Connection.Blocked"
		case 61:
			return "Connection.Unblocked"
		}
	case 20: // Channel
		switch methodID {
		case 10:
			return "Channel.Open"
		case 11:
			return "Channel.OpenOk"
		case 20:
			return "Channel.Flow"
		case 21:
			return "Channel.FlowOk"
		case 40:
			return "Channel.Close"
		case 41:
			return "Channel.CloseOk"
		}
	case 40: // Exchange
		switch methodID {
		case 10:
			return "Exchange.Declare"
		case 11:
			return "Exchange.DeclareOk"
		case 20:
			return "Exchange.Delete"
		case 21:
			return "Exchange.DeleteOk"
		case 30:
			return "Exchange.Bind"
		case 31:
			return "Exchange.BindOk"
		case 40:
			return "Exchange.Unbind"
		case 51:
			return "Exchange.UnbindOk"
		}
	case 50: // Queue
		switch methodID {
		case 10:
			return "Queue.Declare"
		case 11:
			return "Queue.DeclareOk"
		case 20:
			return "Queue.Bind"
		case 21:
			return "Queue.BindOk"
		case 30:
			return "Queue.Purge"
		case 31:
			return "Queue.PurgeOk"
		case 40:
			return "Queue.Delete"
		case 41:
			return "Queue.DeleteOk"
		case 50:
			return "Queue.Unbind"
		case 51:
			return "Queue.UnbindOk"
		}
	case 60: // Basic
		switch methodID {
		case 10:
			return "Basic.Qos"
		case 11:
			return "Basic.QosOk"
		case 20:
			return "Basic.Consume"
		case 21:
			return "Basic.ConsumeOk"
		case 30:
			return "Basic.Cancel"
		case 31:
			return "Basic.CancelOk"
		case 40:
			return "Basic.Publish"
		case 50:
			return "Basic.Return"
		case 60:
			return "Basic.Deliver"
		case 70:
			return "Basic.Get"
		case 71:
			return "Basic.GetOk"
		case 72:
			return "Basic.GetEmpty"
		case 80:
			return "Basic.Ack"
		case 90:
			return "Basic.Reject"
		case 100:
			return "Basic.RecoverAsync"
		case 110:
			return "Basic.Recover"
		case 111:
			return "Basic.RecoverOk"
		case 120:
			return "Basic.Nack"
		}
	case 85: // Confirm
		switch methodID {
		case 10:
			return "Confirm.Select"
		case 11:
			return "Confirm.SelectOk"
		}
	case 90: // Tx
		switch methodID {
		case 10:
			return "Tx.Select"
		case 11:
			return "Tx.SelectOk"
		case 20:
			return "Tx.Commit"
		case 21:
			return "Tx.CommitOk"
		case 30:
			return "Tx.Rollback"
		case 31:
			return "Tx.RollbackOk"
		}
	}
	return fmt.Sprintf("%s.method_%d", className(classID), methodID)
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
