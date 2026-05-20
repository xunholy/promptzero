// Package opcua decodes OPC UA Binary messages per IEC 62541-6
// (OPC Unified Architecture, Part 6: Mappings). OPC UA is the
// modern industrial-messaging protocol that supersedes OPC
// Classic (DCOM-based) and is the **vendor-neutral lingua franca
// of MES, SCADA, historian, and IIoT gateway stacks** on the
// current-generation factory floor.
//
// Where the older industrial protocols target a specific niche
// (Modbus = serial-derived register access; S7Comm = Siemens
// PLCs; DNP3 + IEC 104 = utility SCADA telecontrol; CIP =
// Allen-Bradley; Profinet = Siemens factory Ethernet), OPC UA
// sits ABOVE all of them as the **application-layer protocol an
// MES or SCADA layer speaks to harvest values from any of them**.
// Every modern PLC + DCS + edge gateway (Siemens S7-1500, Rockwell
// ControlLogix, Schneider M580, Beckhoff TwinCAT, B&R, ABB,
// Yokogawa, ...) ships a built-in OPC UA server. Cloud-bound
// historians (PI System, Cognite Data Fusion, AWS IoT SiteWise,
// Azure Industrial IoT) ship OPC UA clients.
//
// Operationally, OPC UA Binary runs over TCP/4840 by default
// (TCP/4843 for OPC UA over TLS). Sessions follow a deterministic
// six-step opening:
//
//   - **HEL** (Hello) — client → server: ProtocolVersion + buffer
//     sizes + EndpointURL the client wants to talk to.
//   - **ACK** (Acknowledge) — server → client: agreed buffer
//     sizes + protocol version.
//   - **OPN** (OpenSecureChannel) — client → server: security
//     policy URI + sender certificate + receiver thumbprint +
//     OpenSecureChannelRequest service body.
//   - **OPN** (response) — server → client: assigns SecureChannelId
//     and TokenId.
//   - **MSG** (Message) — client → server: per-service requests
//     (CreateSession, ActivateSession, Read, Write, Browse, Call,
//     CreateSubscription, Publish, ...) carried under the
//     established SecureChannelId.
//   - **CLO** (CloseSecureChannel) — eventual session teardown.
//
// Wrap-vs-native judgement
//
//	Native. The OPC UA Binary encoding is publicly documented in
//	IEC 62541-6 and the OPC Foundation reference implementations
//	(open62541 in C, OPCFoundation/UA-.NETStandard in C#). The
//	message header is a tight 8 bytes (3-byte ASCII MessageType
//	+ 1-byte ChunkType + 4-byte LE MessageSize) followed by a
//	per-MessageType body. The per-Service request/response inside
//	MSG/OPN bodies is BINARY-encoded NodeIds + ExpandedNodeIds +
//	QualifiedNames + structured types per IEC 62541-6 §5; the
//	per-service decoder set is enormous and dataset-specific —
//	surfaced as `service_body_hex` for future per-service
//	walkers. No crypto at the parse layer (the SecurityPolicyUri
//	on OPN identifies the algorithm suite — Basic128Rsa15,
//	Basic256Sha256, Aes128_Sha256_RsaOaep — but key derivation
//	and AES-CBC body decryption is higher-level work).
//
// What this package covers
//
//   - **Message header** (IEC 62541-6 §7.1.2, 8 bytes; multi-byte
//     fields are LITTLE-ENDIAN):
//
//   - bytes 0-2: **MessageType** (3 ASCII chars; identifies
//     the message kind).
//
//   - byte 3: **ChunkType** (1 ASCII char): `F` Final / `C`
//     Intermediate Chunk (more chunks follow) / `A` Abort
//     (the sender aborts the chunked message).
//
//   - bytes 4-7: **MessageSize** (uint32 LE; total bytes
//     INCLUDING this 8-byte header).
//
//   - **7-entry MessageType name table** (IEC 62541-6 §7.1.2.2):
//     `HEL` Hello / `ACK` Acknowledge / `ERR` Error / `MSG`
//     Message (UA Service request/response under a secure
//     channel) / `OPN` OpenSecureChannel / `CLO`
//     CloseSecureChannel / `RHE` ReverseHello (server-initiated
//     connection establishment).
//
//   - **3-entry ChunkType name table**: `F` Final / `C`
//     Intermediate Chunk / `A` Abort.
//
//   - **HEL body** (IEC 62541-6 §7.1.2.3): 4-byte
//     ProtocolVersion + 4-byte ReceiveBufferSize + 4-byte
//     SendBufferSize + 4-byte MaxMessageSize + 4-byte
//     MaxChunkCount + UA String EndpointURL (4-byte length LE +
//     UTF-8 bytes; length = -1 / 0xFFFFFFFF indicates null
//     string).
//
//   - **ACK body**: 4-byte ProtocolVersion + 4-byte
//     ReceiveBufferSize + 4-byte SendBufferSize + 4-byte
//     MaxMessageSize + 4-byte MaxChunkCount (no URL).
//
//   - **ERR body**: 4-byte StatusCode + UA String Reason. The
//     StatusCode is the IEC 62541-4 §7.34 OPC UA status code
//     (high 16 bits = error code, low 16 bits = info bits;
//     0x80000000 = severity bit).
//
//   - **OPN body** (OpenSecureChannel security header preface):
//     4-byte SecureChannelId + UA String SecurityPolicyUri +
//     UA ByteString SenderCertificate + UA ByteString
//     ReceiverCertificateThumbprint + 4-byte SequenceNumber +
//     4-byte RequestId. The remaining bytes are the OPN service
//     request/response body (OpenSecureChannelRequest /
//     OpenSecureChannelResponse), surfaced as `service_body_hex`.
//
//   - **MSG / CLO body** (symmetric secure channel): 4-byte
//     SecureChannelId + 4-byte TokenId + 4-byte SequenceNumber
//
//   - 4-byte RequestId. The remaining bytes are the per-
//     service request/response, surfaced as `service_body_hex`.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Network framing** — feed OPC UA Binary bytes after the
//     TCP-segment header strip (default TCP port 4840; OPC UA
//     over TLS on TCP port 4843 wraps the same Binary encoding
//     in TLS records — handle the TLS strip first).
//   - **OPC UA HTTPS (REST)** / **OPC UA WebSocket** — separate
//     transport mappings (IEC 62541-6 §7.2 + §7.3) that re-use
//     the same Binary encoding inside HTTP bodies / WS frames;
//     out of scope here.
//   - **OPC UA over UA-XML / UA-JSON** — XML-based encoding
//     (legacy) + JSON-based encoding (UA 1.04+ for cloud-bound
//     historians); separate decoders.
//   - **Per-service request/response decoder** — the 30+ catalogued
//     UA Services (CreateSession, ActivateSession, CloseSession,
//     Read, Write, HistoryRead, HistoryUpdate, Browse,
//     BrowseNext, TranslateBrowsePathsToNodeIds, Call,
//     CreateMonitoredItems, ModifyMonitoredItems,
//     DeleteMonitoredItems, CreateSubscription, ModifySubscription,
//     DeleteSubscriptions, Publish, Republish, ...) are encoded
//     as BINARY structured types per IEC 62541-6 §5; each service
//     body carries a 4-byte NodeId identifying the service +
//     RequestHeader + per-service parameters. The decoder surfaces
//     `service_body_hex` for future per-service walkers and the
//     OpcUaSecurityPolicyUri name on OPN messages.
//   - **Cryptography** — the SecurityPolicyUri identifies the
//     algorithm suite (Basic128Rsa15, Basic256, Basic256Sha256,
//     Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss) but key
//     derivation, AES-CBC body encryption, and HMAC-SHA1/SHA256
//     signature verification are higher-level work.
//   - **Chunk reassembly** — when ChunkType is `C` (Intermediate),
//     the sender will follow with more chunks until a `F` Final
//     arrives; the decoder reports the per-message ChunkType but
//     does not reassemble across input messages.
//   - **Session state-machine reasoning** — SecureChannel renewal,
//     Session activation, Subscription keep-alive, Publish queue
//     bookkeeping; higher-level analysis.
package opcua

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the structured decode of an OPC UA Binary message.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// Message header
	MessageType     string `json:"message_type"`
	MessageTypeName string `json:"message_type_name"`
	ChunkType       string `json:"chunk_type"`
	ChunkTypeName   string `json:"chunk_type_name"`
	MessageSize     uint32 `json:"message_size"`

	// HEL / ACK
	ProtocolVersion   uint32 `json:"protocol_version,omitempty"`
	ReceiveBufferSize uint32 `json:"receive_buffer_size,omitempty"`
	SendBufferSize    uint32 `json:"send_buffer_size,omitempty"`
	MaxMessageSize    uint32 `json:"max_message_size,omitempty"`
	MaxChunkCount     uint32 `json:"max_chunk_count,omitempty"`
	EndpointURL       string `json:"endpoint_url,omitempty"`

	// ERR
	StatusCodeHex string `json:"status_code_hex,omitempty"`
	Reason        string `json:"reason,omitempty"`

	// MSG / OPN / CLO
	SecureChannelID       uint32 `json:"secure_channel_id,omitempty"`
	SecurityPolicyURI     string `json:"security_policy_uri,omitempty"`
	SenderCertificateHex  string `json:"sender_certificate_hex,omitempty"`
	ReceiverThumbprintHex string `json:"receiver_certificate_thumbprint_hex,omitempty"`
	TokenID               uint32 `json:"token_id,omitempty"`
	SequenceNumber        uint32 `json:"sequence_number,omitempty"`
	RequestID             uint32 `json:"request_id,omitempty"`

	// Trailing per-Service request/response bytes.
	ServiceBodyHex string `json:"service_body_hex,omitempty"`
}

// Decode parses an OPC UA Binary message from a hex string
// starting at the 3-byte MessageType field. Separators (':' '-'
// '_' whitespace) tolerated; '0x' prefix tolerated.
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
	if len(b) < 8 {
		return nil, fmt.Errorf("OPC UA message truncated (%d bytes; need ≥8 for header)",
			len(b))
	}

	r := &Result{
		TotalBytes:  len(b),
		MessageType: string(b[0:3]),
		ChunkType:   string(b[3:4]),
		MessageSize: binary.LittleEndian.Uint32(b[4:8]),
	}
	r.MessageTypeName = messageTypeName(r.MessageType)
	r.ChunkTypeName = chunkTypeName(r.ChunkType)

	body := b[8:]
	switch r.MessageType {
	case "HEL":
		decodeHELBody(r, body)
	case "ACK":
		decodeACKBody(r, body)
	case "ERR":
		decodeERRBody(r, body)
	case "OPN":
		decodeOPNBody(r, body)
	case "MSG", "CLO":
		decodeMSGBody(r, body)
	default:
		if len(body) > 0 {
			r.ServiceBodyHex = strings.ToUpper(hex.EncodeToString(body))
		}
	}
	return r, nil
}

func decodeHELBody(r *Result, b []byte) {
	if len(b) < 20 {
		return
	}
	r.ProtocolVersion = binary.LittleEndian.Uint32(b[0:4])
	r.ReceiveBufferSize = binary.LittleEndian.Uint32(b[4:8])
	r.SendBufferSize = binary.LittleEndian.Uint32(b[8:12])
	r.MaxMessageSize = binary.LittleEndian.Uint32(b[12:16])
	r.MaxChunkCount = binary.LittleEndian.Uint32(b[16:20])
	s, _ := readUAString(b[20:])
	r.EndpointURL = s
}

func decodeACKBody(r *Result, b []byte) {
	if len(b) < 20 {
		return
	}
	r.ProtocolVersion = binary.LittleEndian.Uint32(b[0:4])
	r.ReceiveBufferSize = binary.LittleEndian.Uint32(b[4:8])
	r.SendBufferSize = binary.LittleEndian.Uint32(b[8:12])
	r.MaxMessageSize = binary.LittleEndian.Uint32(b[12:16])
	r.MaxChunkCount = binary.LittleEndian.Uint32(b[16:20])
}

func decodeERRBody(r *Result, b []byte) {
	if len(b) < 4 {
		return
	}
	r.StatusCodeHex = fmt.Sprintf("0x%08X", binary.LittleEndian.Uint32(b[0:4]))
	if len(b) >= 8 {
		reason, _ := readUAString(b[4:])
		r.Reason = reason
	}
}

// decodeOPNBody parses an OpenSecureChannel asymmetric security
// header — the only message type that carries the certificate
// material that identifies the secure channel's algorithm
// suite + endpoint trust.
func decodeOPNBody(r *Result, b []byte) {
	if len(b) < 4 {
		return
	}
	off := 0
	r.SecureChannelID = binary.LittleEndian.Uint32(b[off : off+4])
	off += 4
	uri, n := readUAString(b[off:])
	r.SecurityPolicyURI = uri
	off += n
	cert, n2 := readUAByteString(b[off:])
	r.SenderCertificateHex = cert
	off += n2
	thumb, n3 := readUAByteString(b[off:])
	r.ReceiverThumbprintHex = thumb
	off += n3
	if off+8 > len(b) {
		return
	}
	r.SequenceNumber = binary.LittleEndian.Uint32(b[off : off+4])
	r.RequestID = binary.LittleEndian.Uint32(b[off+4 : off+8])
	off += 8
	if off < len(b) {
		r.ServiceBodyHex = strings.ToUpper(hex.EncodeToString(b[off:]))
	}
}

// decodeMSGBody parses the symmetric secure-channel header for
// MSG + CLO messages (4-byte SecureChannelId + 4-byte TokenId +
// 4-byte SequenceNumber + 4-byte RequestId).
func decodeMSGBody(r *Result, b []byte) {
	if len(b) < 16 {
		return
	}
	r.SecureChannelID = binary.LittleEndian.Uint32(b[0:4])
	r.TokenID = binary.LittleEndian.Uint32(b[4:8])
	r.SequenceNumber = binary.LittleEndian.Uint32(b[8:12])
	r.RequestID = binary.LittleEndian.Uint32(b[12:16])
	if len(b) > 16 {
		r.ServiceBodyHex = strings.ToUpper(hex.EncodeToString(b[16:]))
	}
}

// readUAString reads a UA String (4-byte length LE + UTF-8 bytes);
// returns (string, bytes consumed). Null string (length = -1)
// returns ("", 4).
func readUAString(b []byte) (string, int) {
	if len(b) < 4 {
		return "", 0
	}
	length := int32(binary.LittleEndian.Uint32(b[0:4]))
	if length < 0 {
		return "", 4
	}
	if 4+int(length) > len(b) {
		return "", 0
	}
	return string(b[4 : 4+int(length)]), 4 + int(length)
}

// readUAByteString reads a UA ByteString (4-byte length LE +
// bytes); returns (hex-encoded value, bytes consumed). Null
// byte string (length = -1) returns ("", 4).
func readUAByteString(b []byte) (string, int) {
	if len(b) < 4 {
		return "", 0
	}
	length := int32(binary.LittleEndian.Uint32(b[0:4]))
	if length < 0 {
		return "", 4
	}
	if 4+int(length) > len(b) {
		return "", 0
	}
	return strings.ToUpper(hex.EncodeToString(b[4 : 4+int(length)])), 4 + int(length)
}

func messageTypeName(t string) string {
	switch t {
	case "HEL":
		return "Hello"
	case "ACK":
		return "Acknowledge"
	case "ERR":
		return "Error"
	case "MSG":
		return "Message"
	case "OPN":
		return "OpenSecureChannel"
	case "CLO":
		return "CloseSecureChannel"
	case "RHE":
		return "ReverseHello"
	}
	return fmt.Sprintf("uncatalogued MessageType %q", t)
}

func chunkTypeName(c string) string {
	switch c {
	case "F":
		return "Final"
	case "C":
		return "Intermediate"
	case "A":
		return "Abort"
	}
	return fmt.Sprintf("uncatalogued ChunkType %q", c)
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
