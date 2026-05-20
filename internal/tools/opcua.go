// opcua.go — host-side OPC UA Binary message decoder Spec.
// Wraps the internal/opcua walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/opcua"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(opcuaDecodeSpec)
}

var opcuaDecodeSpec = Spec{
	Name: "opcua_decode",
	Description: "Decode an OPC UA Binary message per IEC 62541-6 (OPC Unified " +
		"Architecture, Part 6: Mappings). OPC UA is the modern industrial-" +
		"messaging protocol that supersedes OPC Classic (DCOM-based) and is the " +
		"vendor-neutral lingua franca of MES, SCADA, historian, and IIoT gateway " +
		"stacks on the current-generation factory floor. Sits ABOVE the field-" +
		"protocol family (Modbus / S7Comm / DNP3 / IEC 104 / CIP / Profinet) as " +
		"the application-layer protocol an MES or SCADA layer speaks to harvest " +
		"values from any of them. Every modern PLC + DCS + edge gateway (Siemens " +
		"S7-1500, Rockwell ControlLogix, Schneider M580, Beckhoff TwinCAT, B&R, " +
		"ABB, Yokogawa) ships a built-in OPC UA server; cloud-bound historians " +
		"(PI System, Cognite Data Fusion, AWS IoT SiteWise, Azure Industrial IoT) " +
		"ship OPC UA clients. Default TCP port 4840 (4843 for OPC UA over TLS). " +
		"Decodes:\n\n" +
		"- **Message header** (IEC 62541-6 §7.1.2, 8 bytes, little-endian where " +
		"multi-byte): 3-byte ASCII MessageType + 1-byte ASCII ChunkType + 4-byte " +
		"MessageSize (uint32 LE; total bytes INCLUDING this 8-byte header).\n" +
		"- **7-entry MessageType name table**: HEL Hello / ACK Acknowledge / ERR " +
		"Error / MSG Message (UA Service request/response under a secure channel) " +
		"/ OPN OpenSecureChannel / CLO CloseSecureChannel / RHE ReverseHello " +
		"(server-initiated connection establishment).\n" +
		"- **3-entry ChunkType name table**: F Final / C Intermediate Chunk / A " +
		"Abort.\n" +
		"- **HEL body** (the first message in every session): ProtocolVersion + " +
		"ReceiveBufferSize + SendBufferSize + MaxMessageSize + MaxChunkCount + " +
		"UA String EndpointURL.\n" +
		"- **ACK body** (server agrees on buffer sizes): mirrors HEL minus the " +
		"EndpointURL.\n" +
		"- **ERR body** (server returns a fatal error): StatusCode (IEC 62541-4 " +
		"§7.34 OPC UA status code) + UA String Reason.\n" +
		"- **OPN body** (OpenSecureChannel asymmetric security header): " +
		"SecureChannelId + UA String SecurityPolicyUri + UA ByteString " +
		"SenderCertificate + UA ByteString ReceiverCertificateThumbprint + " +
		"SequenceNumber + RequestId + opaque OpenSecureChannelRequest/Response " +
		"service body (surfaced as service_body_hex).\n" +
		"- **MSG / CLO body** (symmetric secure channel header): SecureChannelId " +
		"+ TokenId + SequenceNumber + RequestId + opaque per-service request/" +
		"response body (surfaced as service_body_hex).\n\n" +
		"Pure offline parser — operators paste OPC UA Binary bytes (starting at " +
		"the 3-byte MessageType field) from a `tcpdump -X port 4840` line or a " +
		"Wireshark OPC UA dissector view and get the documented header + per-" +
		"MessageType body breakdown.\n\n" +
		"Out of scope (deferred): network framing (feed OPC UA Binary bytes " +
		"after the TCP-segment header strip; OPC UA over TLS on TCP/4843 wraps " +
		"the same Binary encoding in TLS records — handle the TLS strip first); " +
		"OPC UA HTTPS REST + OPC UA WebSocket (separate transport mappings — IEC " +
		"62541-6 §7.2 + §7.3 — that re-use the same Binary encoding inside HTTP " +
		"bodies / WS frames; out of scope here); OPC UA over UA-XML / UA-JSON " +
		"(legacy XML-based encoding + UA 1.04+ JSON-based encoding for cloud-" +
		"bound historians; separate decoders); per-service request/response " +
		"decoder (the 30+ catalogued UA Services — CreateSession / " +
		"ActivateSession / Read / Write / HistoryRead / Browse / Call / " +
		"CreateMonitoredItems / CreateSubscription / Publish ... — are encoded " +
		"as BINARY structured types per IEC 62541-6 §5 with NodeId + " +
		"RequestHeader + per-service parameters; the decoder surfaces " +
		"service_body_hex for future per-service walkers); cryptography (the " +
		"SecurityPolicyUri identifies the algorithm suite — Basic128Rsa15, " +
		"Basic256, Basic256Sha256, Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss " +
		"— but key derivation, AES-CBC body encryption, and HMAC-SHA1/SHA256 " +
		"signature verification are higher-level work); chunk reassembly (when " +
		"ChunkType is C/Intermediate, the sender will follow with more chunks " +
		"until an F/Final arrives; reports per-message ChunkType but does not " +
		"reassemble across input messages); session state-machine reasoning " +
		"(SecureChannel renewal, Session activation, Subscription keep-alive, " +
		"Publish queue bookkeeping — higher-level analysis).\n\n" +
		"Source: docs/catalog/gap-analysis.md (modern industrial-messaging " +
		"dissector — sits ABOVE the field-protocol family already covered by " +
		"modbus_decode / dnp3_decode / iec104_decode / s7comm_decode / enip_decode " +
		"/ profinet_dcp_decode; targets DEF CON ICS Village CTFs + modern factory " +
		"+ DCS pentest engagements + cloud historian ingestion traffic). Wrap-vs-" +
		"native: native — IEC 62541-6 is publicly documented and the open62541 " +
		"+ UA-.NETStandard reference implementations are open source; the message " +
		"header is a tight 8 bytes followed by a per-MessageType body; no crypto " +
		"at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"OPC UA Binary message bytes starting at the 3-byte MessageType field (after the TCP-segment header strip; default TCP port 4840; OPC UA over TLS on TCP/4843 wraps the same Binary encoding in TLS records — handle the TLS strip first). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   opcuaDecodeHandler,
}

func opcuaDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("opcua_decode: 'hex' is required")
	}
	res, err := opcua.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("opcua_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
