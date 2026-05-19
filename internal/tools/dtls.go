// dtls.go — host-side DTLS record + handshake decoder Spec.
// Wraps the internal/dtls walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/dtls"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(dtlsRecordDecodeSpec)
}

var dtlsRecordDecodeSpec = Spec{
	Name: "dtls_record_decode",
	Description: "Decode one or more concatenated DTLS records per RFC 6347 (DTLS 1.2) " +
		"and RFC 9147 (DTLS 1.3 legacy-form). DTLS is the UDP equivalent of TLS — " +
		"used by WebRTC's DTLS-SRTP media key exchange (every video/voice call in " +
		"Chrome / Safari / Firefox), OpenVPN UDP mode, CoAP-over-DTLS for IoT " +
		"deployments, QUIC's connection setup (legacy), and many embedded-device " +
		"protocols. Natural pair to `tls_handshake_decode`. Decodes:\n\n" +
		"- **Record layer** (13 bytes fixed, RFC 6347 §4.1): ContentType (1 byte) + " +
		"Version (2 bytes) + Epoch (2 bytes BE — incremented on each cipher state " +
		"change) + Sequence Number (6 bytes BE — replay-protection nonce) + Length " +
		"(2 bytes BE) + Fragment (Length bytes). The walker iterates concatenated " +
		"records until the buffer is consumed.\n" +
		"- **5 Content Types**: 20 ChangeCipherSpec / 21 Alert / 22 Handshake / " +
		"23 ApplicationData / 24 Heartbeat (RFC 6520 — yes, that one).\n" +
		"- **3 Version values**: 0xFEFF DTLS 1.0 / 0xFEFD DTLS 1.2 / 0xFEFC DTLS 1.3.\n" +
		"- **Alert body**: Level (1 warning / 2 fatal) + Description with **23-entry " +
		"name table** (close_notify, unexpected_message, bad_record_mac, " +
		"decryption_failed, record_overflow, decompression_failure, handshake_failure, " +
		"no_certificate, bad_certificate, unsupported_certificate, certificate_revoked, " +
		"certificate_expired, certificate_unknown, illegal_parameter, unknown_ca, " +
		"access_denied, decode_error, decrypt_error, export_restriction, " +
		"protocol_version, insufficient_security, internal_error, user_canceled, " +
		"no_renegotiation, unsupported_extension).\n" +
		"- **Handshake message header** (12 bytes fixed, RFC 6347 §4.2.2): MsgType " +
		"+ Length (3 bytes BE total reassembled length) + MessageSeq + " +
		"FragmentOffset + FragmentLength. The walker marks `is_fragmented=true` when " +
		"offset≠0 or fragment_length≠total_length.\n" +
		"- **13 Handshake message types**: 0 HelloRequest, 1 ClientHello, 2 " +
		"ServerHello, 3 HelloVerifyRequest (DTLS-specific cookie exchange), 4 " +
		"NewSessionTicket, 8 EncryptedExtensions (TLS 1.3), 11 Certificate, 12 " +
		"ServerKeyExchange, 13 CertificateRequest, 14 ServerHelloDone, 15 " +
		"CertificateVerify, 16 ClientKeyExchange, 20 Finished.\n" +
		"- **ClientHello body** dissected: legacy_version + 32-byte random + " +
		"session_id (length-prefixed) + cookie (length-prefixed, DTLS-specific) + " +
		"cipher_suites (count + raw hex) + compression_methods (count + raw hex) + " +
		"extensions (length + raw hex).\n" +
		"- **ServerHello body** dissected: legacy_version + random + session_id + " +
		"selected cipher_suite (uint16 BE) + selected compression_method + " +
		"extensions.\n" +
		"- **HelloVerifyRequest body** dissected: server_version + cookie. This is " +
		"the hallmark of DTLS's stateless cookie exchange that mitigates UDP " +
		"amplification DoS.\n" +
		"- **Heartbeat body** (RFC 6520): MessageType (1 Request / 2 Response) + " +
		"declared PayloadLength + actual remaining bytes. **Heartbleed (CVE-2014-" +
		"0160) detection**: when declared payload_length exceeds the actual " +
		"remaining bytes, a `heartbleed_hint` field is emitted explaining the " +
		"information-disclosure pattern.\n" +
		"- **Multi-record walker** — one UDP datagram may carry multiple " +
		"concatenated records; the walker iterates record-by-record and emits a " +
		"summary string (e.g. 'ClientHello + HelloVerifyRequest').\n\n" +
		"Pure offline parser — operators paste UDP payload bytes from a Wireshark " +
		"Follow-UDP-Stream view, a `tcpdump -X udp port 443` line, a `tcpdump -X udp " +
		"port 5061` SIPS-over-DTLS capture, a WebRTC traffic dump, or any DTLS-" +
		"emitting tool and inspect every documented field.\n\n" +
		"Out of scope (deferred): decryption (operators need session keys exported " +
		"from the handshake; ciphertext surfaced as hex); DTLS 1.3 unified-header " +
		"records (RFC 9147 §4 — ultra-compact 8-bit-tag variant; future Spec); full " +
		"TLS extension dissection (SNI / ALPN / supported_groups / signature_" +
		"algorithms / key_share — extension bodies surfaced as hex; the catalogue is " +
		"in `tls_handshake_decode`); X.509 certificate decoding inside Certificate " +
		"handshake messages (surfaced as hex; `x509_certificate_decode` can be fed " +
		"each ASN.1 cert blob); UDP / IP framing.\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational security protocol — " +
		"DTLS is the UDP equivalent of TLS, used by WebRTC / OpenVPN / CoAP / IoT " +
		"deployments). Wrap-vs-native: native — both DTLS RFCs are fully public; " +
		"wire format is a tight fixed-layout binary record header plus a well-" +
		"documented handshake-message catalogue.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"DTLS UDP-payload bytes as hex. May contain multiple concatenated records. Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   dtlsRecordDecodeHandler,
}

func dtlsRecordDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("dtls_record_decode: 'hex' is required")
	}
	res, err := dtls.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("dtls_record_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
