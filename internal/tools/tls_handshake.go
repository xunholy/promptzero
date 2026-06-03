// tls_handshake.go — host-side TLS ClientHello / ServerHello
// dissector Spec, delegating to the internal/tlsdecode
// package for the walker proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/tlsdecode"
)

func init() { //nolint:gochecknoinits
	Register(tlsHandshakeDecodeSpec)
}

var tlsHandshakeDecodeSpec = Spec{
	Name: "tls_handshake_decode",
	Description: "Decode the cleartext portion of a TLS handshake — the ClientHello and " +
		"ServerHello records that every TLS connection emits in the clear before encryption " +
		"is negotiated. Per RFC 5246 (TLS 1.2), RFC 8446 (TLS 1.3), and the IANA TLS " +
		"registries. Workhorse pcap-and-paste primitive for SOC blue-team analysis (JA3 " +
		"fingerprinting, plaintext SNI extraction, ALPN inspection), threat-intel triage " +
		"(cipher-suite weakness scanning, version downgrade detection), and offensive recon " +
		"(server-preference fingerprinting, client-stack identification). Decodes:\n\n" +
		"- **TLS record layer envelope**: ContentType (Handshake / ChangeCipherSpec / Alert / " +
		"ApplicationData / Heartbeat), Version (with TLS 1.0..1.3 name lookup), Length. " +
		"Multiple back-to-back records in one buffer are supported.\n" +
		"- **Handshake message dispatch**: ClientHello, ServerHello, HelloRetryRequest, " +
		"NewSessionTicket, EndOfEarlyData, EncryptedExtensions, Certificate, " +
		"CertificateRequest, CertificateVerify, Finished, KeyUpdate, MessageHash — every " +
		"type named; bodies for non-Hello messages surfaced as raw hex.\n" +
		"- **ClientHello body**: legacy_version, random (32 bytes), legacy_session_id, " +
		"cipher_suites with IANA name lookup for ~80 suites (all current TLS 1.3 suites + " +
		"the most-deployed TLS 1.2 ECDHE-ECDSA / ECDHE-RSA / DHE-RSA suites + the deprecated " +
		"RSA / 3DES / CBC legacy suites still found in older captures), compression methods, " +
		"and extensions.\n" +
		"- **ServerHello body**: same field layout but with single selected cipher suite + " +
		"compression method + negotiated extensions.\n" +
		"- **Extension dispatch** with type-name lookup for ~30 IANA-registered extensions, " +
		"plus deep decode for the operationally-important ones:\n" +
		"  - **server_name (type 0, SNI)**: extracts the requested host name (the single " +
		"most valuable plaintext field — identifies which domain a TLS client is " +
		"connecting to even when DNS is encrypted with DoH/DoT).\n" +
		"  - **supported_groups (type 10)**: list of named curves / DH groups with name " +
		"lookup (x25519, x448, secp256r1/P-256, secp384r1/P-384, ffdhe2048, post-quantum " +
		"hybrids like x25519_kyber768_draft00).\n" +
		"  - **signature_algorithms (type 13)**: SignatureScheme codes (rsa_pkcs1_sha256, " +
		"ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, ed25519, etc.).\n" +
		"  - **application_layer_protocol_negotiation (type 16, ALPN)**: list of protocol " +
		"strings (h2, http/1.1, http/0.9, h3, etc.).\n" +
		"  - **supported_versions (type 43)**: the canonical TLS 1.3 version-negotiation " +
		"extension.\n" +
		"  - **key_share (type 51)**: list of (group, key) pairs with the group name " +
		"surfaced.\n" +
		"- **JA3 fingerprint** (per the Salesforce/John Althouse spec): the comma-separated " +
		"string 'TLSVersion,CipherSuites,Extensions,SupportedGroups,EcPointFormats' with " +
		"hyphens between list members, plus its MD5 hash. GREASE values (RFC 8701: 0x?A?A) " +
		"are stripped automatically. The JA3 client fingerprint identifies the TLS client " +
		"stack (browser, library, malware family) across thousands of distinct signatures " +
		"and is the standard input for SOC TLS-anomaly detection.\n\n" +
		"Pure offline parser — operators paste a hex blob extracted from a Wireshark TLS " +
		"frame, a tcpdump-of-443 capture, or a tshark `tls.handshake` field and inspect " +
		"every plaintext field without re-attaching to the network. Complements the " +
		"existing ieee80211_* and dns coverage with the missing read-side primitive for " +
		"the most-traffic-bearing application-layer protocol on the internet.\n\n" +
		"The TLS 1.2 Certificate handshake message is decoded: each DER cert in the chain " +
		"is run through the X.509 decoder, surfacing subject / issuer / validity / SAN / " +
		"fingerprints (the TLS 1.3 Certificate message is encrypted on the wire and so is " +
		"not present in a passive capture).\n\n" +
		"Out of scope (deferred to future iterations): JA4 / JA4S / JA4H / JA4X fingerprinting " +
		"(newer FoxIO scheme), TLS 1.3 inner-handshake (encrypted on the wire without " +
		"session keys), DTLS (Datagram TLS over UDP).\n\n" +
		"Source: docs/catalog/gap-analysis.md (network-protocol decode space — TLS is the " +
		"most-traffic-bearing app-layer protocol). Wrap-vs-native: native — RFC 5246 + RFC " +
		"8446 + IANA TLS registries are fully public, every field is fixed-format integer " +
		"or length-prefixed byte string, dispatch is a switch.\n\n" +
		"Accepts ':' / '-' / '_' / whitespace separators and a leading '0x' prefix.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded TLS record-layer bytes. One or more back-to-back records (each starting with content_type + version + length). Most commonly a single TLS Handshake record carrying a ClientHello or ServerHello. ':' / '-' / '_' / whitespace separators tolerated; '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   tlsHandshakeDecodeHandler,
}

func tlsHandshakeDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("tls_handshake_decode: 'hex' is required")
	}
	res, err := tlsdecode.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("tls_handshake_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
