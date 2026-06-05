// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tlsdecode decodes the cleartext portion of a TLS
// handshake — the ClientHello and ServerHello records that
// every TLS connection emits in the clear before encryption
// is negotiated. This is the workhorse pcap-and-paste tool
// for SOC blue-team analysis (JA3 / JA4 fingerprinting,
// plaintext SNI extraction, ALPN inspection), threat-intel
// triage (cipher-suite weakness scanning, version
// downgrade detection), and offensive recon (server
// preference fingerprinting, client-stack identification).
//
// # Wrap-vs-native judgement
//
// Native. The TLS record layer and handshake messages are
// fully published in RFC 5246 (TLS 1.2), RFC 8446 (TLS 1.3),
// and the IANA TLS registries. Every field is a fixed-length
// integer, length-prefixed byte string, or list. Extension
// dispatch is a switch over a 2-byte type. Pasting a hex
// blob extracted from a Wireshark TLS frame, a tcpdump-of-
// 443 capture, or a tshark `tls.handshake` field is enough
// — no cryptography (the cleartext portion is the entire
// scope), no key material, no live network attach.
//
// # What this package covers
//
//   - TLS record layer envelope: ContentType (Handshake /
//     ChangeCipherSpec / Alert / ApplicationData), Version
//     (major + minor, with TLS 1.0..1.3 name lookup), Length.
//     Multiple back-to-back records in one buffer are
//     supported.
//   - Handshake message dispatch: ClientHello, ServerHello,
//     HelloRetryRequest, NewSessionTicket, EndOfEarlyData,
//     EncryptedExtensions, Certificate, CertificateRequest,
//     CertificateVerify, Finished, KeyUpdate, MessageHash.
//     Bodies for non-ClientHello / non-ServerHello messages
//     are surfaced as raw hex.
//   - ClientHello body: legacy_version, random (32 bytes),
//     legacy_session_id, cipher_suites (with IANA name
//     lookup for ~80 suites covering all current TLS 1.3
//     suites + the most-deployed TLS 1.2 suites including
//     ECDHE-RSA-AES, ECDHE-ECDSA-AES, ChaCha20-Poly1305,
//     and the deprecated-but-still-seen RSA / 3DES / CBC
//     legacy suites), compression_methods, extensions.
//   - ServerHello body: same field layout as ClientHello but
//     with single selected cipher suite + compression
//     method.
//   - Extension dispatch with type-name lookup for ~30 IANA-
//     registered extensions. Deep decode for the
//     operationally-important ones:
//   - server_name (type 0): extracts the SNI value
//     (only host_name name_type 0 is in scope).
//   - supported_groups (type 10): list of named curves
//     / DH groups with name lookup.
//   - signature_algorithms (type 13): list of
//     SignatureScheme codes with name lookup.
//   - application_layer_protocol_negotiation (type 16,
//     ALPN): list of protocol strings (h2, http/1.1,
//     etc.).
//   - supported_versions (type 43): the canonical TLS
//     1.3 version-negotiation extension.
//   - key_share (type 51): list of (group, key) pairs
//     with the group name surfaced.
//   - **JA3 fingerprint** (per the Salesforce / John Althouse
//     spec): the comma-separated string
//     "version,cipher_suites,extensions,curves,
//     ec_point_formats" with hyphens between list members,
//     plus its MD5 hash. The standard JA3 client fingerprint
//     identifies the TLS client stack (browser, library,
//     malware family) across thousands of distinct signatures.
//   - **JA4 fingerprint** (FoxIO LLC, the modern successor to
//     JA3): protocol + TLS version + SNI flag + cipher/extension
//     counts + ALPN, then truncated SHA-256 of the sorted cipher
//     list and of the sorted extensions + signature_algorithms.
//     GREASE values are ignored throughout. Verified byte-for-byte
//     against the FoxIO worked example.
//   - **JA4S fingerprint** (FoxIO, server side): from the
//     ServerHello — protocol + TLS version + extension count +
//     chosen ALPN, the negotiated cipher, and the truncated
//     SHA-256 of the server's extensions in WIRE ORDER (not
//     sorted — the server's extension order is itself the
//     fingerprint signal). Pairs with the client JA4 to
//     fingerprint both ends of a session. Verified byte-for-byte
//     against FoxIO snapshot outputs.
//
// # Certificate handshake message
//
// The TLS 1.2 (and earlier) Certificate handshake message is decoded: the
// certificate_list is walked and each DER certificate is chained through
// internal/x509decode to surface subject / issuer / validity / SAN /
// fingerprints / CA flag — so a captured handshake yields the server's cert
// chain in one decode. In TLS 1.3 the Certificate message is encrypted, so the
// plaintext form seen in a passive capture is the pre-1.3 layout decoded here;
// a body that doesn't match it is reported with a note, never mis-parsed.
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - Encrypted ApplicationData / CCS / Alert bodies: the
//     record envelope is decoded but the post-handshake
//     ciphertext is opaque without key material.
//     (The JA4X X.509 fingerprint is computed for each cert in
//     the chain by internal/x509decode, and the JA4H HTTP-client
//     fingerprint by internal/httpmsg — so the whole JA4+ family
//     JA4 / JA4S / JA4X / JA4H is now covered across the stack.)
//   - TLS 1.3 inner handshake (EncryptedExtensions onward)
//     is encrypted on the wire and requires session-key
//     material that this Spec deliberately does not handle.
//   - DTLS (Datagram TLS over UDP) — slight envelope
//     differences (record sequence number); deferred.
package tlsdecode

import (
	"crypto/md5"    //nolint:gosec // JA3 hash is defined as MD5 by spec.
	"crypto/sha256" // JA4 hash is defined as SHA-256 by spec.
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/xunholy/promptzero/internal/x509decode"
)

// Frame is a list of decoded TLS records — TCP segments often
// pack multiple back-to-back records, so the top-level result
// is always a slice.
type Frame struct {
	Records []*Record `json:"records"`
}

// Record is one TLS record-layer frame.
type Record struct {
	ContentType  int          `json:"content_type"`
	ContentName  string       `json:"content_name"`
	VersionMajor int          `json:"version_major"`
	VersionMinor int          `json:"version_minor"`
	VersionName  string       `json:"version_name"`
	Length       int          `json:"length"`
	Handshakes   []*Handshake `json:"handshakes,omitempty"`
	BodyHex      string       `json:"body_hex,omitempty"`
}

// Handshake is one TLS handshake message inside a record.
type Handshake struct {
	MessageType int          `json:"message_type"`
	MessageName string       `json:"message_name"`
	Length      int          `json:"length"`
	ClientHello *ClientHello `json:"client_hello,omitempty"`
	ServerHello *ServerHello `json:"server_hello,omitempty"`
	Certificate *Certificate `json:"certificate,omitempty"`
	BodyHex     string       `json:"body_hex,omitempty"`
}

// Certificate is a decoded TLS Certificate handshake message (the
// TLS 1.2 / TLS 1.0-1.1 form: a 3-byte certificate_list length followed by
// 3-byte-length-prefixed DER certificates). In TLS 1.3 the Certificate
// message is encrypted (sent after the handshake keys are derived), so the
// plaintext form visible in a passive capture is the pre-1.3 layout decoded
// here; a body that does not match it (e.g. a decrypted 1.3 message with its
// request-context prefix and per-certificate extensions) is reported with a
// note rather than mis-parsed.
type Certificate struct {
	CertificateCount int          `json:"certificate_count"`
	Certificates     []*CertEntry `json:"certificates,omitempty"`
	Notes            []string     `json:"notes,omitempty"`
}

// CertEntry is one certificate from the chain, decoded via internal/x509decode.
type CertEntry struct {
	Length      int                     `json:"length"`
	Certificate *x509decode.Certificate `json:"x509,omitempty"`
	DERHex      string                  `json:"der_hex,omitempty"`
	DecodeError string                  `json:"decode_error,omitempty"`
}

// ClientHello is the decoded TLS ClientHello body.
type ClientHello struct {
	VersionMajor        int           `json:"version_major"`
	VersionMinor        int           `json:"version_minor"`
	VersionName         string        `json:"version_name"`
	RandomHex           string        `json:"random_hex"`
	SessionIDHex        string        `json:"session_id_hex"`
	CipherSuites        []CipherSuite `json:"cipher_suites"`
	CompressionMethods  []int         `json:"compression_methods"`
	Extensions          []*Extension  `json:"extensions,omitempty"`
	ServerName          string        `json:"server_name,omitempty"`
	ALPNProtocols       []string      `json:"alpn_protocols,omitempty"`
	SupportedVersions   []string      `json:"supported_versions,omitempty"`
	SupportedGroups     []string      `json:"supported_groups,omitempty"`
	SignatureAlgorithms []string      `json:"signature_algorithms,omitempty"`
	KeyShareGroups      []string      `json:"key_share_groups,omitempty"`
	JA3                 string        `json:"ja3,omitempty"`
	JA3Hash             string        `json:"ja3_hash,omitempty"`
	JA4                 string        `json:"ja4,omitempty"`
}

// ServerHello is the decoded TLS ServerHello body. Same shape
// as ClientHello but with a single selected cipher suite +
// compression method.
type ServerHello struct {
	VersionMajor      int          `json:"version_major"`
	VersionMinor      int          `json:"version_minor"`
	VersionName       string       `json:"version_name"`
	RandomHex         string       `json:"random_hex"`
	SessionIDHex      string       `json:"session_id_hex"`
	CipherSuite       CipherSuite  `json:"cipher_suite"`
	CompressionMethod int          `json:"compression_method"`
	Extensions        []*Extension `json:"extensions,omitempty"`
	NegotiatedALPN    string       `json:"negotiated_alpn,omitempty"`
	NegotiatedVersion string       `json:"negotiated_version,omitempty"`
	JA4S              string       `json:"ja4s,omitempty"`
}

// CipherSuite is one TLS cipher suite reference.
type CipherSuite struct {
	Value uint16 `json:"value"`
	Hex   string `json:"hex"`
	Name  string `json:"name,omitempty"`
}

// Extension is one TLS extension.
type Extension struct {
	Type     int    `json:"type"`
	TypeName string `json:"type_name"`
	Length   int    `json:"length"`
	DataHex  string `json:"data_hex,omitempty"`
}

// Decode parses a hex-encoded buffer of one or more TLS
// records.
func Decode(hexBlob string) (*Frame, error) {
	b, err := parseHex(hexBlob)
	if err != nil {
		return nil, err
	}
	return DecodeBytes(b)
}

// DecodeBytes parses raw TLS record bytes — one or more
// back-to-back records.
func DecodeBytes(b []byte) (*Frame, error) {
	if len(b) < 5 {
		return nil, fmt.Errorf("tlsdecode: input too short (%d bytes) — TLS record header alone is 5 bytes", len(b))
	}
	f := &Frame{}
	off := 0
	for off+5 <= len(b) {
		rec, err := decodeRecord(b[off:])
		if err != nil {
			return nil, fmt.Errorf("tlsdecode: record at offset %d: %w", off, err)
		}
		f.Records = append(f.Records, rec)
		off += 5 + rec.Length
	}
	if off != len(b) {
		return nil, fmt.Errorf("tlsdecode: %d trailing bytes after last record at offset %d", len(b)-off, off)
	}
	return f, nil
}

func decodeRecord(b []byte) (*Record, error) {
	ct := int(b[0])
	verMajor := int(b[1])
	verMinor := int(b[2])
	length := int(b[3])<<8 | int(b[4])
	if 5+length > len(b) {
		return nil, fmt.Errorf("record length %d exceeds buffer (%d available)", length, len(b)-5)
	}
	r := &Record{
		ContentType:  ct,
		ContentName:  contentTypeName(ct),
		VersionMajor: verMajor,
		VersionMinor: verMinor,
		VersionName:  versionName(verMajor, verMinor),
		Length:       length,
	}
	body := b[5 : 5+length]
	switch ct {
	case 22: // Handshake
		off := 0
		for off+4 <= len(body) {
			hs, used, err := decodeHandshake(body[off:])
			if err != nil {
				return nil, fmt.Errorf("handshake at record offset %d: %w", off, err)
			}
			r.Handshakes = append(r.Handshakes, hs)
			off += used
		}
		if off != len(body) {
			r.BodyHex = strings.ToUpper(hex.EncodeToString(body[off:]))
		}
	default:
		r.BodyHex = strings.ToUpper(hex.EncodeToString(body))
	}
	return r, nil
}

func decodeHandshake(b []byte) (*Handshake, int, error) {
	if len(b) < 4 {
		return nil, 0, fmt.Errorf("handshake header truncated")
	}
	mt := int(b[0])
	length := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if 4+length > len(b) {
		return nil, 0, fmt.Errorf("handshake message length %d exceeds buffer (%d available)", length, len(b)-4)
	}
	h := &Handshake{
		MessageType: mt,
		MessageName: handshakeMessageName(mt),
		Length:      length,
	}
	body := b[4 : 4+length]
	switch mt {
	case 1: // ClientHello
		ch, err := decodeClientHello(body, "t")
		if err != nil {
			return nil, 0, fmt.Errorf("ClientHello: %w", err)
		}
		h.ClientHello = ch
	case 2: // ServerHello
		sh, err := decodeServerHello(body, "t")
		if err != nil {
			return nil, 0, fmt.Errorf("ServerHello: %w", err)
		}
		h.ServerHello = sh
	case 11: // Certificate
		h.Certificate = decodeCertificate(body)
		if len(h.Certificate.Certificates) == 0 {
			// Surface the raw body too when nothing parsed (e.g. an
			// encrypted/contextual TLS 1.3 Certificate message).
			h.BodyHex = strings.ToUpper(hex.EncodeToString(body))
		}
	default:
		h.BodyHex = strings.ToUpper(hex.EncodeToString(body))
	}
	return h, 4 + length, nil
}

// decodeCertificate parses a TLS 1.2 (and earlier) Certificate handshake
// message body — a 3-byte certificate_list length followed by 3-byte-length-
// prefixed DER certificates — and decodes each certificate via
// internal/x509decode. A body whose certificate_list length does not match is
// reported with a note rather than mis-parsed (no confidently-wrong output).
func decodeCertificate(body []byte) *Certificate {
	m := &Certificate{}
	if len(body) < 3 {
		m.Notes = append(m.Notes, "Certificate message too short for a certificate_list length")
		return m
	}
	listLen := int(body[0])<<16 | int(body[1])<<8 | int(body[2])
	if 3+listLen != len(body) {
		m.Notes = append(m.Notes,
			fmt.Sprintf("certificate_list length %d does not match the %d-byte body; if this is a TLS 1.3 Certificate message it carries a request-context prefix and per-certificate extensions and is not parsed here", listLen, len(body)-3))
		return m
	}
	off := 3
	for off+3 <= len(body) {
		cl := int(body[off])<<16 | int(body[off+1])<<8 | int(body[off+2])
		off += 3
		if off+cl > len(body) {
			m.Notes = append(m.Notes, fmt.Sprintf("certificate length %d at offset %d overruns the body", cl, off-3))
			break
		}
		der := body[off : off+cl]
		off += cl
		entry := &CertEntry{Length: cl}
		if c, err := x509decode.Decode(hex.EncodeToString(der)); err == nil {
			entry.Certificate = c
		} else {
			entry.DecodeError = err.Error()
			entry.DERHex = strings.ToUpper(hex.EncodeToString(der))
		}
		m.Certificates = append(m.Certificates, entry)
	}
	m.CertificateCount = len(m.Certificates)
	return m
}

func decodeClientHello(b []byte, proto string) (*ClientHello, error) {
	if len(b) < 38 {
		return nil, fmt.Errorf("ClientHello body too short (%d bytes)", len(b))
	}
	ch := &ClientHello{
		VersionMajor: int(b[0]),
		VersionMinor: int(b[1]),
		VersionName:  versionName(int(b[0]), int(b[1])),
		RandomHex:    strings.ToUpper(hex.EncodeToString(b[2:34])),
	}
	off := 34
	sidLen := int(b[off])
	off++
	if off+sidLen > len(b) {
		return nil, fmt.Errorf("session ID length %d exceeds buffer", sidLen)
	}
	ch.SessionIDHex = strings.ToUpper(hex.EncodeToString(b[off : off+sidLen]))
	off += sidLen
	if off+2 > len(b) {
		return nil, fmt.Errorf("cipher suites length missing")
	}
	csLen := int(b[off])<<8 | int(b[off+1])
	off += 2
	if off+csLen > len(b) {
		return nil, fmt.Errorf("cipher suites length %d exceeds buffer", csLen)
	}
	for i := 0; i+2 <= csLen; i += 2 {
		v := uint16(b[off+i])<<8 | uint16(b[off+i+1])
		ch.CipherSuites = append(ch.CipherSuites, CipherSuite{
			Value: v,
			Hex:   fmt.Sprintf("0x%04X", v),
			Name:  cipherSuiteName(v),
		})
	}
	off += csLen
	if off >= len(b) {
		return nil, fmt.Errorf("compression methods length missing")
	}
	cmLen := int(b[off])
	off++
	if off+cmLen > len(b) {
		return nil, fmt.Errorf("compression methods length %d exceeds buffer", cmLen)
	}
	for i := 0; i < cmLen; i++ {
		ch.CompressionMethods = append(ch.CompressionMethods, int(b[off+i]))
	}
	off += cmLen
	if off+2 <= len(b) {
		// Extensions are optional in TLS 1.0/1.1, mandatory in
		// TLS 1.2/1.3 ClientHello. Either way, decode if present.
		extLen := int(b[off])<<8 | int(b[off+1])
		off += 2
		if off+extLen > len(b) {
			return nil, fmt.Errorf("extensions length %d exceeds buffer", extLen)
		}
		exts, ext0, ja3Curves, ja3Formats, err := decodeExtensions(b[off : off+extLen])
		if err != nil {
			return nil, fmt.Errorf("extensions: %w", err)
		}
		ch.Extensions = exts
		ch.ServerName = ext0.serverName
		ch.ALPNProtocols = ext0.alpn
		ch.SupportedVersions = ext0.versions
		ch.SupportedGroups = ext0.groups
		ch.SignatureAlgorithms = ext0.sigAlgs
		ch.KeyShareGroups = ext0.keyShareGroups
		ch.JA3, ch.JA3Hash = computeJA3(
			ch.VersionMajor, ch.VersionMinor, ch.CipherSuites, ch.Extensions,
			ja3Curves, ja3Formats)
		ch.JA4 = computeJA4(
			proto, ch.VersionMajor, ch.VersionMinor, ch.CipherSuites, ch.Extensions,
			ch.ALPNProtocols, ext0.versionsRaw, ext0.sigAlgsRaw)
	}
	return ch, nil
}

func decodeServerHello(b []byte, proto string) (*ServerHello, error) {
	if len(b) < 38 {
		return nil, fmt.Errorf("ServerHello body too short (%d bytes)", len(b))
	}
	sh := &ServerHello{
		VersionMajor: int(b[0]),
		VersionMinor: int(b[1]),
		VersionName:  versionName(int(b[0]), int(b[1])),
		RandomHex:    strings.ToUpper(hex.EncodeToString(b[2:34])),
	}
	off := 34
	sidLen := int(b[off])
	off++
	if off+sidLen > len(b) {
		return nil, fmt.Errorf("session ID length %d exceeds buffer", sidLen)
	}
	sh.SessionIDHex = strings.ToUpper(hex.EncodeToString(b[off : off+sidLen]))
	off += sidLen
	if off+3 > len(b) {
		return nil, fmt.Errorf("cipher suite / compression method missing")
	}
	cs := uint16(b[off])<<8 | uint16(b[off+1])
	off += 2
	sh.CipherSuite = CipherSuite{
		Value: cs,
		Hex:   fmt.Sprintf("0x%04X", cs),
		Name:  cipherSuiteName(cs),
	}
	sh.CompressionMethod = int(b[off])
	off++
	if off+2 <= len(b) {
		extLen := int(b[off])<<8 | int(b[off+1])
		off += 2
		if off+extLen > len(b) {
			return nil, fmt.Errorf("extensions length %d exceeds buffer", extLen)
		}
		exts, ext0, _, _, err := decodeExtensions(b[off : off+extLen])
		if err != nil {
			return nil, fmt.Errorf("extensions: %w", err)
		}
		sh.Extensions = exts
		if len(ext0.alpn) > 0 {
			sh.NegotiatedALPN = ext0.alpn[0]
		}
		if len(ext0.versions) > 0 {
			sh.NegotiatedVersion = ext0.versions[0]
		}
		sh.JA4S = computeJA4S(proto, sh.VersionMajor, sh.VersionMinor, cs, exts, sh.NegotiatedALPN, sh.NegotiatedVersion)
	}
	return sh, nil
}

// QUICHandshakeJA4 computes the JA4 (for a ClientHello) or JA4S (for a
// ServerHello) fingerprint of a bare TLS handshake message lifted out of
// a QUIC Initial packet's reassembled CRYPTO stream, using the QUIC
// protocol prefix "q" (JA4 §"q"/"t"/"d" rule). QUIC carries the TLS
// handshake directly in CRYPTO frames with no TLS record envelope (RFC
// 9001 §4.1), so handshake[0] is the 1-byte handshake type and
// handshake[1:4] the 3-byte length. Returns the fingerprint and the
// message kind ("ClientHello" / "ServerHello"). The JA4 computation is
// identical to the TLS-over-TCP path bar the leading protocol character —
// verified end-to-end against FoxIO's QUIC snapshots (see
// internal/quic).
func QUICHandshakeJA4(handshake []byte) (fingerprint, kind string, err error) {
	if len(handshake) < 4 {
		return "", "", fmt.Errorf("handshake message too short (%d bytes)", len(handshake))
	}
	mt := int(handshake[0])
	length := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if 4+length > len(handshake) {
		return "", "", fmt.Errorf("handshake length %d exceeds buffer (%d available)",
			length, len(handshake)-4)
	}
	body := handshake[4 : 4+length]
	switch mt {
	case 1:
		ch, err := decodeClientHello(body, "q")
		if err != nil {
			return "", "", fmt.Errorf("ClientHello: %w", err)
		}
		return ch.JA4, "ClientHello", nil
	case 2:
		sh, err := decodeServerHello(body, "q")
		if err != nil {
			return "", "", fmt.Errorf("ServerHello: %w", err)
		}
		return sh.JA4S, "ServerHello", nil
	}
	return "", "", fmt.Errorf("handshake type %d is not ClientHello/ServerHello", mt)
}

// extractedExtensions bundles the operationally-interesting
// values lifted out of the extension list so the ClientHello/
// ServerHello populator doesn't have to re-walk extensions.
type extractedExtensions struct {
	serverName     string
	alpn           []string
	versions       []string
	groups         []string
	sigAlgs        []string
	keyShareGroups []string
	sigAlgsRaw     []uint16 // raw signature_algorithm code points, in order (for JA4_c)
	versionsRaw    []uint16 // raw supported_versions code points (for the JA4 version)
}

func decodeExtensions(b []byte) ([]*Extension, extractedExtensions, []uint16, []int, error) {
	var (
		out     []*Extension
		ex      extractedExtensions
		curves  []uint16
		formats []int
		off     = 0
	)
	for off+4 <= len(b) {
		typ := int(b[off])<<8 | int(b[off+1])
		length := int(b[off+2])<<8 | int(b[off+3])
		off += 4
		if off+length > len(b) {
			return nil, ex, nil, nil, fmt.Errorf("extension %d length %d exceeds buffer", typ, length)
		}
		ext := &Extension{
			Type:     typ,
			TypeName: extensionTypeName(typ),
			Length:   length,
			DataHex:  strings.ToUpper(hex.EncodeToString(b[off : off+length])),
		}
		body := b[off : off+length]
		off += length
		switch typ {
		case 0:
			ex.serverName = parseSNI(body)
		case 10:
			ex.groups, curves = parseSupportedGroups(body)
		case 11:
			formats = parseECPointFormats(body)
		case 13:
			ex.sigAlgs = parseSignatureAlgorithms(body)
			ex.sigAlgsRaw = parseU16List(body, 2)
		case 16:
			ex.alpn = parseALPN(body)
		case 43:
			ex.versions = parseSupportedVersions(body)
			ex.versionsRaw = parseU16List(body, 1)
		case 51:
			ex.keyShareGroups = parseKeyShareGroups(body)
		}
		out = append(out, ext)
	}
	return out, ex, curves, formats, nil
}

func parseSNI(b []byte) string {
	if len(b) < 5 {
		return ""
	}
	// ServerNameList length (2) + per entry: name_type (1) +
	// name (length-prefixed by 2 bytes).
	listLen := int(b[0])<<8 | int(b[1])
	if 2+listLen > len(b) {
		return ""
	}
	body := b[2 : 2+listLen]
	off := 0
	for off+3 <= len(body) {
		nameType := body[off]
		nameLen := int(body[off+1])<<8 | int(body[off+2])
		off += 3
		if off+nameLen > len(body) {
			return ""
		}
		if nameType == 0 {
			return string(body[off : off+nameLen])
		}
		off += nameLen
	}
	return ""
}

func parseALPN(b []byte) []string {
	if len(b) < 2 {
		return nil
	}
	listLen := int(b[0])<<8 | int(b[1])
	if 2+listLen > len(b) {
		return nil
	}
	body := b[2 : 2+listLen]
	var out []string
	off := 0
	for off < len(body) {
		l := int(body[off])
		off++
		if off+l > len(body) {
			break
		}
		out = append(out, string(body[off:off+l]))
		off += l
	}
	return out
}

func parseSupportedVersions(b []byte) []string {
	if len(b) < 1 {
		return nil
	}
	// ServerHello uses a 2-byte version directly; ClientHello
	// uses 1-byte length + N×2 bytes of versions.
	if len(b) == 2 {
		return []string{versionName(int(b[0]), int(b[1]))}
	}
	listLen := int(b[0])
	body := b[1:]
	if listLen != len(body) {
		return nil
	}
	var out []string
	for i := 0; i+2 <= listLen; i += 2 {
		out = append(out, versionName(int(body[i]), int(body[i+1])))
	}
	return out
}

func parseSupportedGroups(b []byte) ([]string, []uint16) {
	if len(b) < 2 {
		return nil, nil
	}
	listLen := int(b[0])<<8 | int(b[1])
	if 2+listLen > len(b) {
		return nil, nil
	}
	body := b[2 : 2+listLen]
	var names []string
	var raw []uint16
	for i := 0; i+2 <= len(body); i += 2 {
		v := uint16(body[i])<<8 | uint16(body[i+1])
		raw = append(raw, v)
		names = append(names, namedGroupName(v))
	}
	return names, raw
}

func parseECPointFormats(b []byte) []int {
	if len(b) < 1 {
		return nil
	}
	listLen := int(b[0])
	if 1+listLen > len(b) {
		return nil
	}
	out := make([]int, 0, listLen)
	for i := 0; i < listLen; i++ {
		out = append(out, int(b[1+i]))
	}
	return out
}

func parseSignatureAlgorithms(b []byte) []string {
	if len(b) < 2 {
		return nil
	}
	listLen := int(b[0])<<8 | int(b[1])
	if 2+listLen > len(b) {
		return nil
	}
	body := b[2 : 2+listLen]
	var out []string
	for i := 0; i+2 <= len(body); i += 2 {
		v := uint16(body[i])<<8 | uint16(body[i+1])
		out = append(out, signatureSchemeName(v))
	}
	return out
}

func parseKeyShareGroups(b []byte) []string {
	if len(b) < 2 {
		return nil
	}
	listLen := int(b[0])<<8 | int(b[1])
	if 2+listLen > len(b) {
		return nil
	}
	body := b[2 : 2+listLen]
	var out []string
	off := 0
	for off+4 <= len(body) {
		g := uint16(body[off])<<8 | uint16(body[off+1])
		kl := int(body[off+2])<<8 | int(body[off+3])
		off += 4 + kl
		if off > len(body) {
			break
		}
		out = append(out, namedGroupName(g))
	}
	return out
}

// computeJA3 builds the canonical JA3 client fingerprint
// string per https://github.com/salesforce/ja3. Format:
//
//	"<TLSVersion>,<CipherSuites>,<Extensions>,<EllipticCurves>,<EllipticCurvePointFormats>"
//
// with hyphens between list elements. GREASE values
// (0x?A?A) are stripped per Google's GREASE spec.
func computeJA3(verMajor, verMinor int, suites []CipherSuite, exts []*Extension,
	curves []uint16, formats []int,
) (string, string) {
	ver := uint16(verMajor)<<8 | uint16(verMinor)
	var b strings.Builder
	b.WriteString(strconv.Itoa(int(ver)))
	b.WriteByte(',')
	first := true
	for _, c := range suites {
		if isGREASE(c.Value) {
			continue
		}
		if !first {
			b.WriteByte('-')
		}
		first = false
		b.WriteString(strconv.Itoa(int(c.Value)))
	}
	b.WriteByte(',')
	first = true
	for _, e := range exts {
		if isGREASE(uint16(e.Type)) {
			continue
		}
		if !first {
			b.WriteByte('-')
		}
		first = false
		b.WriteString(strconv.Itoa(e.Type))
	}
	b.WriteByte(',')
	first = true
	for _, c := range curves {
		if isGREASE(c) {
			continue
		}
		if !first {
			b.WriteByte('-')
		}
		first = false
		b.WriteString(strconv.Itoa(int(c)))
	}
	b.WriteByte(',')
	first = true
	for _, f := range formats {
		if !first {
			b.WriteByte('-')
		}
		first = false
		b.WriteString(strconv.Itoa(f))
	}
	ja3 := b.String()
	sum := md5.Sum([]byte(ja3)) //nolint:gosec // MD5 is the JA3 spec.
	return ja3, hex.EncodeToString(sum[:])
}

// computeJA4 builds the JA4 TLS client fingerprint per the FoxIO spec
// (https://github.com/FoxIO-LLC/ja4), the modern successor to JA3. Format:
//
//	JA4_a _ JA4_b _ JA4_c
//
// JA4_a = protocol(t) + 2-char TLS version (highest offered) + SNI present(d)/
// absent(i) + 2-digit non-GREASE cipher count + 2-digit non-GREASE extension
// count (SNI + ALPN included in the count) + first/last char of the first ALPN.
// JA4_b = first 12 hex of SHA-256 of the sorted, non-GREASE cipher list
// (4-hex, lower-case, comma-joined). JA4_c = first 12 hex of SHA-256 of the
// sorted, non-GREASE extension list with SNI(0x0000) and ALPN(0x0010) removed,
// then "_" and the signature_algorithms in their original order. An empty hash
// input yields twelve zeros, per the spec.
//
// Verified byte-for-byte against the FoxIO worked example
// t13d1516h2_8daaf6152771_e5627efa2ab1. The protocol prefix is a parameter:
// "t" for TLS-over-TCP records (the decoder's own path) and "q" for the QUIC
// variant computed over a ClientHello extracted from a QUIC Initial (see
// QUICHandshakeJA4), the only difference between the two per the JA4 spec. The
// rare non-alphanumeric-ALPN fallback follows the spec's hex rule but is not
// exercised by any IANA-registered ALPN.
func computeJA4(proto string, verMajor, verMinor int, suites []CipherSuite, exts []*Extension,
	alpn []string, versionsRaw, sigAlgsRaw []uint16) string {
	sni := "i"
	for _, e := range exts {
		if e.Type == 0 {
			sni = "d"
			break
		}
	}

	var cipherHex []string
	for _, c := range suites {
		if isGREASE(c.Value) {
			continue
		}
		cipherHex = append(cipherHex, fmt.Sprintf("%04x", c.Value))
	}
	extCount := 0
	var extHex []string
	for _, e := range exts {
		if isGREASE(uint16(e.Type)) {
			continue
		}
		extCount++ // the JA4_a count includes SNI + ALPN
		if e.Type == 0 || e.Type == 16 {
			continue // ...but they are removed from the JA4_c hash
		}
		extHex = append(extHex, fmt.Sprintf("%04x", e.Type))
	}

	a := fmt.Sprintf("%s%s%s%02d%02d%s",
		proto, ja4Version(verMajor, verMinor, versionsRaw), sni,
		minInt(len(cipherHex), 99), minInt(extCount, 99), ja4ALPN(alpn))

	sort.Strings(cipherHex)
	b := ja4Hash(strings.Join(cipherHex, ","))

	sort.Strings(extHex)
	cInput := strings.Join(extHex, ",")
	if len(sigAlgsRaw) > 0 {
		sigHex := make([]string, len(sigAlgsRaw))
		for i, s := range sigAlgsRaw {
			sigHex[i] = fmt.Sprintf("%04x", s) // original order, NOT sorted
		}
		cInput += "_" + strings.Join(sigHex, ",")
	}
	c := ja4Hash(cInput)

	return a + "_" + b + "_" + c
}

// computeJA4S builds the JA4S TLS *server* fingerprint per the FoxIO reference
// implementation. Format:
//
//	JA4S_a _ JA4S_b _ JA4S_c
//
// JA4S_a = protocol(t) + 2-char TLS version (the version the server selected) +
// 2-digit server-extension count + first/last char of the chosen ALPN ("00" if
// none). JA4S_b = the single negotiated cipher suite as 4-hex lower-case.
// JA4S_c = first 12 hex of SHA-256 of the server's extension list in WIRE ORDER
// (4-hex, comma-joined). Unlike JA4 (client), the list is NOT sorted and SNI /
// ALPN are NOT removed — the server's extension order is itself the fingerprint
// signal, so it is preserved verbatim.
//
// Verified byte-for-byte against two real FoxIO snapshot outputs: a Google-stack
// TLS 1.3 ServerHello (key_share then supported_versions) ->
// t130200_1301_234ea6891581, and a LastPass one (supported_versions then
// key_share) -> t130200_1302_a56c5b993250 — the same two extensions in opposite
// order yield different hashes, confirming the wire-order rule. The protocol
// prefix is a parameter ("t" for TLS-over-TCP, "q" for a ServerHello extracted
// from a QUIC Initial — see QUICHandshakeJA4); GREASE-bearing servers remain
// out of scope as in the reference.
func computeJA4S(proto string, verMajor, verMinor int, cipher uint16, exts []*Extension, alpn, negotiatedVersion string) string {
	// The ServerHello's supported_versions extension is a single bare version
	// (not the client's length-prefixed list), so the negotiated-version string
	// is the reliable source; fall back to the legacy ClientHello-version field.
	var vraw []uint16
	if c := versionStringToCode(negotiatedVersion); c != 0 {
		vraw = []uint16{c}
	}
	alpnCode := "00"
	if alpn != "" {
		alpnCode = ja4ALPN([]string{alpn})
	}
	extHex := make([]string, len(exts))
	for i, e := range exts {
		extHex[i] = fmt.Sprintf("%04x", uint16(e.Type)) // wire order, not sorted
	}
	a := fmt.Sprintf("%s%s%02d%s", proto, ja4Version(verMajor, verMinor, vraw), minInt(len(exts), 99), alpnCode)
	return fmt.Sprintf("%s_%04x_%s", a, cipher, ja4Hash(strings.Join(extHex, ",")))
}

// versionStringToCode inverts versionName for the JA4/JA4S version lookup.
func versionStringToCode(s string) uint16 {
	switch s {
	case "SSL 3.0":
		return 0x0300
	case "TLS 1.0":
		return 0x0301
	case "TLS 1.1":
		return 0x0302
	case "TLS 1.2":
		return 0x0303
	case "TLS 1.3", "TLS 1.3 (draft)":
		return 0x0304
	}
	return 0
}

// ja4Hash returns the first 12 hex chars of SHA-256(s), or twelve zeros when s
// is empty (the FoxIO "no values" sentinel).
func ja4Hash(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// ja4Version maps the highest offered TLS version to its 2-char JA4 code,
// preferring the supported_versions extension (non-GREASE max) over the legacy
// ClientHello version field.
func ja4Version(verMajor, verMinor int, versionsRaw []uint16) string {
	best := -1
	for _, v := range versionsRaw {
		if isGREASE(v) {
			continue
		}
		if int(v) > best {
			best = int(v)
		}
	}
	if best < 0 {
		best = verMajor<<8 | verMinor
	}
	switch best {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	default:
		return "00"
	}
}

// ja4ALPN returns the JA4 2-char ALPN code: the first and last character of the
// first ALPN protocol when both are alphanumeric (e.g. "h2" -> "h2",
// "http/1.1" -> "h1"), "00" when no ALPN, or the spec's hex fallback for a
// non-alphanumeric boundary (not hit by any IANA-registered ALPN).
func ja4ALPN(alpn []string) string {
	if len(alpn) == 0 || alpn[0] == "" {
		return "00"
	}
	s := alpn[0]
	first, last := s[0], s[len(s)-1]
	if isAlnumByte(first) && isAlnumByte(last) {
		return string([]byte{first, last})
	}
	h := fmt.Sprintf("%02x%02x", first, last)
	return string([]byte{h[0], h[len(h)-1]})
}

func isAlnumByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// parseU16List reads a length-prefixed list of big-endian uint16 code points.
// prefixLen is the byte width of the leading list-length field (1 for
// supported_versions, 2 for signature_algorithms).
func parseU16List(b []byte, prefixLen int) []uint16 {
	if len(b) < prefixLen {
		return nil
	}
	listLen := 0
	for i := 0; i < prefixLen; i++ {
		listLen = listLen<<8 | int(b[i])
	}
	body := b[prefixLen:]
	if listLen > len(body) {
		listLen = len(body)
	}
	body = body[:listLen]
	var out []uint16
	for i := 0; i+2 <= len(body); i += 2 {
		out = append(out, uint16(body[i])<<8|uint16(body[i+1]))
	}
	return out
}

// isGREASE reports true for the GREASE values defined in RFC
// 8701: every 2-byte value with both halves equal and a low
// nibble of 0xA (0x0A0A, 0x1A1A, ..., 0xFAFA).
func isGREASE(v uint16) bool {
	high := byte(v >> 8)
	low := byte(v & 0xFF)
	return high == low && (low&0x0F) == 0x0A
}

// contentTypeName labels the TLS record-layer ContentType.
func contentTypeName(ct int) string {
	switch ct {
	case 20:
		return "ChangeCipherSpec"
	case 21:
		return "Alert"
	case 22:
		return "Handshake"
	case 23:
		return "ApplicationData"
	case 24:
		return "Heartbeat (RFC 6520)"
	}
	return fmt.Sprintf("Reserved (content type %d)", ct)
}

// versionName labels a TLS protocol version pair.
func versionName(major, minor int) string {
	switch (major << 8) | minor {
	case 0x0300:
		return "SSL 3.0"
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	case 0x7F1C, 0x7F1D, 0x7F1E:
		return "TLS 1.3 (draft)"
	}
	return fmt.Sprintf("Unknown (%d.%d)", major, minor)
}

// handshakeMessageName labels the TLS handshake message type.
func handshakeMessageName(mt int) string {
	switch mt {
	case 0:
		return "HelloRequest"
	case 1:
		return "ClientHello"
	case 2:
		return "ServerHello"
	case 4:
		return "NewSessionTicket"
	case 5:
		return "EndOfEarlyData"
	case 8:
		return "EncryptedExtensions"
	case 11:
		return "Certificate"
	case 12:
		return "ServerKeyExchange"
	case 13:
		return "CertificateRequest"
	case 14:
		return "ServerHelloDone"
	case 15:
		return "CertificateVerify"
	case 16:
		return "ClientKeyExchange"
	case 20:
		return "Finished"
	case 22:
		return "CertificateStatus"
	case 24:
		return "KeyUpdate"
	case 254:
		return "MessageHash"
	}
	return fmt.Sprintf("Reserved (handshake %d)", mt)
}

// extensionTypeName labels TLS extension types per the IANA
// registry. ~30 of the most-deployed extensions.
func extensionTypeName(t int) string {
	switch t {
	case 0:
		return "server_name (SNI)"
	case 1:
		return "max_fragment_length"
	case 4:
		return "trusted_ca_keys"
	case 5:
		return "status_request"
	case 10:
		return "supported_groups"
	case 11:
		return "ec_point_formats"
	case 13:
		return "signature_algorithms"
	case 14:
		return "use_srtp"
	case 15:
		return "heartbeat"
	case 16:
		return "application_layer_protocol_negotiation (ALPN)"
	case 17:
		return "status_request_v2"
	case 18:
		return "signed_certificate_timestamp"
	case 19:
		return "client_certificate_type"
	case 20:
		return "server_certificate_type"
	case 21:
		return "padding"
	case 22:
		return "encrypt_then_mac"
	case 23:
		return "extended_master_secret"
	case 27:
		return "compress_certificate"
	case 28:
		return "record_size_limit"
	case 35:
		return "session_ticket"
	case 41:
		return "pre_shared_key"
	case 42:
		return "early_data"
	case 43:
		return "supported_versions"
	case 44:
		return "cookie"
	case 45:
		return "psk_key_exchange_modes"
	case 47:
		return "certificate_authorities"
	case 48:
		return "oid_filters"
	case 49:
		return "post_handshake_auth"
	case 50:
		return "signature_algorithms_cert"
	case 51:
		return "key_share"
	case 65281:
		return "renegotiation_info"
	}
	if isGREASE(uint16(t)) {
		return fmt.Sprintf("GREASE (RFC 8701, 0x%04X)", t)
	}
	return fmt.Sprintf("Unknown (0x%04X)", t)
}

// cipherSuiteName labels TLS cipher suites. ~80 entries
// covering all current TLS 1.3 suites + the most-deployed
// TLS 1.2 suites + the legacy / deprecated suites operators
// still find in legacy captures.
func cipherSuiteName(v uint16) string {
	if n, ok := cipherSuiteTable[v]; ok {
		return n
	}
	if isGREASE(v) {
		return fmt.Sprintf("GREASE (RFC 8701, 0x%04X)", v)
	}
	return fmt.Sprintf("Unknown (0x%04X)", v)
}

var cipherSuiteTable = map[uint16]string{
	// TLS 1.3 (RFC 8446)
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0x1304: "TLS_AES_128_CCM_SHA256",
	0x1305: "TLS_AES_128_CCM_8_SHA256",
	// ECDHE-ECDSA-AES suites (TLS 1.2 modern)
	0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	// ECDHE-RSA-AES suites (TLS 1.2 modern)
	0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
	0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	// DHE-RSA-AES suites
	0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
	0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
	0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
	0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	// RSA suites (legacy)
	0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
	0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
	0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0005: "TLS_RSA_WITH_RC4_128_SHA",
	0x0004: "TLS_RSA_WITH_RC4_128_MD5",
	// Empty / signaling
	0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
	0x5600: "TLS_FALLBACK_SCSV",
	0x0000: "TLS_NULL_WITH_NULL_NULL",
}

// namedGroupName labels the TLS named-group (supported_groups
// extension) value. ~20 entries covering the deployed elliptic
// curves + FFDHE groups + post-quantum hybrid groups.
func namedGroupName(g uint16) string {
	switch g {
	case 0x0017:
		return "secp256r1 (P-256)"
	case 0x0018:
		return "secp384r1 (P-384)"
	case 0x0019:
		return "secp521r1 (P-521)"
	case 0x001D:
		return "x25519"
	case 0x001E:
		return "x448"
	case 0x0100:
		return "ffdhe2048"
	case 0x0101:
		return "ffdhe3072"
	case 0x0102:
		return "ffdhe4096"
	case 0x0103:
		return "ffdhe6144"
	case 0x0104:
		return "ffdhe8192"
	case 0x6399:
		return "x25519_kyber768_draft00"
	case 0x639A:
		return "secp256r1_kyber768_draft00"
	}
	if isGREASE(g) {
		return fmt.Sprintf("GREASE (RFC 8701, 0x%04X)", g)
	}
	return fmt.Sprintf("Unknown (0x%04X)", g)
}

// signatureSchemeName labels TLS SignatureScheme values per
// RFC 8446 §4.2.3 + IANA registry.
func signatureSchemeName(s uint16) string {
	switch s {
	case 0x0401:
		return "rsa_pkcs1_sha256"
	case 0x0501:
		return "rsa_pkcs1_sha384"
	case 0x0601:
		return "rsa_pkcs1_sha512"
	case 0x0403:
		return "ecdsa_secp256r1_sha256"
	case 0x0503:
		return "ecdsa_secp384r1_sha384"
	case 0x0603:
		return "ecdsa_secp521r1_sha512"
	case 0x0804:
		return "rsa_pss_rsae_sha256"
	case 0x0805:
		return "rsa_pss_rsae_sha384"
	case 0x0806:
		return "rsa_pss_rsae_sha512"
	case 0x0807:
		return "ed25519"
	case 0x0808:
		return "ed448"
	case 0x0809:
		return "rsa_pss_pss_sha256"
	case 0x080A:
		return "rsa_pss_pss_sha384"
	case 0x080B:
		return "rsa_pss_pss_sha512"
	case 0x0201:
		return "rsa_pkcs1_sha1"
	case 0x0203:
		return "ecdsa_sha1"
	}
	if isGREASE(s) {
		return fmt.Sprintf("GREASE (RFC 8701, 0x%04X)", s)
	}
	return fmt.Sprintf("Unknown (0x%04X)", s)
}

func parseHex(s string) ([]byte, error) {
	s = stripSeparators(s)
	if s == "" {
		return nil, fmt.Errorf("tlsdecode: empty hex input")
	}
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("tlsdecode: invalid hex: %w", err)
	}
	return b, nil
}

func stripSeparators(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
