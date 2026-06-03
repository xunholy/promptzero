// Package dtls decodes Datagram Transport Layer Security
// records and handshake messages per RFC 6347 (DTLS 1.2) and
// RFC 9147 (DTLS 1.3 — unified header form is not supported
// here; we decode the legacy DTLS 1.3 record layer that uses
// the same 13-byte header as 1.2).
//
// Wrap-vs-native judgement
//
//	Native. Both DTLS RFCs are fully public; the wire format
//	is a tight fixed-layout binary record header plus a
//	well-documented handshake-message catalogue. No crypto
//	is performed at this layer — handshake bodies of
//	post-Finished records and ApplicationData payloads are
//	encrypted (when the cipher state has advanced past the
//	null cipher) and are surfaced as hex. Operators paste
//	UDP payload bytes from a Wireshark Follow-UDP-Stream
//	view, a `tcpdump -X udp port 443` line, or any DTLS-
//	emitting tool and inspect every documented field.
//
// What this package covers
//
//   - **Record layer** (13 bytes fixed, RFC 6347 §4.1):
//     ContentType (1 byte) + Version (2 bytes) + Epoch (2
//     bytes BE — incremented on each cipher state change) +
//     Sequence Number (6 bytes BE — replay-protection nonce)
//
//   - Length (2 bytes BE) + Fragment (Length bytes). The
//     walker iterates concatenated records until the buffer
//     is consumed.
//
//   - **Content types** (RFC 5246 §6.2.1):
//
//   - 20 ChangeCipherSpec
//
//   - 21 Alert
//
//   - 22 Handshake
//
//   - 23 ApplicationData
//
//   - 24 Heartbeat (RFC 6520 — yes, that one)
//
//   - **Version values**:
//
//   - 0xFEFF DTLS 1.0
//
//   - 0xFEFD DTLS 1.2
//
//   - 0xFEFC DTLS 1.3 (legacy-form records)
//
//   - **Alert body** (2 bytes): Level (1 warning / 2 fatal) +
//     Description with a **23-entry name table** covering
//     close_notify, unexpected_message, bad_record_mac,
//     decryption_failed, record_overflow, decompression_
//     failure, handshake_failure, no_certificate (TLS 1.0),
//     bad_certificate, unsupported_certificate, certificate_
//     revoked, certificate_expired, certificate_unknown,
//     illegal_parameter, unknown_ca, access_denied, decode_
//     error, decrypt_error, export_restriction, protocol_
//     version, insufficient_security, internal_error,
//     user_canceled, no_renegotiation, unsupported_extension.
//
//   - **ChangeCipherSpec body** (1 byte, always 0x01).
//
//   - **Handshake message header** (12 bytes fixed, RFC 6347
//     §4.2.2): MsgType (1 byte) + Length (3 bytes BE — total
//     reassembled message length) + MessageSeq (2 bytes BE
//     — for fragment reassembly) + FragmentOffset (3 bytes
//     BE) + FragmentLength (3 bytes BE) + FragmentBody.
//
//   - **Handshake message types** (RFC 5246 + RFC 6347):
//
//   - 0 HelloRequest
//
//   - 1 ClientHello
//
//   - 2 ServerHello
//
//   - 3 HelloVerifyRequest (DTLS-specific cookie exchange)
//
//   - 4 NewSessionTicket
//
//   - 8 EncryptedExtensions (TLS 1.3)
//
//   - 11 Certificate
//
//   - 12 ServerKeyExchange
//
//   - 13 CertificateRequest
//
//   - 14 ServerHelloDone
//
//   - 15 CertificateVerify
//
//   - 16 ClientKeyExchange
//
//   - 20 Finished
//
//   - **ClientHello body** parsed: legacy_version + random
//     (32 bytes) + session_id (length-prefixed) + cookie
//     (length-prefixed, DTLS-specific) + cipher_suites
//     (length-prefixed list of uint16 BE; rendered as count
//
//   - raw hex blob) + compression_methods (length-prefixed
//     list of uint8) + extensions (length-prefixed list of
//     uint16 type + uint16 length + body bytes, rendered as
//     count + raw hex blob).
//
//   - **ServerHello body** parsed: legacy_version + random
//
//   - session_id + selected cipher_suite (uint16 BE) +
//     selected compression_method (uint8) + extensions.
//
//   - **HelloVerifyRequest body** parsed: server_version +
//     cookie (length-prefixed). The hallmark of DTLS's
//     stateless cookie exchange (mitigates UDP amplification
//     DoS).
//
//   - **Heartbeat body** (RFC 6520): MessageType (1 byte:
//     1 Request / 2 Response) + PayloadLength (uint16 BE) +
//     Payload + Padding. NB: a mismatched PayloadLength
//     vs declared was the basis for Heartbleed (CVE-2014-
//     0160) — we surface the declared value AND the actual
//     remaining bytes so operators can spot the gap.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - Decryption of encrypted records — operators need
//     session keys exported from the TLS handshake; the
//     ciphertext is surfaced as hex.
//
//   - DTLS 1.3 unified header records (RFC 9147 §4) — the
//     ultra-compact variant with 8-bit-tag header is a
//     future Spec.
//
//   - Full TLS extension dissection (SNI / ALPN / supported_
//     groups / signature_algorithms / key_share / etc.) —
//     extension bodies are surfaced as hex. The TLS
//     extension catalogue is handled by `tls_handshake_decode`
//     for cleartext TCP records; the same table would apply
//     once cleartext bytes have been extracted from DTLS.
//
//   - UDP / IP framing — feed the UDP payload bytes.
package dtls

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/x509decode"
)

// Result is the top-level decoded view.
type Result struct {
	Records     []Record `json:"records"`
	RecordCount int      `json:"record_count"`
	TotalBytes  int      `json:"total_bytes"`
	Summary     string   `json:"summary"`
}

// Record is one DTLS record-layer frame.
type Record struct {
	ContentType     int    `json:"content_type"`
	ContentTypeName string `json:"content_type_name"`
	Version         string `json:"version"`
	VersionHex      string `json:"version_hex"`
	Epoch           uint16 `json:"epoch"`
	SequenceNumber  uint64 `json:"sequence_number"`
	Length          int    `json:"length"`
	FragmentHex     string `json:"fragment_hex,omitempty"`

	Handshake        *Handshake       `json:"handshake,omitempty"`
	Alert            *Alert           `json:"alert,omitempty"`
	ChangeCipherSpec *uint8           `json:"change_cipher_spec,omitempty"`
	Heartbeat        *Heartbeat       `json:"heartbeat,omitempty"`
	ApplicationData  *ApplicationData `json:"application_data,omitempty"`
}

// Handshake is the dissected DTLS handshake header + per-type
// body. When the fragment is encrypted (post-ChangeCipherSpec),
// only the FragmentHex on the parent Record is meaningful and
// this struct is nil.
type Handshake struct {
	MsgType        int    `json:"msg_type"`
	MsgTypeName    string `json:"msg_type_name"`
	Length         int    `json:"total_message_length"`
	MessageSeq     uint16 `json:"message_seq"`
	FragmentOffset int    `json:"fragment_offset"`
	FragmentLength int    `json:"fragment_length"`
	IsFragmented   bool   `json:"is_fragmented"`

	ClientHello        *ClientHello        `json:"client_hello,omitempty"`
	ServerHello        *ServerHello        `json:"server_hello,omitempty"`
	HelloVerifyRequest *HelloVerifyRequest `json:"hello_verify_request,omitempty"`
	Certificate        *Certificate        `json:"certificate,omitempty"`
}

// Certificate is a decoded DTLS Certificate handshake message. Its body uses
// the same layout as TLS 1.2 (a 3-byte certificate_list length followed by
// 3-byte-length-prefixed DER certificates); each DER certificate is decoded
// via internal/x509decode. Only attempted on an unfragmented handshake
// message (the dispatch above returns early when IsFragmented).
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

// ClientHello body fields.
type ClientHello struct {
	LegacyVersion      string `json:"legacy_version"`
	LegacyVersionHex   string `json:"legacy_version_hex"`
	RandomHex          string `json:"random_hex"`
	SessionIDHex       string `json:"session_id_hex,omitempty"`
	SessionIDLength    int    `json:"session_id_length"`
	CookieHex          string `json:"cookie_hex,omitempty"`
	CookieLength       int    `json:"cookie_length"`
	CipherSuiteCount   int    `json:"cipher_suite_count"`
	CipherSuitesHex    string `json:"cipher_suites_hex,omitempty"`
	CompressionCount   int    `json:"compression_count"`
	CompressionMethods string `json:"compression_methods_hex,omitempty"`
	ExtensionsLength   int    `json:"extensions_length,omitempty"`
	ExtensionsHex      string `json:"extensions_hex,omitempty"`
}

// ServerHello body fields.
type ServerHello struct {
	LegacyVersion     string `json:"legacy_version"`
	LegacyVersionHex  string `json:"legacy_version_hex"`
	RandomHex         string `json:"random_hex"`
	SessionIDHex      string `json:"session_id_hex,omitempty"`
	SessionIDLength   int    `json:"session_id_length"`
	CipherSuiteHex    string `json:"cipher_suite_hex"`
	CompressionMethod int    `json:"compression_method"`
	ExtensionsLength  int    `json:"extensions_length,omitempty"`
	ExtensionsHex     string `json:"extensions_hex,omitempty"`
}

// HelloVerifyRequest body fields.
type HelloVerifyRequest struct {
	ServerVersion    string `json:"server_version"`
	ServerVersionHex string `json:"server_version_hex"`
	CookieHex        string `json:"cookie_hex"`
	CookieLength     int    `json:"cookie_length"`
}

// Alert is the body of content type 21.
type Alert struct {
	Level           int    `json:"level"`
	LevelName       string `json:"level_name"`
	Description     int    `json:"description"`
	DescriptionName string `json:"description_name"`
}

// Heartbeat is the body of content type 24 (RFC 6520).
type Heartbeat struct {
	MessageType     int    `json:"message_type"`
	MessageTypeName string `json:"message_type_name"`
	PayloadLength   int    `json:"payload_length_declared"`
	ActualRemaining int    `json:"actual_remaining_bytes"`
	PayloadHex      string `json:"payload_hex,omitempty"`
	HeartbleedHint  string `json:"heartbleed_hint,omitempty"`
}

// ApplicationData surfaces the ciphertext blob with length.
type ApplicationData struct {
	CipherTextLen int    `json:"cipher_text_length"`
	CipherTextHex string `json:"cipher_text_hex,omitempty"`
}

// Decode parses one or more concatenated DTLS records from hex.
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if clean == "" {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("hex must have even length, got %d", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}

	r := &Result{TotalBytes: len(b)}
	off := 0
	for off < len(b) {
		if off+13 > len(b) {
			return nil, fmt.Errorf("record header truncated at offset %d (need 13 bytes, have %d)",
				off, len(b)-off)
		}
		ct := int(b[off])
		ver := binary.BigEndian.Uint16(b[off+1 : off+3])
		epoch := binary.BigEndian.Uint16(b[off+3 : off+5])
		seq := uint64(b[off+5])<<40 |
			uint64(b[off+6])<<32 |
			uint64(b[off+7])<<24 |
			uint64(b[off+8])<<16 |
			uint64(b[off+9])<<8 |
			uint64(b[off+10])
		length := int(binary.BigEndian.Uint16(b[off+11 : off+13]))
		if off+13+length > len(b) {
			return nil, fmt.Errorf("record at offset %d declares %d-byte fragment; %d left",
				off, length, len(b)-off-13)
		}
		frag := b[off+13 : off+13+length]
		rec := Record{
			ContentType:     ct,
			ContentTypeName: contentTypeName(ct),
			Version:         versionName(ver),
			VersionHex:      fmt.Sprintf("0x%04X", ver),
			Epoch:           epoch,
			SequenceNumber:  seq,
			Length:          length,
		}
		if length > 0 {
			if length > 256 {
				rec.FragmentHex = strings.ToUpper(hex.EncodeToString(frag[:256])) + "..."
			} else {
				rec.FragmentHex = strings.ToUpper(hex.EncodeToString(frag))
			}
		}

		// Only decode plaintext payloads when epoch==0 (pre-
		// cipher-change) or when the content type is the
		// always-plaintext Alert. ChangeCipherSpec is always
		// 1 byte plaintext. ApplicationData is always
		// surfaced as ciphertext.
		switch ct {
		case 20: // ChangeCipherSpec
			if length == 1 {
				v := frag[0]
				rec.ChangeCipherSpec = &v
			}
		case 21: // Alert
			if length >= 2 {
				rec.Alert = &Alert{
					Level:           int(frag[0]),
					LevelName:       alertLevelName(int(frag[0])),
					Description:     int(frag[1]),
					DescriptionName: alertDescriptionName(int(frag[1])),
				}
			}
		case 22: // Handshake
			if epoch == 0 {
				h, err := decodeHandshake(frag)
				if err != nil {
					return nil, fmt.Errorf("record at offset %d handshake: %w",
						off, err)
				}
				rec.Handshake = h
			}
		case 23: // ApplicationData
			rec.ApplicationData = &ApplicationData{
				CipherTextLen: length,
			}
			if length > 0 {
				if length > 256 {
					rec.ApplicationData.CipherTextHex =
						strings.ToUpper(hex.EncodeToString(frag[:256])) + "..."
				} else {
					rec.ApplicationData.CipherTextHex =
						strings.ToUpper(hex.EncodeToString(frag))
				}
			}
		case 24: // Heartbeat
			if length >= 3 {
				hb := &Heartbeat{
					MessageType:     int(frag[0]),
					MessageTypeName: heartbeatTypeName(int(frag[0])),
					PayloadLength:   int(binary.BigEndian.Uint16(frag[1:3])),
					ActualRemaining: length - 3,
				}
				if length > 3 {
					if length > 256+3 {
						hb.PayloadHex =
							strings.ToUpper(hex.EncodeToString(frag[3:259])) + "..."
					} else {
						hb.PayloadHex = strings.ToUpper(hex.EncodeToString(frag[3:]))
					}
				}
				// Heartbleed hint: declared payload length
				// exceeds the actual remaining bytes
				// (before padding). RFC 6520 requires the
				// payload to be exactly payload_length
				// bytes followed by ≥16 bytes of random
				// padding. A request with declared length
				// way larger than what's on the wire is
				// the Heartbleed bug pattern.
				if hb.PayloadLength > hb.ActualRemaining {
					hb.HeartbleedHint = fmt.Sprintf(
						"declared payload_length %d exceeds remaining bytes "+
							"%d — this is the Heartbleed (CVE-2014-0160) "+
							"information-disclosure pattern when the peer is "+
							"a vulnerable OpenSSL implementation",
						hb.PayloadLength, hb.ActualRemaining)
				}
				rec.Heartbeat = hb
			}
		}

		r.Records = append(r.Records, rec)
		off += 13 + length
	}

	r.RecordCount = len(r.Records)
	names := make([]string, 0, len(r.Records))
	for _, rec := range r.Records {
		label := rec.ContentTypeName
		if rec.Handshake != nil {
			label = rec.Handshake.MsgTypeName
		}
		names = append(names, label)
	}
	r.Summary = strings.Join(names, " + ")
	return r, nil
}

func decodeHandshake(frag []byte) (*Handshake, error) {
	if len(frag) < 12 {
		return nil, fmt.Errorf("handshake header truncated (%d bytes; need 12)",
			len(frag))
	}
	h := &Handshake{
		MsgType:        int(frag[0]),
		MsgTypeName:    handshakeTypeName(int(frag[0])),
		Length:         int(frag[1])<<16 | int(frag[2])<<8 | int(frag[3]),
		MessageSeq:     binary.BigEndian.Uint16(frag[4:6]),
		FragmentOffset: int(frag[6])<<16 | int(frag[7])<<8 | int(frag[8]),
		FragmentLength: int(frag[9])<<16 | int(frag[10])<<8 | int(frag[11]),
	}
	h.IsFragmented = h.FragmentLength != h.Length || h.FragmentOffset != 0

	if 12+h.FragmentLength > len(frag) {
		return nil, fmt.Errorf("handshake fragment declares %d bytes; %d left",
			h.FragmentLength, len(frag)-12)
	}
	body := frag[12 : 12+h.FragmentLength]

	// Only attempt body dissection on the first (unfragmented)
	// piece — partial fragments are surfaced via the header.
	if h.IsFragmented {
		return h, nil
	}

	switch h.MsgType {
	case 1:
		h.ClientHello = decodeClientHello(body)
	case 2:
		h.ServerHello = decodeServerHello(body)
	case 3:
		h.HelloVerifyRequest = decodeHelloVerifyRequest(body)
	case 11:
		h.Certificate = decodeCertificate(body)
	}
	return h, nil
}

// decodeCertificate parses a DTLS Certificate handshake body (same layout as
// TLS 1.2: a 3-byte certificate_list length + 3-byte-length-prefixed DER
// certificates) and decodes each certificate via internal/x509decode. A body
// whose certificate_list length does not match is reported with a note rather
// than mis-parsed; a certificate whose DER fails to parse is surfaced raw with
// a decode_error.
func decodeCertificate(body []byte) *Certificate {
	m := &Certificate{}
	if len(body) < 3 {
		m.Notes = append(m.Notes, "Certificate message too short for a certificate_list length")
		return m
	}
	listLen := int(body[0])<<16 | int(body[1])<<8 | int(body[2])
	if 3+listLen != len(body) {
		m.Notes = append(m.Notes,
			fmt.Sprintf("certificate_list length %d does not match the %d-byte body", listLen, len(body)-3))
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

func decodeClientHello(b []byte) *ClientHello {
	if len(b) < 2+32+1 {
		return nil
	}
	ch := &ClientHello{
		LegacyVersionHex: fmt.Sprintf("0x%04X", binary.BigEndian.Uint16(b[0:2])),
		LegacyVersion:    versionName(binary.BigEndian.Uint16(b[0:2])),
		RandomHex:        strings.ToUpper(hex.EncodeToString(b[2:34])),
	}
	off := 34
	if off >= len(b) {
		return ch
	}
	sidLen := int(b[off])
	off++
	if off+sidLen > len(b) {
		return ch
	}
	ch.SessionIDLength = sidLen
	if sidLen > 0 {
		ch.SessionIDHex = strings.ToUpper(hex.EncodeToString(b[off : off+sidLen]))
	}
	off += sidLen
	if off >= len(b) {
		return ch
	}
	cookieLen := int(b[off])
	off++
	if off+cookieLen > len(b) {
		return ch
	}
	ch.CookieLength = cookieLen
	if cookieLen > 0 {
		ch.CookieHex = strings.ToUpper(hex.EncodeToString(b[off : off+cookieLen]))
	}
	off += cookieLen
	if off+2 > len(b) {
		return ch
	}
	csLen := int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	if off+csLen > len(b) {
		return ch
	}
	ch.CipherSuiteCount = csLen / 2
	if csLen > 0 {
		ch.CipherSuitesHex = strings.ToUpper(hex.EncodeToString(b[off : off+csLen]))
	}
	off += csLen
	if off >= len(b) {
		return ch
	}
	compLen := int(b[off])
	off++
	if off+compLen > len(b) {
		return ch
	}
	ch.CompressionCount = compLen
	if compLen > 0 {
		ch.CompressionMethods = strings.ToUpper(hex.EncodeToString(b[off : off+compLen]))
	}
	off += compLen
	if off+2 > len(b) {
		return ch
	}
	extLen := int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	if off+extLen > len(b) {
		return ch
	}
	ch.ExtensionsLength = extLen
	if extLen > 0 {
		ch.ExtensionsHex = strings.ToUpper(hex.EncodeToString(b[off : off+extLen]))
	}
	return ch
}

func decodeServerHello(b []byte) *ServerHello {
	if len(b) < 2+32+1 {
		return nil
	}
	sh := &ServerHello{
		LegacyVersionHex: fmt.Sprintf("0x%04X", binary.BigEndian.Uint16(b[0:2])),
		LegacyVersion:    versionName(binary.BigEndian.Uint16(b[0:2])),
		RandomHex:        strings.ToUpper(hex.EncodeToString(b[2:34])),
	}
	off := 34
	sidLen := int(b[off])
	off++
	if off+sidLen > len(b) {
		return sh
	}
	sh.SessionIDLength = sidLen
	if sidLen > 0 {
		sh.SessionIDHex = strings.ToUpper(hex.EncodeToString(b[off : off+sidLen]))
	}
	off += sidLen
	if off+3 > len(b) {
		return sh
	}
	sh.CipherSuiteHex = fmt.Sprintf("0x%04X", binary.BigEndian.Uint16(b[off:off+2]))
	off += 2
	sh.CompressionMethod = int(b[off])
	off++
	if off+2 > len(b) {
		return sh
	}
	extLen := int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	if off+extLen > len(b) {
		return sh
	}
	sh.ExtensionsLength = extLen
	if extLen > 0 {
		sh.ExtensionsHex = strings.ToUpper(hex.EncodeToString(b[off : off+extLen]))
	}
	return sh
}

func decodeHelloVerifyRequest(b []byte) *HelloVerifyRequest {
	if len(b) < 3 {
		return nil
	}
	hvr := &HelloVerifyRequest{
		ServerVersionHex: fmt.Sprintf("0x%04X", binary.BigEndian.Uint16(b[0:2])),
		ServerVersion:    versionName(binary.BigEndian.Uint16(b[0:2])),
	}
	cookieLen := int(b[2])
	if 3+cookieLen > len(b) {
		return hvr
	}
	hvr.CookieLength = cookieLen
	if cookieLen > 0 {
		hvr.CookieHex = strings.ToUpper(hex.EncodeToString(b[3 : 3+cookieLen]))
	}
	return hvr
}

func contentTypeName(t int) string {
	switch t {
	case 20:
		return "ChangeCipherSpec"
	case 21:
		return "Alert"
	case 22:
		return "Handshake"
	case 23:
		return "ApplicationData"
	case 24:
		return "Heartbeat"
	}
	return fmt.Sprintf("Unknown (0x%02X)", t)
}

func versionName(v uint16) string {
	switch v {
	case 0xFEFF:
		return "DTLS 1.0"
	case 0xFEFD:
		return "DTLS 1.2"
	case 0xFEFC:
		return "DTLS 1.3"
	}
	return fmt.Sprintf("unknown 0x%04X", v)
}

func handshakeTypeName(t int) string {
	switch t {
	case 0:
		return "HelloRequest"
	case 1:
		return "ClientHello"
	case 2:
		return "ServerHello"
	case 3:
		return "HelloVerifyRequest"
	case 4:
		return "NewSessionTicket"
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
	}
	return fmt.Sprintf("Unknown handshake type %d", t)
}

func alertLevelName(l int) string {
	switch l {
	case 1:
		return "warning"
	case 2:
		return "fatal"
	}
	return fmt.Sprintf("level %d", l)
}

func alertDescriptionName(d int) string {
	switch d {
	case 0:
		return "close_notify"
	case 10:
		return "unexpected_message"
	case 20:
		return "bad_record_mac"
	case 21:
		return "decryption_failed"
	case 22:
		return "record_overflow"
	case 30:
		return "decompression_failure"
	case 40:
		return "handshake_failure"
	case 41:
		return "no_certificate (TLS 1.0)"
	case 42:
		return "bad_certificate"
	case 43:
		return "unsupported_certificate"
	case 44:
		return "certificate_revoked"
	case 45:
		return "certificate_expired"
	case 46:
		return "certificate_unknown"
	case 47:
		return "illegal_parameter"
	case 48:
		return "unknown_ca"
	case 49:
		return "access_denied"
	case 50:
		return "decode_error"
	case 51:
		return "decrypt_error"
	case 60:
		return "export_restriction"
	case 70:
		return "protocol_version"
	case 71:
		return "insufficient_security"
	case 80:
		return "internal_error"
	case 90:
		return "user_canceled"
	case 100:
		return "no_renegotiation"
	case 110:
		return "unsupported_extension"
	}
	return fmt.Sprintf("alert %d", d)
}

func heartbeatTypeName(t int) string {
	switch t {
	case 1:
		return "Request"
	case 2:
		return "Response"
	}
	return fmt.Sprintf("type %d", t)
}

func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
