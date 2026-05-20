// Package ike decodes IKEv2 (Internet Key Exchange version 2)
// messages per RFC 7296. IKEv2 is the control-plane protocol
// that negotiates the IPsec Security Associations (SAs)
// consumed by ESP (RFC 4303, covered by `esp_decode`) and AH
// (RFC 4302, covered by `ah_decode`). Without IKE the SPIs +
// keys + algorithms ESP/AH need come from nowhere; with IKEv2
// we decode the negotiation that produces them.
//
// IKEv2 is universal on every site-to-site VPN + IPsec
// remote-access deployment — StrongSwan, OpenSwan/Libreswan,
// Cisco AnyConnect IPsec mode, FortiGate, pfSense, OPNsense,
// Windows IPsec, macOS IKEv2 client. Runs on UDP destination
// port 500, or UDP 4500 with a 4-byte all-zeros marker when
// behind NAT (NAT-T per RFC 3947 / 3948).
//
// Wrap-vs-native judgement
//
//	Native. RFC 7296 is fully public. IKEv2 has a tight
//	28-byte fixed header followed by a chained list of
//	payloads (each a 4-byte header + body). The first
//	exchange (IKE_SA_INIT) is sent unencrypted so SA
//	proposals, KE shares, nonces, and NAT-T markers are
//	decoded fully; from IKE_AUTH onwards the payload bodies
//	are wrapped in an Encrypted (SK) payload whose
//	plaintext is opaque without the IKE-derived keys
//	(surfaced as hex; full decryption would require an
//	IKE-state-aware iteration).
//
// What this package covers
//
//   - **28-byte fixed header** (RFC 7296 §3.1):
//
//   - bytes 0-7: Initiator SPI (uint64 BE; the SA's
//     initiator-side identifier).
//
//   - bytes 8-15: Responder SPI (uint64 BE; zero in the
//     first IKE_SA_INIT request, set in the reply).
//
//   - byte 16: Next Payload (first payload's type code).
//
//   - byte 17: Version (4-bit Major / 4-bit Minor;
//     2/0 for IKEv2).
//
//   - byte 18: **Exchange Type** with **4-entry name
//     table** (RFC 7296 §3.1): 34 IKE_SA_INIT, 35
//     IKE_AUTH, 36 CREATE_CHILD_SA, 37 INFORMATIONAL.
//
//   - byte 19: **Flags** decoded into **3 named bits**:
//     R (Response — 0x20), V (Version — 0x10; only set
//     by responders), I (Initiator — 0x08).
//
//   - bytes 20-23: Message ID (uint32 BE; per-SA
//     monotonic; matches request/reply).
//
//   - bytes 24-27: Length (uint32 BE; total message
//     length including this header).
//
//   - **Payload walker** — chained list driven by the
//     Next Payload field of the previous payload (or of
//     the IKE header for the first). Each payload header
//     is 4 bytes: Next Payload (1B) + Critical (1B; high
//     bit only) + Payload Length (uint16 BE; total
//     including this 4-byte header). Walker terminates
//     when Next Payload = 0.
//
//   - **~15-entry payload type name table** (RFC 7296
//     §3.2 + IANA "IKEv2 Payload Types" registry):
//     33 SA (Security Association proposal/transform tree)
//     / 34 KE (Key Exchange — DH/ECDH public value) /
//     35 IDi (Identification - Initiator) / 36 IDr
//     (Identification - Responder) / 37 CERT
//     (Certificate) / 38 CERTREQ (Certificate Request) /
//     39 AUTH (Authentication — signature/PSK proof) /
//     40 Ni or Nr (Nonce) / 41 N (Notify — error /
//     status / capability) / 42 D (Delete — tear down
//     SAs) / 43 V (Vendor ID — feature negotiation) /
//     44 TSi (Traffic Selector - Initiator) / 45 TSr
//     (Traffic Selector - Responder) / 46 SK (Encrypted
//     and Authenticated — wraps inner payloads from
//     IKE_AUTH onwards) / 47 CP (Configuration —
//     remote-access settings like IP allocation) /
//     48 EAP (Extensible Authentication Protocol).
//
//   - **N (Notify) payload body** (Type 41; RFC 7296
//     §3.10): 1-byte Protocol ID (0 IKE / 2 AH / 3 ESP)
//
//   - 1-byte SPI Size + 2-byte **Notify Message Type**
//     resolved via a **~30-entry name table** covering
//     the most common error / status codes:
//     **Errors**: 1 UNSUPPORTED_CRITICAL_PAYLOAD / 4
//     INVALID_IKE_SPI / 5 INVALID_MAJOR_VERSION / 7
//     INVALID_SYNTAX / 9 INVALID_MESSAGE_ID / 11
//     INVALID_SPI / 14 NO_PROPOSAL_CHOSEN / 17
//     INVALID_KE_PAYLOAD / 24 AUTHENTICATION_FAILED /
//     34 SINGLE_PAIR_REQUIRED / 35 NO_ADDITIONAL_SAS /
//     36 INTERNAL_ADDRESS_FAILURE / 37 FAILED_CP_REQUIRED
//     / 38 TS_UNACCEPTABLE / 39 INVALID_SELECTORS / 43
//     TEMPORARY_FAILURE / 44 CHILD_SA_NOT_FOUND.
//     **Status**: 16384 INITIAL_CONTACT / 16385
//     SET_WINDOW_SIZE / 16386 ADDITIONAL_TS_POSSIBLE /
//     16387 IPCOMP_SUPPORTED / 16388
//     NAT_DETECTION_SOURCE_IP / 16389
//     NAT_DETECTION_DESTINATION_IP / 16390 COOKIE / 16391
//     USE_TRANSPORT_MODE / 16393 REKEY_SA / 16395
//     NON_FIRST_FRAGMENTS_ALSO / 16404 MOBIKE_SUPPORTED
//     / 16407 NO_NATS_ALLOWED / 16408 AUTH_LIFETIME /
//     16431 SIGNATURE_HASH_ALGORITHMS.
//
//   - **SK (Encrypted) payload** (Type 46) — surfaced
//     with the encrypted body as opaque hex pending the
//     IKE-derived keys. The body wraps inner payloads
//     (the Next Payload of the SK header names the type
//     of the first inner payload).
//
// What this package does NOT cover (deliberately out of scope)
//
//   - UDP framing — feed IKE bytes after the UDP header
//     strip. IKE runs on UDP destination port 500 (or
//     4500 with a 4-byte all-zeros marker prefix when
//     behind NAT, per RFC 3948 NAT-T).
//
//   - SA proposal/transform tree deep dissection — the
//     SA payload (Type 33) contains a nested list of
//     Proposals + Transforms (encryption / integrity /
//     PRF / DH algorithms negotiated); surfaced as
//     opaque hex; would warrant a separate iteration.
//
//   - KE / Ni / Nr / IDi / IDr / AUTH / CERT body
//     dissection — surfaced as opaque hex; per-body
//     decoders are future work.
//
//   - SK payload decryption — requires the SK_e/SK_a
//     keys derived from the IKE_SA_INIT KE + Nonce
//     exchange; surfaced as opaque hex with an
//     encryption note.
//
//   - IKEv1 (RFC 2409) — different header (8-byte SPIs
//
//   - Initiator Cookie / Responder Cookie naming +
//     Exchange Type code 1-5 mapping to Identity
//     Protection / Aggressive / Authentication Only /
//     Informational / Quick Mode); long-deprecated but
//     still seen in legacy deployments; would warrant
//     its own Spec.
//
//   - NAT-T marker stripping — when the 4-byte all-zeros
//     marker is present (UDP port 4500), the operator
//     must strip it before feeding bytes into this
//     decoder. ESP-in-UDP (RFC 3948) doesn't have the
//     all-zeros marker, so the demux is unambiguous.
package ike

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the top-level decoded view of an IKEv2 message.
type Result struct {
	InitiatorSPI     uint64    `json:"initiator_spi"`
	InitiatorSPIHex  string    `json:"initiator_spi_hex"`
	ResponderSPI     uint64    `json:"responder_spi"`
	ResponderSPIHex  string    `json:"responder_spi_hex"`
	FirstPayloadType int       `json:"first_payload_type"`
	FirstPayloadName string    `json:"first_payload_name"`
	VersionMajor     int       `json:"version_major"`
	VersionMinor     int       `json:"version_minor"`
	ExchangeType     int       `json:"exchange_type"`
	ExchangeTypeName string    `json:"exchange_type_name"`
	FlagResponse     bool      `json:"flag_response"`
	FlagVersion      bool      `json:"flag_version"`
	FlagInitiator    bool      `json:"flag_initiator"`
	MessageID        uint32    `json:"message_id"`
	Length           uint32    `json:"length"`
	Payloads         []Payload `json:"payloads"`
	TotalBytes       int       `json:"total_bytes"`
	Notes            []string  `json:"notes,omitempty"`
}

// Payload is one (Next Payload, Critical, Length, Body) record
// from the payload walker.
type Payload struct {
	Type     int    `json:"type"`
	TypeName string `json:"type_name"`
	NextType int    `json:"next_type"`
	Critical bool   `json:"critical"`
	Length   int    `json:"length"`
	BodyHex  string `json:"body_hex,omitempty"`

	// Decoded forms populated for known payload types.
	Notify    *NotifyBody `json:"notify,omitempty"`
	Encrypted *SKBody     `json:"encrypted,omitempty"`
}

// NotifyBody is the decoded body of an N (Notify) payload.
type NotifyBody struct {
	ProtocolID          int    `json:"protocol_id"`
	ProtocolIDName      string `json:"protocol_id_name"`
	SPISize             int    `json:"spi_size"`
	NotifyMessageType   int    `json:"notify_message_type"`
	NotifyMessageName   string `json:"notify_message_name"`
	NotifyMessageClass  string `json:"notify_message_class"`
	SPIHex              string `json:"spi_hex,omitempty"`
	NotificationDataHex string `json:"notification_data_hex,omitempty"`
}

// SKBody is the decoded view of an SK (Encrypted) payload.
type SKBody struct {
	EncryptedBytes int    `json:"encrypted_bytes"`
	EncryptedHex   string `json:"encrypted_hex,omitempty"`
	Note           string `json:"note"`
}

// DecodeOpts tunes the walker for output size.
type DecodeOpts struct {
	// MaxPayloadBodyBytes caps the per-payload body hex
	// preview (default 256). Zero shows the full body.
	MaxPayloadBodyBytes int
}

// DefaultDecodeOpts returns a 256-byte body preview cap.
func DefaultDecodeOpts() DecodeOpts {
	return DecodeOpts{MaxPayloadBodyBytes: 256}
}

// Decode parses a single IKEv2 message from hex.
func Decode(hexStr string, opts DecodeOpts) (*Result, error) {
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
	if len(b) < 28 {
		return nil, fmt.Errorf("IKEv2 message truncated (%d bytes; need ≥28 for header)",
			len(b))
	}
	r := &Result{
		TotalBytes:       len(b),
		InitiatorSPI:     binary.BigEndian.Uint64(b[0:8]),
		ResponderSPI:     binary.BigEndian.Uint64(b[8:16]),
		FirstPayloadType: int(b[16]),
		VersionMajor:     int(b[17] >> 4),
		VersionMinor:     int(b[17] & 0x0F),
		ExchangeType:     int(b[18]),
		FlagResponse:     b[19]&0x20 != 0,
		FlagVersion:      b[19]&0x10 != 0,
		FlagInitiator:    b[19]&0x08 != 0,
		MessageID:        binary.BigEndian.Uint32(b[20:24]),
		Length:           binary.BigEndian.Uint32(b[24:28]),
	}
	r.InitiatorSPIHex = fmt.Sprintf("0x%016X", r.InitiatorSPI)
	r.ResponderSPIHex = fmt.Sprintf("0x%016X", r.ResponderSPI)
	r.FirstPayloadName = payloadTypeName(r.FirstPayloadType)
	r.ExchangeTypeName = exchangeTypeName(r.ExchangeType)
	if r.VersionMajor != 2 {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"version is %d.%d (this Spec covers IKEv2 / version 2.0 only)",
			r.VersionMajor, r.VersionMinor))
	}
	if int(r.Length) != len(b) {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"header declares length %d but %d bytes provided", r.Length, len(b)))
	}
	r.Payloads = decodePayloads(b[28:], r.FirstPayloadType, opts)
	return r, nil
}

func decodePayloads(b []byte, nextType int, opts DecodeOpts) []Payload {
	var out []Payload
	off := 0
	for nextType != 0 && off+4 <= len(b) {
		nt := int(b[off])
		crit := b[off+1]&0x80 != 0
		ln := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		if ln < 4 || off+ln > len(b) {
			return out
		}
		body := b[off+4 : off+ln]
		p := Payload{
			Type:     nextType,
			TypeName: payloadTypeName(nextType),
			NextType: nt,
			Critical: crit,
			Length:   ln,
		}
		show := len(body)
		if opts.MaxPayloadBodyBytes > 0 && show > opts.MaxPayloadBodyBytes {
			show = opts.MaxPayloadBodyBytes
		}
		if show > 0 {
			p.BodyHex = strings.ToUpper(hex.EncodeToString(body[:show]))
		}
		switch nextType {
		case 41: // N (Notify)
			p.Notify = decodeNotify(body)
		case 46: // SK (Encrypted)
			p.Encrypted = &SKBody{
				EncryptedBytes: len(body),
				EncryptedHex:   strings.ToUpper(hex.EncodeToString(body[:show])),
				Note: "SK payload is encrypted with the IKE-derived SK_e/SK_a keys; " +
					"full decryption requires the SA's KE + Nonce + PRF state from IKE_SA_INIT",
			}
		}
		out = append(out, p)
		nextType = nt
		off += ln
	}
	return out
}

func decodeNotify(b []byte) *NotifyBody {
	if len(b) < 4 {
		return nil
	}
	n := &NotifyBody{
		ProtocolID:        int(b[0]),
		SPISize:           int(b[1]),
		NotifyMessageType: int(binary.BigEndian.Uint16(b[2:4])),
	}
	n.ProtocolIDName = ikeProtocolIDName(n.ProtocolID)
	n.NotifyMessageName = notifyMessageTypeName(n.NotifyMessageType)
	n.NotifyMessageClass = notifyMessageClass(n.NotifyMessageType)
	off := 4
	if n.SPISize > 0 && off+n.SPISize <= len(b) {
		n.SPIHex = strings.ToUpper(hex.EncodeToString(b[off : off+n.SPISize]))
		off += n.SPISize
	}
	if off < len(b) {
		n.NotificationDataHex = strings.ToUpper(hex.EncodeToString(b[off:]))
	}
	return n
}

func exchangeTypeName(t int) string {
	switch t {
	case 34:
		return "IKE_SA_INIT"
	case 35:
		return "IKE_AUTH"
	case 36:
		return "CREATE_CHILD_SA"
	case 37:
		return "INFORMATIONAL"
	}
	return fmt.Sprintf("uncatalogued exchange type %d", t)
}

func payloadTypeName(t int) string {
	switch t {
	case 0:
		return "(end of chain)"
	case 33:
		return "SA (Security Association)"
	case 34:
		return "KE (Key Exchange)"
	case 35:
		return "IDi (Identification - Initiator)"
	case 36:
		return "IDr (Identification - Responder)"
	case 37:
		return "CERT (Certificate)"
	case 38:
		return "CERTREQ (Certificate Request)"
	case 39:
		return "AUTH (Authentication)"
	case 40:
		return "Ni/Nr (Nonce)"
	case 41:
		return "N (Notify)"
	case 42:
		return "D (Delete)"
	case 43:
		return "V (Vendor ID)"
	case 44:
		return "TSi (Traffic Selector - Initiator)"
	case 45:
		return "TSr (Traffic Selector - Responder)"
	case 46:
		return "SK (Encrypted and Authenticated)"
	case 47:
		return "CP (Configuration)"
	case 48:
		return "EAP (Extensible Authentication Protocol)"
	}
	return fmt.Sprintf("uncatalogued payload type %d", t)
}

func ikeProtocolIDName(p int) string {
	switch p {
	case 0:
		return "IKE"
	case 2:
		return "AH"
	case 3:
		return "ESP"
	}
	return fmt.Sprintf("uncatalogued protocol %d", p)
}

func notifyMessageClass(t int) string {
	switch {
	case t >= 1 && t < 8192:
		return "Error"
	case t >= 16384:
		return "Status"
	}
	return "Reserved"
}

func notifyMessageTypeName(t int) string {
	switch t {
	// Errors
	case 1:
		return "UNSUPPORTED_CRITICAL_PAYLOAD"
	case 4:
		return "INVALID_IKE_SPI"
	case 5:
		return "INVALID_MAJOR_VERSION"
	case 7:
		return "INVALID_SYNTAX"
	case 9:
		return "INVALID_MESSAGE_ID"
	case 11:
		return "INVALID_SPI"
	case 14:
		return "NO_PROPOSAL_CHOSEN"
	case 17:
		return "INVALID_KE_PAYLOAD"
	case 24:
		return "AUTHENTICATION_FAILED"
	case 34:
		return "SINGLE_PAIR_REQUIRED"
	case 35:
		return "NO_ADDITIONAL_SAS"
	case 36:
		return "INTERNAL_ADDRESS_FAILURE"
	case 37:
		return "FAILED_CP_REQUIRED"
	case 38:
		return "TS_UNACCEPTABLE"
	case 39:
		return "INVALID_SELECTORS"
	case 43:
		return "TEMPORARY_FAILURE"
	case 44:
		return "CHILD_SA_NOT_FOUND"
	// Status
	case 16384:
		return "INITIAL_CONTACT"
	case 16385:
		return "SET_WINDOW_SIZE"
	case 16386:
		return "ADDITIONAL_TS_POSSIBLE"
	case 16387:
		return "IPCOMP_SUPPORTED"
	case 16388:
		return "NAT_DETECTION_SOURCE_IP"
	case 16389:
		return "NAT_DETECTION_DESTINATION_IP"
	case 16390:
		return "COOKIE"
	case 16391:
		return "USE_TRANSPORT_MODE"
	case 16393:
		return "REKEY_SA"
	case 16395:
		return "NON_FIRST_FRAGMENTS_ALSO"
	case 16404:
		return "MOBIKE_SUPPORTED"
	case 16407:
		return "NO_NATS_ALLOWED"
	case 16408:
		return "AUTH_LIFETIME"
	case 16431:
		return "SIGNATURE_HASH_ALGORITHMS"
	}
	return fmt.Sprintf("uncatalogued notify type %d", t)
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
