// Package hartip decodes HART-IP (Highway Addressable Remote
// Transducer over IP) messages per the HART Foundation
// specification (HCF_SPEC-085 + the HART-IP wire format
// reference). HART-IP encapsulates **HART field-instrument
// messages over IP** (UDP or TCP port 5094 by default),
// extending the 30-year-old HART industrial-instrumentation
// protocol that originally ran on top of the 4-20 mA current
// loop into modern Ethernet-connected control systems.
//
// Operationally, HART-IP is the wire format on the boundary
// between **modern DCS / SCADA layers** (Emerson DeltaV,
// Honeywell Experion, ABB Ability, Yokogawa CENTUM, Schneider
// Foxboro Evo) and **HART-capable field instruments**
// (pressure transmitters, flow meters, temperature sensors,
// control valves with smart positioners — Rosemount, Endress+
// Hauser, Yokogawa EJX, ABB, Honeywell SmartLine). Every
// modern multiplexer + I/O network from these vendors speaks
// HART-IP either natively or via a WirelessHART gateway. It
// is interesting to an ICS pentester because:
//
//   - **Calibration tampering** — a HART command sent over
//     HART-IP can re-trim a transmitter's range, shift its
//     zero point, or change its damping constant — a
//     subtle process attack that bypasses control-system
//     bound checks.
//   - **Device enumeration** — HART command 0 (Read Unique
//     Identifier) over HART-IP enumerates every reachable
//     HART device, leaking manufacturer + device type + tag
//   - serial number.
//   - **Configuration disclosure** — HART command 13 + 18
//     reveal Tag + Date + Descriptor + Message fields used
//     to label the device in the plant historian — useful
//     for AD-style lateral identification in process
//     networks.
//   - **Process pentest CTFs** — DEF CON ICS Village + S4
//     Symposium + ICSjwt CTF challenges that hand out HART-
//     IP captures.
//
// Wrap-vs-native judgement
//
//	Native. The HART-IP envelope is a tight 8-byte header
//	(Version + Message Type + Message ID + Status + Sequence
//	Number + Byte Count) with a 4-entry Message Type registry
//	and a 6-entry Message ID registry; both are publicly
//	documented. The encapsulated HART payload itself follows
//	the HART layer-7 wire format which is a separate decoder
//	(HART command frames have their own complexity — short/
//	long address forms, command codes 0-255, per-command
//	data shapes); the decoder surfaces the HART payload as
//	`hart_payload_hex` for downstream HART-command walkers.
//	No crypto at the parse layer.
//
// What this package covers
//
//   - **HART-IP envelope header** (HCF_SPEC-085, 8 bytes;
//     multi-byte fields are big-endian):
//
//   - byte 0: Version (= 0x01 for the current HART-IP).
//
//   - byte 1: **Message Type** (1 byte; the request /
//     response / publish discriminator).
//
//   - byte 2: **Message ID** (1 byte; the session-control
//     / payload-kind discriminator).
//
//   - byte 3: Status Code (1 byte; per-Message-Type
//     status; 0 = success in responses).
//
//   - bytes 4-5: Sequence Number (uint16 BE; per-session
//     monotonic counter pairing requests + responses).
//
//   - bytes 6-7: Byte Count (uint16 BE; bytes of HART
//     payload that follow this 8-byte header).
//
//   - **4-entry Message Type name table** (HCF_SPEC-085
//     §6.2.1): 0 `Request` (host → field device) / 1
//     `Response` (field device → host) / 2 `Publish` (field
//     device unsolicited burst notification) / 3 `NAK`
//     (negative acknowledgement — request was malformed or
//     rejected before reaching the HART layer).
//
//   - **6-entry Message ID name table** (HCF_SPEC-085 §6.2.2):
//     0 `Session_Initiate` (open a HART-IP session) / 1
//     `Session_Close` / 2 `Keep_Alive` (idle-timer reset) / 3
//     `HART_PDU` (carries a HART command in payload — the
//     overwhelmingly common case) / 4 `Direct_PDU` (direct
//     HART-message passthrough without HART-IP routing) /
//     128 `Publish_Burst_Notify` (Publish-direction
//     equivalent of HART_PDU).
//
//   - **HART payload** — bytes after the 8-byte header are
//     the encapsulated HART command frame; surfaced as
//     `hart_payload_hex` for downstream HART-command-level
//     decoders (per-Command-Code decoders for Cmd 0 Read
//     Unique Identifier, Cmd 13/18 Read Tag/Descriptor,
//     Cmd 42 Device Reset, Cmd 48 Read Additional Device
//     Status, etc.).
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Network framing** — feed HART-IP bytes after the UDP-
//     datagram or TCP-segment header strip (default UDP/TCP
//     port 5094).
//   - **Inner HART command decoders** — the HART layer-7 wire
//     format (Frame Type + Delimiter + Address (short or long
//     form) + Command Code + Byte Count + Response Code +
//     Device Status + Data + Checksum) is a separate decoder;
//     surfaced as `hart_payload_hex`. The per-command data
//     shapes (255 catalogued Command Codes) are dataset-
//     specific and out of scope for the envelope decoder.
//   - **WirelessHART (IEC 62591)** — the wireless mesh variant
//     uses a different per-frame format on the air interface;
//     gateway-side WirelessHART-over-HART-IP is in scope but
//     the wireless-side IEEE 802.15.4 mesh is not.
//   - **HART-IP Session State-Machine** — connection setup,
//     keep-alive timer (default 5 s), session resumption, and
//     re-keying are higher-level concerns.
//   - **Status code semantics** — the Status Code byte is
//     surfaced as a number; per-Message-Type interpretation
//     (different in NAK vs Response) is out of scope.
package hartip

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the structured decode of a HART-IP message.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// Envelope
	Version         int    `json:"version"`
	MessageType     int    `json:"message_type"`
	MessageTypeName string `json:"message_type_name"`
	MessageID       int    `json:"message_id"`
	MessageIDName   string `json:"message_id_name"`
	StatusCode      int    `json:"status_code"`
	SequenceNumber  int    `json:"sequence_number"`
	ByteCount       int    `json:"byte_count"`

	// HART payload (encapsulated HART command frame).
	HartPayloadHex string `json:"hart_payload_hex,omitempty"`
}

// Decode parses a HART-IP message from a hex string starting at
// the Version byte. Separators (':' '-' '_' whitespace)
// tolerated; '0x' prefix tolerated.
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
		return nil, fmt.Errorf("HART-IP message truncated (%d bytes; need ≥8 for envelope header)",
			len(b))
	}

	r := &Result{
		TotalBytes:     len(b),
		Version:        int(b[0]),
		MessageType:    int(b[1]),
		MessageID:      int(b[2]),
		StatusCode:     int(b[3]),
		SequenceNumber: int(binary.BigEndian.Uint16(b[4:6])),
		ByteCount:      int(binary.BigEndian.Uint16(b[6:8])),
	}
	r.MessageTypeName = messageTypeName(r.MessageType)
	r.MessageIDName = messageIDName(r.MessageID)

	// Encapsulated HART payload (bytes 8 .. 8+ByteCount).
	end := 8 + r.ByteCount
	if end > len(b) {
		end = len(b)
	}
	if end > 8 {
		r.HartPayloadHex = strings.ToUpper(hex.EncodeToString(b[8:end]))
	}
	return r, nil
}

func messageTypeName(t int) string {
	switch t {
	case 0:
		return "Request"
	case 1:
		return "Response"
	case 2:
		return "Publish"
	case 3:
		return "NAK"
	}
	return fmt.Sprintf("uncatalogued message type %d", t)
}

func messageIDName(i int) string {
	switch i {
	case 0:
		return "Session_Initiate"
	case 1:
		return "Session_Close"
	case 2:
		return "Keep_Alive"
	case 3:
		return "HART_PDU"
	case 4:
		return "Direct_PDU"
	case 128:
		return "Publish_Burst_Notify"
	}
	return fmt.Sprintf("uncatalogued message ID %d", i)
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
