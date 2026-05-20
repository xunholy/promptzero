// Package mqttsn decodes MQTT-SN (MQTT for Sensor Networks) v1.2
// messages per the OASIS MQTT-SN specification. MQTT-SN is the
// **UDP variant of MQTT** designed for constrained IoT devices
// (battery-powered sensors, 6LoWPAN endpoints, sub-GHz mesh
// leaves) that cannot afford the overhead of MQTT's TCP +
// CONNECT/CONNACK + TLS stack.
//
// Operationally, MQTT-SN runs over UDP/1883 between a sensor and
// an MQTT-SN Gateway (the gateway translates SN messages back
// into native MQTT for upstream brokers). It is interesting to a
// pentester / IoT researcher because:
//
//   - **Sub-GHz IoT pentest** — many LoRaWAN / Zigbee / 6LoWPAN
//     gateways speak MQTT-SN over the IP backhaul; sniffing the
//     gateway uplink reveals device telemetry without breaking
//     the sub-GHz crypto.
//   - **Industrial IoT (IIoT)** — Bosch, Siemens, ABB, and many
//     industrial sensor vendors ship MQTT-SN-capable firmware
//     for low-power telemetry to a plant-floor gateway.
//   - **Default-credential exposure** — like MQTT, MQTT-SN
//     deployments frequently ship without authentication; the
//     CONNECT message exposes the ClientId (often containing
//     hostname + MAC + serial) for asset enumeration.
//   - **Topic enumeration** — REGISTER / PUBLISH messages
//     expose the per-device topic namespace, leaking firmware
//     version + sensor metadata.
//
// Wrap-vs-native judgement
//
//	Native. The MQTT-SN v1.2 OASIS specification is publicly
//	available and the wire format is tight (1-byte or 3-byte
//	length header + 1-byte MsgType + per-MsgType body). The
//	28 catalogued MsgTypes map to documented payload shapes,
//	with the per-MsgType Flags byte and ReturnCode name table
//	being the highest-value decode artefacts. No crypto at the
//	parse layer (MQTT-SN v1.2 has no built-in auth; MQTT-SN
//	1.3 + DTLS is a future extension).
//
// What this package covers
//
//   - **Variable-length header** (OASIS MQTT-SN v1.2 §5.2.1):
//
//   - byte 0: **Length** (1-255 short form; 0x01 = long-form
//     indicator, then bytes 1-2 = uint16 BE length).
//
//   - byte 1 (short) or byte 3 (long): **MsgType** (1 byte;
//     28-entry name table per §5.2.3).
//
//   - **28-entry MsgType name table** (OASIS MQTT-SN v1.2
//     §5.2.3): 0x00 `ADVERTISE` (gateway broadcasts itself to
//     clients on the LAN) / 0x01 `SEARCHGW` (client searches
//     for a gateway) / 0x02 `GWINFO` (gateway response to
//     SEARCHGW) / 0x04 `CONNECT` (client connects with
//     ClientId) / 0x05 `CONNACK` (server confirms connection)
//     / 0x06 `WILLTOPICREQ` / 0x07 `WILLTOPIC` / 0x08
//     `WILLMSGREQ` / 0x09 `WILLMSG` / 0x0A `REGISTER` (assign
//     a 2-byte TopicId to a topic name to save bandwidth) /
//     0x0B `REGACK` / 0x0C `PUBLISH` (the actual telemetry
//     message — uses TopicId not topic string) / 0x0D
//     `PUBACK` / 0x0E `PUBCOMP` / 0x0F `PUBREC` / 0x10
//     `PUBREL` / 0x12 `SUBSCRIBE` / 0x13 `SUBACK` / 0x14
//     `UNSUBSCRIBE` / 0x15 `UNSUBACK` / 0x16 `PINGREQ` / 0x17
//     `PINGRESP` / 0x18 `DISCONNECT` / 0x1A `WILLTOPICUPD` /
//     0x1B `WILLTOPICRESP` / 0x1C `WILLMSGUPD` / 0x1D
//     `WILLMSGRESP`.
//
//   - **Flags byte** (in CONNECT / PUBLISH / SUBSCRIBE / WILL
//     messages, OASIS MQTT-SN v1.2 §5.3.2):
//
//   - bit 7: `DUP` (duplicate retransmission).
//
//   - bits 6-5: `QoS` (00 → 0; 01 → 1; 10 → 2; 11 → -1, the
//     MQTT-SN-specific "fire-and-forget" QoS).
//
//   - bit 4: `Retain`.
//
//   - bit 3: `Will` (CONNECT only — indicates the client will
//     follow up with WILLTOPIC + WILLMSG).
//
//   - bit 2: `CleanSession`.
//
//   - bits 1-0: `TopicIdType` (0 → normal / registered TopicId;
//     1 → predefined TopicId; 2 → short topic name; 3 →
//     reserved).
//
//   - **Per-MsgType body decoders**:
//
//   - **CONNECT** (0x04): 1-byte Flags + 1-byte ProtocolId
//     (= 0x01) + 2-byte Duration (uint16 BE keep-alive
//     seconds) + variable ClientId UTF-8 string.
//
//   - **CONNACK** (0x05): 1-byte ReturnCode (name-table
//     decoded).
//
//   - **REGISTER** (0x0A): 2-byte TopicId + 2-byte MsgId +
//     variable TopicName UTF-8 string.
//
//   - **REGACK** (0x0B): 2-byte TopicId + 2-byte MsgId +
//     1-byte ReturnCode.
//
//   - **PUBLISH** (0x0C): 1-byte Flags + 2-byte TopicId +
//     2-byte MsgId + variable Data bytes (surfaced as hex
//     since payloads are dataset-specific binary or
//     sensor-encoded values).
//
//   - **PUBACK** (0x0D): 2-byte TopicId + 2-byte MsgId +
//     1-byte ReturnCode.
//
//   - **SUBSCRIBE** (0x12): 1-byte Flags + 2-byte MsgId +
//     variable TopicId (2 bytes for predefined / short) or
//     TopicName UTF-8 string depending on TopicIdType.
//
//   - **SUBACK** (0x13): 1-byte Flags + 2-byte TopicId +
//     2-byte MsgId + 1-byte ReturnCode.
//
//   - **DISCONNECT** (0x18): optional 2-byte Duration
//     (uint16 BE; if present indicates the client is going
//     to sleep mode for this many seconds — the gateway
//     buffers messages until PINGREQ wake-up).
//
//   - **ADVERTISE** (0x00): 1-byte GwId + 2-byte Duration.
//
//   - **GWINFO** (0x02): 1-byte GwId + optional variable
//     GwAdd (the gateway's L3 address).
//
//   - **4-entry ReturnCode name table** (OASIS MQTT-SN v1.2
//     §5.3.4): 0x00 `Accepted` / 0x01 `Rejected_congestion`
//     / 0x02 `Rejected_invalid_topic_ID` / 0x03
//     `Rejected_not_supported`.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Network framing** — feed MQTT-SN bytes after the UDP-
//     datagram header strip (default UDP port 1883).
//   - **MQTT-SN over DTLS** — MQTT-SN v1.3 (and some v1.2
//     gateways) wrap the protocol in DTLS for transport
//     authentication + confidentiality; handle the DTLS strip
//     first.
//   - **MQTT-SN-Gateway state-machine** — the gateway holds per-
//     client SubscriptionTable / RegisteredTopics state and
//     handles the buffer-during-sleep semantics for low-power
//     clients; higher-level analysis.
//   - **Per-Data payload decoding** — PUBLISH Data bytes are
//     surfaced as raw hex since the per-device telemetry
//     encoding (CBOR / MessagePack / Sigfox-RC / vendor binary)
//     is dataset-specific.
//   - **Topic-name resolution** — the TopicId-to-TopicName
//     mapping is established by REGISTER / REGACK pairs at
//     session-start time and held in per-client state; this
//     decoder surfaces the raw TopicId (uint16) but does not
//     resolve it without state.
package mqttsn

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the structured decode of an MQTT-SN message.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// Header
	Length      int    `json:"length"`
	LongFormat  bool   `json:"long_format"`
	MsgType     int    `json:"msg_type"`
	MsgTypeName string `json:"msg_type_name"`

	// Flags byte (when present)
	FlagsHex        string `json:"flags_hex,omitempty"`
	DUP             bool   `json:"dup,omitempty"`
	QoS             int    `json:"qos,omitempty"`
	Retain          bool   `json:"retain,omitempty"`
	Will            bool   `json:"will,omitempty"`
	CleanSession    bool   `json:"clean_session,omitempty"`
	TopicIDType     int    `json:"topic_id_type,omitempty"`
	TopicIDTypeName string `json:"topic_id_type_name,omitempty"`

	// Per-MsgType fields (only one set populated).
	ProtocolID     int    `json:"protocol_id,omitempty"`
	Duration       int    `json:"duration,omitempty"`
	ClientID       string `json:"client_id,omitempty"`
	ReturnCode     int    `json:"return_code,omitempty"`
	ReturnCodeName string `json:"return_code_name,omitempty"`
	TopicID        int    `json:"topic_id,omitempty"`
	MsgID          int    `json:"msg_id,omitempty"`
	TopicName      string `json:"topic_name,omitempty"`
	DataHex        string `json:"data_hex,omitempty"`
	GwID           int    `json:"gw_id,omitempty"`
	GwAddHex       string `json:"gw_add_hex,omitempty"`

	// Trailing bytes the per-MsgType decoder didn't consume.
	PayloadHex string `json:"payload_hex,omitempty"`
}

// Decode parses an MQTT-SN message from a hex string starting at
// the Length byte. Separators (':' '-' '_' whitespace) tolerated;
// '0x' prefix tolerated.
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
	if len(b) < 2 {
		return nil, fmt.Errorf("MQTT-SN message truncated (%d bytes; need ≥2 for header)",
			len(b))
	}

	r := &Result{TotalBytes: len(b)}
	var body []byte
	if b[0] == 0x01 {
		// Long form: 0x01 + uint16 BE length + MsgType + body
		if len(b) < 4 {
			return nil, fmt.Errorf("MQTT-SN long-form truncated (need ≥4 bytes)")
		}
		r.LongFormat = true
		r.Length = int(binary.BigEndian.Uint16(b[1:3]))
		r.MsgType = int(b[3])
		body = b[4:]
	} else {
		r.Length = int(b[0])
		r.MsgType = int(b[1])
		body = b[2:]
	}
	r.MsgTypeName = msgTypeName(r.MsgType)

	// Per-MsgType body decode.
	switch r.MsgType {
	case 0x00: // ADVERTISE
		if len(body) >= 3 {
			r.GwID = int(body[0])
			r.Duration = int(binary.BigEndian.Uint16(body[1:3]))
		}
	case 0x02: // GWINFO
		if len(body) >= 1 {
			r.GwID = int(body[0])
		}
		if len(body) > 1 {
			r.GwAddHex = strings.ToUpper(hex.EncodeToString(body[1:]))
		}
	case 0x04: // CONNECT
		if len(body) >= 4 {
			r.decodeFlags(body[0])
			r.ProtocolID = int(body[1])
			r.Duration = int(binary.BigEndian.Uint16(body[2:4]))
			if len(body) > 4 {
				r.ClientID = string(body[4:])
			}
		}
	case 0x05: // CONNACK
		if len(body) >= 1 {
			r.ReturnCode = int(body[0])
			r.ReturnCodeName = returnCodeName(r.ReturnCode)
		}
	case 0x07: // WILLTOPIC
		if len(body) >= 1 {
			r.decodeFlags(body[0])
			if len(body) > 1 {
				r.TopicName = string(body[1:])
			}
		}
	case 0x09: // WILLMSG
		if len(body) > 0 {
			r.DataHex = strings.ToUpper(hex.EncodeToString(body))
		}
	case 0x0A: // REGISTER
		if len(body) >= 4 {
			r.TopicID = int(binary.BigEndian.Uint16(body[0:2]))
			r.MsgID = int(binary.BigEndian.Uint16(body[2:4]))
			if len(body) > 4 {
				r.TopicName = string(body[4:])
			}
		}
	case 0x0B: // REGACK
		if len(body) >= 5 {
			r.TopicID = int(binary.BigEndian.Uint16(body[0:2]))
			r.MsgID = int(binary.BigEndian.Uint16(body[2:4]))
			r.ReturnCode = int(body[4])
			r.ReturnCodeName = returnCodeName(r.ReturnCode)
		}
	case 0x0C: // PUBLISH
		if len(body) >= 5 {
			r.decodeFlags(body[0])
			r.TopicID = int(binary.BigEndian.Uint16(body[1:3]))
			r.MsgID = int(binary.BigEndian.Uint16(body[3:5]))
			if len(body) > 5 {
				r.DataHex = strings.ToUpper(hex.EncodeToString(body[5:]))
			}
		}
	case 0x0D, 0x0E, 0x0F, 0x10: // PUBACK / PUBCOMP / PUBREC / PUBREL
		if len(body) >= 5 {
			r.TopicID = int(binary.BigEndian.Uint16(body[0:2]))
			r.MsgID = int(binary.BigEndian.Uint16(body[2:4]))
			r.ReturnCode = int(body[4])
			r.ReturnCodeName = returnCodeName(r.ReturnCode)
		} else if len(body) >= 2 {
			// PUBREC / PUBREL only carry MsgId (2 bytes).
			r.MsgID = int(binary.BigEndian.Uint16(body[0:2]))
		}
	case 0x12: // SUBSCRIBE
		if len(body) >= 3 {
			r.decodeFlags(body[0])
			r.MsgID = int(binary.BigEndian.Uint16(body[1:3]))
			if len(body) > 3 {
				if r.TopicIDType == 0 {
					r.TopicName = string(body[3:])
				} else if len(body) >= 5 {
					r.TopicID = int(binary.BigEndian.Uint16(body[3:5]))
				}
			}
		}
	case 0x13: // SUBACK
		if len(body) >= 6 {
			r.decodeFlags(body[0])
			r.TopicID = int(binary.BigEndian.Uint16(body[1:3]))
			r.MsgID = int(binary.BigEndian.Uint16(body[3:5]))
			r.ReturnCode = int(body[5])
			r.ReturnCodeName = returnCodeName(r.ReturnCode)
		}
	case 0x14: // UNSUBSCRIBE
		if len(body) >= 3 {
			r.decodeFlags(body[0])
			r.MsgID = int(binary.BigEndian.Uint16(body[1:3]))
			if len(body) > 3 {
				if r.TopicIDType == 0 {
					r.TopicName = string(body[3:])
				} else if len(body) >= 5 {
					r.TopicID = int(binary.BigEndian.Uint16(body[3:5]))
				}
			}
		}
	case 0x15: // UNSUBACK
		if len(body) >= 2 {
			r.MsgID = int(binary.BigEndian.Uint16(body[0:2]))
		}
	case 0x18: // DISCONNECT
		if len(body) >= 2 {
			r.Duration = int(binary.BigEndian.Uint16(body[0:2]))
		}
	default:
		if len(body) > 0 {
			r.PayloadHex = strings.ToUpper(hex.EncodeToString(body))
		}
	}
	return r, nil
}

func (r *Result) decodeFlags(f byte) {
	r.FlagsHex = fmt.Sprintf("0x%02X", f)
	r.DUP = f&0x80 != 0
	r.QoS = int((f >> 5) & 0x03)
	if r.QoS == 3 {
		r.QoS = -1 // MQTT-SN-specific fire-and-forget
	}
	r.Retain = f&0x10 != 0
	r.Will = f&0x08 != 0
	r.CleanSession = f&0x04 != 0
	r.TopicIDType = int(f & 0x03)
	r.TopicIDTypeName = topicIDTypeName(r.TopicIDType)
}

func msgTypeName(t int) string {
	switch t {
	case 0x00:
		return "ADVERTISE"
	case 0x01:
		return "SEARCHGW"
	case 0x02:
		return "GWINFO"
	case 0x04:
		return "CONNECT"
	case 0x05:
		return "CONNACK"
	case 0x06:
		return "WILLTOPICREQ"
	case 0x07:
		return "WILLTOPIC"
	case 0x08:
		return "WILLMSGREQ"
	case 0x09:
		return "WILLMSG"
	case 0x0A:
		return "REGISTER"
	case 0x0B:
		return "REGACK"
	case 0x0C:
		return "PUBLISH"
	case 0x0D:
		return "PUBACK"
	case 0x0E:
		return "PUBCOMP"
	case 0x0F:
		return "PUBREC"
	case 0x10:
		return "PUBREL"
	case 0x12:
		return "SUBSCRIBE"
	case 0x13:
		return "SUBACK"
	case 0x14:
		return "UNSUBSCRIBE"
	case 0x15:
		return "UNSUBACK"
	case 0x16:
		return "PINGREQ"
	case 0x17:
		return "PINGRESP"
	case 0x18:
		return "DISCONNECT"
	case 0x1A:
		return "WILLTOPICUPD"
	case 0x1B:
		return "WILLTOPICRESP"
	case 0x1C:
		return "WILLMSGUPD"
	case 0x1D:
		return "WILLMSGRESP"
	}
	return fmt.Sprintf("uncatalogued MsgType 0x%02X", t)
}

func returnCodeName(c int) string {
	switch c {
	case 0x00:
		return "Accepted"
	case 0x01:
		return "Rejected_congestion"
	case 0x02:
		return "Rejected_invalid_topic_ID"
	case 0x03:
		return "Rejected_not_supported"
	}
	return fmt.Sprintf("uncatalogued return code 0x%02X", c)
}

func topicIDTypeName(t int) string {
	switch t {
	case 0:
		return "normal"
	case 1:
		return "predefined"
	case 2:
		return "short_name"
	case 3:
		return "reserved"
	}
	return ""
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
