// Package someip decodes SOME/IP (Scalable service-Oriented
// MiddlewarE over IP) messages per the AUTOSAR R23-11 SOME/IP
// Protocol Specification (PRS_SOMEIPProtocol) and the parallel
// SOME/IP Service Discovery spec (PRS_SOMEIPServiceDiscoveryProtocol).
// SOME/IP is the **automotive Ethernet RPC + pub/sub bus** sitting
// alongside CAN/CAN-FD in modern vehicles — particularly EVs and
// AUTOSAR Adaptive Platform ECUs — for service-oriented in-vehicle
// communication that the CAN family can't carry (large payloads,
// multi-recipient pub/sub, dynamic service discovery).
//
// Operationally, SOME/IP is the signalling that drives:
//
//   - **Camera + radar + lidar feeds** from the ADAS sensor cluster
//     to the central perception ECU (mid-Mbps payloads classic CAN
//     can't move).
//   - **In-Vehicle Infotainment (IVI) ↔ instrument cluster**
//     service calls (volume changes, navigation routes, diagnostic
//     overlays).
//   - **Inter-domain controller traffic** in zonal-architecture
//     vehicles (Tesla, Rivian, VW MEB+, BMW Neue Klasse, NIO) —
//     SOME/IP is the lingua franca between zone controllers running
//     AUTOSAR Adaptive.
//   - **DoIP companions** — Diagnostic over IP (ISO 13400) and
//     SOME/IP frequently share the same Ethernet pair; SOME/IP
//     traffic is what an attacker sees first on a freshly-tapped
//     vehicle Ethernet bus.
//
// Wrap-vs-native judgement
//
//	Native. The AUTOSAR PRS specs are fully public; SOME/IP has a
//	tight 16-byte header followed by either a method-call payload
//	or (for the SOME/IP-SD subtype identified by Service ID 0xFFFF
//	+ Method ID 0x8100) a Service-Discovery body of typed entries
//	and options. No crypto at the parse layer (SOME/IP-MAC is a
//	future authentication extension; this Spec targets bare-wire
//	deployments).
//
// What this package covers
//
//   - **SOME/IP header** (PRS_SOMEIPProtocol §4.1, 16 bytes;
//     transmitted big-endian):
//
//   - bytes 0-1: Service ID (16-bit identifier of the
//     AUTOSAR service contract; 0xFFFF is reserved for
//     SOME/IP-SD).
//
//   - bytes 2-3: Method ID (16-bit; high bit clear = method
//     call, high bit set = event notification — i.e. the
//     decoder reports `is_event` when bit 15 of Method ID
//     is set).
//
//   - bytes 4-7: Length (uint32 BE; counts bytes from byte
//     8 to end of payload — i.e. Request ID + Protocol /
//     Interface Version + Message Type + Return Code +
//     Payload).
//
//   - bytes 8-9: Client ID (16-bit; identifies the calling
//     ECU within the network).
//
//   - bytes 10-11: Session ID (16-bit; per-Client monotonic
//     counter used to pair a Response to its Request — 0
//     means "no session tracking").
//
//   - byte 12: Protocol Version (= 0x01 for AUTOSAR
//     SOME/IP).
//
//   - byte 13: Interface Version (per-service contract
//     version; bumped on schema breaks).
//
//   - byte 14: Message Type — full 8-bit code:
//
//   - **8-entry messageType name table** (PRS_SOMEIPProtocol
//     §4.1.2.10, surfaced on the *base* type — high TP-bit
//     masked off): 0x00 REQUEST / 0x01 REQUEST_NO_RETURN /
//     0x02 NOTIFICATION / 0x40 REQUEST_ACK / 0x41
//     REQUEST_NO_RETURN_ACK / 0x42 NOTIFICATION_ACK / 0x80
//     RESPONSE / 0x81 ERROR. The high bit (0x20) is the
//     **Transport-Protocol (TP) flag** — when set, the
//     message is one segment of a UDP-Fragmentation
//     SOME/IP-TP chain (PRS §6); both the masked base type
//     and the TP indicator are surfaced.
//
//   - byte 15: Return Code — full 8-bit code:
//
//   - **12-entry returnCode name table** (PRS_SOMEIPProtocol
//     §4.1.2.11): 0x00 E_OK / 0x01 E_NOT_OK / 0x02
//     E_UNKNOWN_SERVICE / 0x03 E_UNKNOWN_METHOD / 0x04
//     E_NOT_READY / 0x05 E_NOT_REACHABLE / 0x06 E_TIMEOUT /
//     0x07 E_WRONG_PROTOCOL_VERSION / 0x08
//     E_WRONG_INTERFACE_VERSION / 0x09 E_MALFORMED_MESSAGE
//     / 0x0A E_WRONG_MESSAGE_TYPE / 0x0B E_E2E_REPEATED /
//     plus 0x0C-0x1F reserved + 0x20-0x5E
//     application-allocated (surfaced as raw with
//     "application-specific" label).
//
//   - **SOME/IP-SD body decoder**
//     (PRS_SOMEIPServiceDiscoveryProtocol §4.1) — triggered when
//     Service ID = 0xFFFF + Method ID = 0x8100 + Message Type =
//     NOTIFICATION (0x02) over UDP/30490 (multicast 224.224.224.245)
//     or unicast. The SD body lays out:
//
//   - byte 0: **Flags** — bit 7 = Reboot (set when a
//     sender just rebooted; subsequent SDs after a 0→1
//     transition clear it once the sender's Session-ID
//     wraps); bit 6 = Unicast (sender supports unicast
//     responses); bits 5-0 = Reserved.
//
//   - bytes 1-3: Reserved.
//
//   - bytes 4-7: Entries Length (uint32 BE; bytes of the
//     Entries array that follows).
//
//   - Then: **Entries[]** — each entry is 16 bytes (PRS_SD
//     §4.2). Two entry shapes share the same layout but
//     have different field semantics — discriminated by
//     the **Type** byte:
//
//   - **8-entry SD entry type name table**:
//     0x00 FIND_SERVICE / 0x01 OFFER_SERVICE (and
//     STOP_OFFER_SERVICE when TTL = 0) / 0x06
//     SUBSCRIBE_EVENTGROUP (and STOP_SUBSCRIBE_EVENTGROUP
//     when TTL = 0) / 0x07 SUBSCRIBE_EVENTGROUP_ACK (and
//     NACK when Return Code != 0); the masking against TTL
//     == 0 and the NACK heuristic are surfaced as derived
//     fields.
//
//   - Entry layout: 1-byte Type + 1-byte Index 1st
//     Options + 1-byte Index 2nd Options + 4-bit Number of
//     1st Options + 4-bit Number of 2nd Options + 2-byte
//     Service ID + 2-byte Instance ID + 1-byte Major
//     Version + 3-byte TTL + 4 bytes of type-specific data
//     (Service entries: Minor Version; Eventgroup
//     entries: Reserved + Initial-Data-Requested flag +
//     reserved + 4-bit Counter + 2-byte Eventgroup ID).
//
//   - Then: **Options Length** (uint32 BE) +
//     **Options[]** — variable-length records each starting
//     with 2-byte Length + 1-byte Type + 1-byte Reserved.
//     Length is **payload bytes after** the 4-byte option
//     header. **8-entry Option type name table**: 0x01
//     Configuration / 0x02 Load Balancing / 0x04 IPv4
//     Endpoint / 0x06 IPv6 Endpoint / 0x14 IPv4 Multicast /
//     0x16 IPv6 Multicast / 0x24 IPv4 SD Endpoint / 0x26
//     IPv6 SD Endpoint. The IPv4 / IPv6 endpoint family
//     (0x04, 0x14, 0x24) is further decoded into an IP
//     address + L4 protocol (TCP/UDP) + port; other Option
//     types are surfaced as raw hex.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Network framing** — UDP/30490 (default SD multicast) +
//     UDP/30491-30499 (per-vendor application channels) or TCP for
//     the same port range. Feed SOME/IP bytes after the UDP / TCP
//     header strip.
//   - **Payload decoding** — the per-method serialisation (AUTOSAR
//     SOME/IP serialisation rules, ARXML-driven) is service-
//     contract-specific and not part of the wire-format spec;
//     payload is surfaced as raw hex via `payload_hex`.
//   - **TP reassembly** — when the TP flag (bit 0x20 of Message
//     Type) is set, the message is one segment of a UDP-
//     fragmentation chain; the per-segment Offset + More-Segments
//     field appears at the start of the payload. The decoder
//     reports `tp_segment: true` and surfaces the per-segment
//     offset, but does not reassemble across multiple input
//     packets — feed each segment separately.
//   - **SOME/IP-MAC authentication** (planned AUTOSAR extension) —
//     out of scope.
//   - **State-machine reasoning** — SD timer/counter logic
//     (Initial-Delay, Repetition-Phase, Cyclic-Offer, TTL expiry,
//     Subscription state) is a higher-level concern.
package someip

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Result is the structured decode of a SOME/IP message.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// Header
	ServiceID        int    `json:"service_id"`
	MethodID         int    `json:"method_id"`
	IsEvent          bool   `json:"is_event"`
	Length           uint32 `json:"length"`
	ClientID         int    `json:"client_id"`
	SessionID        int    `json:"session_id"`
	ProtocolVersion  int    `json:"protocol_version"`
	InterfaceVersion int    `json:"interface_version"`
	MessageType      int    `json:"message_type"`
	MessageTypeBase  int    `json:"message_type_base"`
	MessageTypeName  string `json:"message_type_name"`
	TPSegment        bool   `json:"tp_segment"`
	ReturnCode       int    `json:"return_code"`
	ReturnCodeName   string `json:"return_code_name"`

	// Body
	PayloadHex string  `json:"payload_hex,omitempty"`
	SDBody     *SDBody `json:"sd_body,omitempty"`
}

// SDBody is the SOME/IP-SD body — flags + entries + options.
type SDBody struct {
	FlagsHex      string     `json:"flags_hex"`
	RebootFlag    bool       `json:"reboot_flag"`
	UnicastFlag   bool       `json:"unicast_flag"`
	EntriesLength uint32     `json:"entries_length"`
	OptionsLength uint32     `json:"options_length"`
	Entries       []SDEntry  `json:"entries,omitempty"`
	Options       []SDOption `json:"options,omitempty"`
}

// SDEntry is one 16-byte Service Discovery entry.
type SDEntry struct {
	Type             int    `json:"type"`
	TypeName         string `json:"type_name"`
	Index1stOptions  int    `json:"index_1st_options"`
	Index2ndOptions  int    `json:"index_2nd_options"`
	Number1stOptions int    `json:"number_1st_options"`
	Number2ndOptions int    `json:"number_2nd_options"`
	ServiceID        int    `json:"service_id"`
	InstanceID       int    `json:"instance_id"`
	MajorVersion     int    `json:"major_version"`
	TTL              uint32 `json:"ttl"`
	// For Service entries (FIND/OFFER): 4-byte Minor Version.
	MinorVersion *uint32 `json:"minor_version,omitempty"`
	// For Eventgroup entries (SUBSCRIBE/ACK): Counter + EventgroupID.
	Counter      *int `json:"counter,omitempty"`
	EventgroupID *int `json:"eventgroup_id,omitempty"`
	// Derived semantics.
	IsStop bool `json:"is_stop,omitempty"`
}

// SDOption is one variable-length Service Discovery option.
type SDOption struct {
	Length     int    `json:"length"`
	Type       int    `json:"type"`
	TypeName   string `json:"type_name"`
	IPAddress  string `json:"ip_address,omitempty"`
	L4Protocol string `json:"l4_protocol,omitempty"`
	Port       int    `json:"port,omitempty"`
	PayloadHex string `json:"payload_hex,omitempty"`
}

// Decode parses a SOME/IP message from a hex string. Separators
// (':' '-' '_' whitespace) are tolerated; a leading '0x' prefix
// is stripped.
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
	if len(b) < 16 {
		return nil, fmt.Errorf("SOME/IP message truncated (%d bytes; need ≥16 for header)",
			len(b))
	}

	r := &Result{
		TotalBytes:       len(b),
		ServiceID:        int(binary.BigEndian.Uint16(b[0:2])),
		MethodID:         int(binary.BigEndian.Uint16(b[2:4])),
		Length:           binary.BigEndian.Uint32(b[4:8]),
		ClientID:         int(binary.BigEndian.Uint16(b[8:10])),
		SessionID:        int(binary.BigEndian.Uint16(b[10:12])),
		ProtocolVersion:  int(b[12]),
		InterfaceVersion: int(b[13]),
		MessageType:      int(b[14]),
		ReturnCode:       int(b[15]),
	}
	r.IsEvent = r.MethodID&0x8000 != 0
	r.TPSegment = (r.MessageType & 0x20) != 0
	r.MessageTypeBase = r.MessageType &^ 0x20
	r.MessageTypeName = messageTypeName(r.MessageTypeBase)
	r.ReturnCodeName = returnCodeName(r.ReturnCode)

	// Decode body — SOME/IP-SD if Service=0xFFFF + Method=0x8100,
	// otherwise opaque payload.
	if r.ServiceID == 0xFFFF && r.MethodID == 0x8100 && len(b) >= 16+12 {
		r.SDBody = decodeSDBody(b[16:])
	} else if len(b) > 16 {
		r.PayloadHex = strings.ToUpper(hex.EncodeToString(b[16:]))
	}
	return r, nil
}

func decodeSDBody(body []byte) *SDBody {
	if len(body) < 12 {
		return nil
	}
	sd := &SDBody{
		FlagsHex:      fmt.Sprintf("0x%02X", body[0]),
		RebootFlag:    body[0]&0x80 != 0,
		UnicastFlag:   body[0]&0x40 != 0,
		EntriesLength: binary.BigEndian.Uint32(body[4:8]),
	}
	// Entries[]
	entriesStart := 8
	entriesEnd := entriesStart + int(sd.EntriesLength)
	if entriesEnd > len(body) {
		entriesEnd = len(body)
	}
	for off := entriesStart; off+16 <= entriesEnd; off += 16 {
		sd.Entries = append(sd.Entries, decodeSDEntry(body[off:off+16]))
	}
	// Options Length + Options[]
	if entriesEnd+4 <= len(body) {
		sd.OptionsLength = binary.BigEndian.Uint32(body[entriesEnd : entriesEnd+4])
		optStart := entriesEnd + 4
		optEnd := optStart + int(sd.OptionsLength)
		if optEnd > len(body) {
			optEnd = len(body)
		}
		off := optStart
		for off+4 <= optEnd {
			// Length field counts bytes AFTER the Type byte —
			// i.e. it includes the 1-byte Reserved that
			// follows Type. Total wire bytes for the option =
			// 2 (Length) + 1 (Type) + Length-value.
			length := int(binary.BigEndian.Uint16(body[off : off+2]))
			if off+3+length > optEnd {
				break
			}
			sd.Options = append(sd.Options,
				decodeSDOption(body[off:off+3+length]))
			off += 3 + length
		}
	}
	return sd
}

func decodeSDEntry(b []byte) SDEntry {
	e := SDEntry{
		Type:             int(b[0]),
		Index1stOptions:  int(b[1]),
		Index2ndOptions:  int(b[2]),
		Number1stOptions: int(b[3] >> 4),
		Number2ndOptions: int(b[3] & 0x0F),
		ServiceID:        int(binary.BigEndian.Uint16(b[4:6])),
		InstanceID:       int(binary.BigEndian.Uint16(b[6:8])),
		MajorVersion:     int(b[8]),
		TTL: (uint32(b[9]) << 16) |
			(uint32(b[10]) << 8) |
			uint32(b[11]),
	}
	e.IsStop = e.TTL == 0
	e.TypeName = sdEntryTypeName(e.Type, e.IsStop)
	switch e.Type {
	case 0x00, 0x01: // FIND_SERVICE / OFFER_SERVICE
		mv := binary.BigEndian.Uint32(b[12:16])
		e.MinorVersion = &mv
	case 0x06, 0x07: // SUBSCRIBE_EVENTGROUP / ACK
		// PRS_SD §4.2.4: byte 12 Reserved; byte 13 has 1-bit
		// Initial-Data-Requested + 3-bit Reserved + 4-bit
		// Counter (low nibble); bytes 14-15 hold the 16-bit
		// Eventgroup ID.
		c := int(b[13] & 0x0F)
		eg := int(binary.BigEndian.Uint16(b[14:16]))
		e.Counter = &c
		e.EventgroupID = &eg
	}
	return e
}

func decodeSDOption(b []byte) SDOption {
	o := SDOption{
		Length:   int(binary.BigEndian.Uint16(b[0:2])),
		Type:     int(b[2]),
		TypeName: sdOptionTypeName(int(b[2])),
	}
	payload := b[4:]
	switch o.Type {
	case 0x04, 0x14, 0x24: // IPv4 Endpoint / Multicast / SD
		if len(payload) == 8 {
			o.IPAddress = net.IPv4(payload[0], payload[1],
				payload[2], payload[3]).String()
			// payload[4] reserved; payload[5] L4Proto;
			// payload[6:8] port
			o.L4Protocol = l4Name(payload[5])
			o.Port = int(binary.BigEndian.Uint16(payload[6:8]))
		}
	case 0x06, 0x16, 0x26: // IPv6 Endpoint / Multicast / SD
		if len(payload) == 20 {
			o.IPAddress = net.IP(payload[0:16]).String()
			o.L4Protocol = l4Name(payload[17])
			o.Port = int(binary.BigEndian.Uint16(payload[18:20]))
		}
	default:
		o.PayloadHex = strings.ToUpper(hex.EncodeToString(payload))
	}
	return o
}

func messageTypeName(t int) string {
	switch t {
	case 0x00:
		return "REQUEST"
	case 0x01:
		return "REQUEST_NO_RETURN"
	case 0x02:
		return "NOTIFICATION"
	case 0x40:
		return "REQUEST_ACK"
	case 0x41:
		return "REQUEST_NO_RETURN_ACK"
	case 0x42:
		return "NOTIFICATION_ACK"
	case 0x80:
		return "RESPONSE"
	case 0x81:
		return "ERROR"
	}
	return fmt.Sprintf("uncatalogued message type 0x%02X", t)
}

func returnCodeName(c int) string {
	switch c {
	case 0x00:
		return "E_OK"
	case 0x01:
		return "E_NOT_OK"
	case 0x02:
		return "E_UNKNOWN_SERVICE"
	case 0x03:
		return "E_UNKNOWN_METHOD"
	case 0x04:
		return "E_NOT_READY"
	case 0x05:
		return "E_NOT_REACHABLE"
	case 0x06:
		return "E_TIMEOUT"
	case 0x07:
		return "E_WRONG_PROTOCOL_VERSION"
	case 0x08:
		return "E_WRONG_INTERFACE_VERSION"
	case 0x09:
		return "E_MALFORMED_MESSAGE"
	case 0x0A:
		return "E_WRONG_MESSAGE_TYPE"
	case 0x0B:
		return "E_E2E_REPEATED"
	}
	if c >= 0x20 && c <= 0x5E {
		return fmt.Sprintf("application-specific 0x%02X", c)
	}
	return fmt.Sprintf("reserved 0x%02X", c)
}

func sdEntryTypeName(t int, isStop bool) string {
	switch t {
	case 0x00:
		return "FIND_SERVICE"
	case 0x01:
		if isStop {
			return "STOP_OFFER_SERVICE"
		}
		return "OFFER_SERVICE"
	case 0x06:
		if isStop {
			return "STOP_SUBSCRIBE_EVENTGROUP"
		}
		return "SUBSCRIBE_EVENTGROUP"
	case 0x07:
		return "SUBSCRIBE_EVENTGROUP_ACK"
	}
	return fmt.Sprintf("uncatalogued entry type 0x%02X", t)
}

func sdOptionTypeName(t int) string {
	switch t {
	case 0x01:
		return "Configuration"
	case 0x02:
		return "Load Balancing"
	case 0x04:
		return "IPv4 Endpoint"
	case 0x06:
		return "IPv6 Endpoint"
	case 0x14:
		return "IPv4 Multicast"
	case 0x16:
		return "IPv6 Multicast"
	case 0x24:
		return "IPv4 SD Endpoint"
	case 0x26:
		return "IPv6 SD Endpoint"
	}
	return fmt.Sprintf("uncatalogued option type 0x%02X", t)
}

func l4Name(p byte) string {
	switch p {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	}
	return fmt.Sprintf("L4 proto %d", p)
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
