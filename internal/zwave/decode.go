// Package zwave decodes classic Z-Wave MAC-layer frames per the
// Sigma Designs / Silicon Labs public specification (SDS-12852,
// Z-Wave Public API + Z-Wave Plus / 700/800-series protocol
// reference). Z-Wave is the dominant **sub-GHz home-automation
// mesh** protocol — used by Yale / Schlage / Kwikset Z-Wave
// door locks, Ring Z-Wave alarm, Aeotec / Fibaro sensors, GE
// Z-Wave dimmers, the SmartThings hub, and roughly every
// "smart home" controller that isn't pure Wi-Fi / Zigbee /
// Matter.
//
// Operationally, Z-Wave runs around 868.42 MHz (EU) /
// 908.42 MHz (US) / 919.82 MHz (AU) on ITU-T G.9959 PHY at
// 9.6 / 40 / 100 kbit/s. The protocol is interesting to a
// Flipper Zero / SDR pentester because:
//
//   - **Door-lock attacks** — Yale / Kwikset Z-Wave locks
//     respond to authenticated commands; replayed commands
//     attack the SECURITY (S0, classic Z-Wave) and SECURITY_2
//     (S2, Z-Wave Plus) key-exchange stacks.
//   - **Mesh enumeration** — every Z-Wave network has a single
//     HomeID (32-bit) and per-node NodeIDs; sniffing a
//     handful of frames lets a pentester map the controller +
//     every paired device.
//   - **Battery-drain DoS** — flooding "Wake Up Notification"
//     frames against battery-powered Z-Wave sensors drives them
//     out of FLiRS sleep mode and burns through CR2032 cells.
//   - **CTF + research** — DEF CON Wireless Village, Black Hat
//     IoT track, and the SamyKam Z-Wave research have all
//     published Z-Wave wire captures that this decoder ingests.
//
// Wrap-vs-native judgement
//
//	Native. The Sigma Designs SDS-12852 Z-Wave Public API
//	document is publicly available; the MAC-layer frame
//	format is fixed (4-byte HomeID + 1-byte SourceNodeID +
//	2-byte Frame Control + 1-byte Length + 1-byte
//	DestinationNodeID + payload + 1-byte XOR checksum) and
//	the Command Class registry (Z-Wave Command Class
//	Reference, Silicon Labs INS13954) maps the 256-entry
//	Command Class space against documented application-
//	layer behaviours. No crypto at the parse layer (the
//	SECURITY / SECURITY_2 Command Classes are container
//	classes; per-key AES-CMAC verification is out of
//	scope).
//
// What this package covers
//
//   - **MAC-layer frame header** (SDS-12852 §3, 9 fixed bytes
//     before the payload):
//
//   - bytes 0-3: **HomeID** (uint32 BE; per-network identifier
//     assigned by the primary controller at inclusion time).
//
//   - byte 4: **SourceNodeID** (1 byte; the originating
//     node's 8-bit address within the HomeID).
//
//   - bytes 5-6: **Frame Control** (2 bytes; bit layout
//     per below).
//
//   - byte 7: **Length** (1 byte; total frame length in
//     bytes INCLUDING the 1-byte trailing checksum).
//
//   - byte 8: **DestinationNodeID** (1 byte; 0xFF =
//     broadcast).
//
//   - **Frame Control field** (2 bytes, big-endian):
//
//   - byte 5 bits 0-3: **Header Type** (1 Singlecast / 2
//     Multicast / 3 Ack / 4 Explore).
//
//   - byte 5 bit 4: Routed (set on a multi-hop relayed
//     frame).
//
//   - byte 5 bit 5: Ack Requested (sender wants a Type-3
//     Ack reply).
//
//   - byte 5 bit 6: Low Power (transmitter is using
//     reduced power; FLiRS-class devices).
//
//   - byte 5 bit 7: Speed Modified (sender is using a
//     non-default PHY data rate).
//
//   - byte 6 bit 0: Beam Control (frame is a beam-mode
//     poll for sleeping devices).
//
//   - byte 6 bits 4-7: Sequence Number (4-bit per-pair
//     monotonic counter used to pair Ack frames to their
//     originating frames).
//
//   - **Payload + Command Class header** (variable):
//
//   - byte 0: **Command Class** (per Z-Wave Command Class
//     Reference).
//
//   - byte 1: **Command** (per-Command-Class operation
//     code).
//
//   - bytes 2+: per-Command parameters (dataset-specific).
//
//   - **30+ entry Command Class name table** (selected high-
//     runners from the Silicon Labs INS13954 registry): 0x20
//     `BASIC` / 0x25 `SWITCH_BINARY` / 0x26 `SWITCH_MULTILEVEL`
//     / 0x27 `SWITCH_ALL` / 0x28 `SWITCH_TOGGLE_BINARY` /
//     0x2B `SCENE_ACTIVATION` / 0x30 `SENSOR_BINARY` / 0x31
//     `SENSOR_MULTILEVEL` / 0x32 `METER` / 0x40
//     `THERMOSTAT_MODE` / 0x42 `THERMOSTAT_OPERATING_STATE` /
//     0x43 `THERMOSTAT_SETPOINT` / 0x44 `THERMOSTAT_FAN_MODE`
//     / 0x60 `MULTI_CHANNEL` / 0x62 `DOOR_LOCK` / 0x63
//     `USER_CODE` / 0x70 `CONFIGURATION` / 0x71 `ALARM` (also
//     `NOTIFICATION`) / 0x72 `MANUFACTURER_SPECIFIC` / 0x73
//     `POWERLEVEL` / 0x75 `PROTECTION` / 0x77 `NODE_NAMING` /
//     0x80 `BATTERY` / 0x81 `CLOCK` / 0x82 `HAIL` / 0x84
//     `WAKE_UP` (the battery-drain attack target) / 0x85
//     `ASSOCIATION` / 0x86 `VERSION` / 0x87 `INDICATOR` /
//     0x8B `TIME_PARAMETERS` / 0x91 `MANUFACTURER_PROPRIETARY`
//     / 0x98 `SECURITY` (S0; classic Z-Wave AES-128 wrapper)
//     / 0x9F `SECURITY_2` (S2; Z-Wave Plus AES-CMAC + ECDH).
//
//   - **4-entry Header Type name table**: 1 `Singlecast` /
//     2 `Multicast` / 3 `Ack` / 4 `Explore`.
//
//   - **Trailing checksum** — 1-byte XOR of every byte from
//     HomeID through the last payload byte, init 0xFF.
//     Surfaced as hex but not re-computed.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **PHY framing** — Z-Wave runs on ITU-T G.9959 FSK PHY at
//     868 / 908 / 920 MHz with Manchester / NRZ encoding plus
//     a 4-byte preamble + 1-byte SOF. Feed this decoder the
//     post-PHY MAC frame bytes (after preamble + SOF strip;
//     Flipper Zero / HackRF / RTL-SDR + zwave-libs is the
//     typical capture chain).
//   - **Z-Wave Long Range (LR)** — the 700/800-series LR
//     variant (Z-Wave Plus v2) re-uses much of the classic
//     wire format but extends NodeIDs to 16 bits and uses a
//     different MAC layout; out of scope here.
//   - **SECURITY (S0) / SECURITY_2 (S2) crypto** — the
//     `SECURITY` (0x98) and `SECURITY_2` (0x9F) Command
//     Classes are container Command Classes that wrap an
//     inner AES-CMAC-protected payload; this decoder surfaces
//     the Command Class identifier + raw payload bytes but
//     does not verify the integrity tag or decrypt the inner
//     command (S0 attack research and S2 ECDH key-exchange
//     analysis are higher-level work).
//   - **Routing-layer reasoning** — multi-hop Z-Wave frames
//     carry repeater tables and routing source headers; the
//     decoder surfaces the Routed bit + Length but does not
//     walk the per-hop fields.
//   - **Multicast frame body** — the Multicast (Type 2) frame
//     carries a NodeMask + per-node grouping that this
//     decoder surfaces as raw payload (per-bit walker is
//     future work).
//   - **Mesh-state reasoning** — inclusion / exclusion / wake-
//     up FLiRS state-machine, per-NodeID sleep tracking;
//     higher-level analysis driven by the controller log.
package zwave

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the structured decode of a Z-Wave MAC-layer frame.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// MAC header
	HomeIDHex         string `json:"home_id_hex"`
	SourceNodeID      int    `json:"source_node_id"`
	FrameControlHex   string `json:"frame_control_hex"`
	HeaderType        int    `json:"header_type"`
	HeaderTypeName    string `json:"header_type_name"`
	Routed            bool   `json:"routed"`
	AckRequested      bool   `json:"ack_requested"`
	LowPower          bool   `json:"low_power"`
	SpeedModified     bool   `json:"speed_modified"`
	BeamControl       bool   `json:"beam_control"`
	SequenceNumber    int    `json:"sequence_number"`
	Length            int    `json:"length"`
	DestinationNodeID int    `json:"destination_node_id"`

	// Payload
	CommandClass     int    `json:"command_class,omitempty"`
	CommandClassName string `json:"command_class_name,omitempty"`
	Command          int    `json:"command,omitempty"`
	ParametersHex    string `json:"parameters_hex,omitempty"`

	// Trailing checksum (XOR; not re-computed here).
	ChecksumHex string `json:"checksum_hex,omitempty"`
}

// Decode parses a Z-Wave MAC-layer frame from a hex string
// starting at the first HomeID byte (i.e. AFTER the PHY
// preamble + SOF strip). Separators (':' '-' '_' whitespace)
// tolerated; a leading '0x' prefix is stripped.
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
	if len(b) < 10 {
		return nil, fmt.Errorf("z-wave frame truncated (%d bytes; need ≥10 for header + checksum)",
			len(b))
	}

	r := &Result{
		TotalBytes:        len(b),
		HomeIDHex:         fmt.Sprintf("0x%08X", binary.BigEndian.Uint32(b[0:4])),
		SourceNodeID:      int(b[4]),
		FrameControlHex:   fmt.Sprintf("0x%02X%02X", b[5], b[6]),
		HeaderType:        int(b[5] & 0x0F),
		Routed:            b[5]&0x10 != 0,
		AckRequested:      b[5]&0x20 != 0,
		LowPower:          b[5]&0x40 != 0,
		SpeedModified:     b[5]&0x80 != 0,
		BeamControl:       b[6]&0x01 != 0,
		SequenceNumber:    int(b[6] >> 4),
		Length:            int(b[7]),
		DestinationNodeID: int(b[8]),
	}
	r.HeaderTypeName = headerTypeName(r.HeaderType)

	// Body bytes between byte 9 and the trailing checksum.
	// Length counts total frame bytes including the 1-byte
	// checksum, so the payload occupies bytes [9, Length-1).
	end := r.Length
	if end > len(b) {
		end = len(b)
	}
	if end < 10 {
		return r, nil
	}
	payload := b[9 : end-1]
	if len(payload) >= 2 {
		r.CommandClass = int(payload[0])
		r.CommandClassName = commandClassName(r.CommandClass)
		r.Command = int(payload[1])
		if len(payload) > 2 {
			r.ParametersHex = strings.ToUpper(hex.EncodeToString(payload[2:]))
		}
	} else if len(payload) == 1 {
		r.CommandClass = int(payload[0])
		r.CommandClassName = commandClassName(r.CommandClass)
	}
	r.ChecksumHex = fmt.Sprintf("0x%02X", b[end-1])
	return r, nil
}

func headerTypeName(t int) string {
	switch t {
	case 1:
		return "Singlecast"
	case 2:
		return "Multicast"
	case 3:
		return "Ack"
	case 4:
		return "Explore"
	}
	return fmt.Sprintf("uncatalogued header type %d", t)
}

func commandClassName(c int) string {
	switch c {
	case 0x20:
		return "BASIC"
	case 0x25:
		return "SWITCH_BINARY"
	case 0x26:
		return "SWITCH_MULTILEVEL"
	case 0x27:
		return "SWITCH_ALL"
	case 0x28:
		return "SWITCH_TOGGLE_BINARY"
	case 0x2B:
		return "SCENE_ACTIVATION"
	case 0x30:
		return "SENSOR_BINARY"
	case 0x31:
		return "SENSOR_MULTILEVEL"
	case 0x32:
		return "METER"
	case 0x40:
		return "THERMOSTAT_MODE"
	case 0x42:
		return "THERMOSTAT_OPERATING_STATE"
	case 0x43:
		return "THERMOSTAT_SETPOINT"
	case 0x44:
		return "THERMOSTAT_FAN_MODE"
	case 0x60:
		return "MULTI_CHANNEL"
	case 0x62:
		return "DOOR_LOCK"
	case 0x63:
		return "USER_CODE"
	case 0x70:
		return "CONFIGURATION"
	case 0x71:
		return "ALARM"
	case 0x72:
		return "MANUFACTURER_SPECIFIC"
	case 0x73:
		return "POWERLEVEL"
	case 0x75:
		return "PROTECTION"
	case 0x77:
		return "NODE_NAMING"
	case 0x80:
		return "BATTERY"
	case 0x81:
		return "CLOCK"
	case 0x82:
		return "HAIL"
	case 0x84:
		return "WAKE_UP"
	case 0x85:
		return "ASSOCIATION"
	case 0x86:
		return "VERSION"
	case 0x87:
		return "INDICATOR"
	case 0x8B:
		return "TIME_PARAMETERS"
	case 0x91:
		return "MANUFACTURER_PROPRIETARY"
	case 0x98:
		return "SECURITY"
	case 0x9F:
		return "SECURITY_2"
	}
	return fmt.Sprintf("uncatalogued command class 0x%02X", c)
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
