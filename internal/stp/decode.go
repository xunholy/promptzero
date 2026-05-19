// Package stp decodes Spanning Tree Protocol BPDUs per IEEE
// 802.1D-2004 (STP / RSTP) and IEEE 802.1Q-2014 §13 (MSTP).
//
// Wrap-vs-native judgement
//
//	Native. IEEE 802.1D is fully public; the BPDU wire
//	format is a tight bit-packed binary header — Protocol
//	ID + Version + BPDU Type + per-type body (Configuration
//	or Topology Change Notification). RSTP and MSTP extend
//	the Configuration BPDU with additional flags and a
//	Version 1 / Version 3 trailing block. No crypto, no
//	compression, no varints. Operators paste BPDU bytes
//	(after the LLC header strip — DSAP/SSAP 0x42, Control
//	0x03, sent to the STP-bridge multicast MAC
//	01:80:C2:00:00:00) from a `tcpdump -X ether dst host
//	01:80:c2:00:00:00` line, a Wireshark Follow-Frame view,
//	or any STP-emitting switch and get the documented
//	bridge / root / cost / port / timer breakdown.
//
// What this package covers
//
//   - **3-byte common header**:
//
//   - Protocol ID (2 bytes BE) — must be 0x0000.
//
//   - Version (1 byte) — 0 = STP (IEEE 802.1D), 2 = RSTP
//     (IEEE 802.1D-2004), 3 = MSTP (IEEE 802.1Q-2014 §13).
//
//   - **BPDU Type** (1 byte):
//
//   - 0x00 Configuration BPDU
//
//   - 0x80 Topology Change Notification (TCN) BPDU
//
//   - 0x02 RSTP/MSTP BPDU (carries the extended flags)
//
//   - **Configuration BPDU body** (35 bytes):
//
//   - Flags (1 byte) with **8-bit name table** (TC bit 0 /
//     Proposal bit 1 / Port Role bits 2-3 / Learning bit
//     4 / Forwarding bit 5 / Agreement bit 6 / TC Ack
//     bit 7). Port Role: 0 Unknown / 1 Alternate-or-Backup
//     / 2 Root / 3 Designated.
//
//   - Root Bridge ID (8 bytes) — 4-bit priority + 12-bit
//     system ID extension + 6-byte MAC. Priority must be
//     a multiple of 4096 per IEEE 802.1D §17.13.7.
//
//   - Root Path Cost (4 bytes BE).
//
//   - Bridge ID (8 bytes) — same split as Root Bridge ID.
//
//   - Port ID (2 bytes BE) — 4-bit Port Priority + 12-bit
//     Port Number.
//
//   - Message Age (2 bytes BE; units of 1/256 second).
//
//   - Max Age (2 bytes BE; same units).
//
//   - Hello Time (2 bytes BE; same units).
//
//   - Forward Delay (2 bytes BE; same units).
//
//   - **TCN BPDU body** — empty (the 4-byte common header
//     is the entire frame).
//
//   - **Bridge ID decoding** — splits the leading 2 bytes
//     into the 4-bit System Priority (multiple of 4096) and
//     the 12-bit System ID Extension (typically the VLAN
//     ID for PVST+ or 0 for classic STP), then formats the
//     trailing 6 bytes as a MAC.
//
//   - **Timer formatting** — all 4 timer fields are
//     converted from IEEE 1/256-second units to milliseconds
//     for readability.
//
//   - **MSTP trailer** (Version=3) — the 64-byte MSTI
//     configuration block isn't deeply decoded; it's
//     surfaced as a raw hex blob with a length prefix.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - LLC header (DSAP/SSAP/Control) — feed the BPDU bytes
//     starting at the Protocol ID field (after the 3-byte
//     LLC strip).
//
//   - PVST+ / per-VLAN STP — Cisco proprietary uses standard
//     BPDUs with SNAP encapsulation and embeds the VLAN ID
//     in the System ID Extension; the decoder handles the
//     extension but the SNAP wrapper is the operator's
//     responsibility.
//
//   - Convergence-time simulation — the timers are surfaced;
//     reasoning about how long convergence takes belongs to
//     a higher-level analysis.
//
//   - MSTP MSTI configuration block beyond the raw hex
//     surface — IEEE 802.1Q §13 layout is documented but
//     deep dissection is a future Spec.
package stp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the top-level decoded view.
type Result struct {
	ProtocolID   int    `json:"protocol_id"`
	Version      int    `json:"version"`
	VersionName  string `json:"version_name"`
	BPDUType     int    `json:"bpdu_type"`
	BPDUTypeHex  string `json:"bpdu_type_hex"`
	BPDUTypeName string `json:"bpdu_type_name"`
	TotalBytes   int    `json:"total_bytes"`

	Configuration  *Config `json:"configuration_bpdu,omitempty"`
	TCN            *TCN    `json:"tcn_bpdu,omitempty"`
	MSTITrailerHex string  `json:"msti_trailer_hex,omitempty"`

	Notes []string `json:"notes,omitempty"`
}

// Config is the body of Configuration / RSTP / MSTP BPDUs.
type Config struct {
	Flags          int       `json:"flags"`
	FlagsHex       string    `json:"flags_hex"`
	FlagsDecoded   []string  `json:"flags_decoded,omitempty"`
	PortRole       int       `json:"port_role"`
	PortRoleName   string    `json:"port_role_name"`
	RootBridgeID   *BridgeID `json:"root_bridge_id"`
	RootPathCost   uint32    `json:"root_path_cost"`
	BridgeID       *BridgeID `json:"bridge_id"`
	PortPriority   int       `json:"port_priority"`
	PortNumber     int       `json:"port_number"`
	MessageAgeMs   int       `json:"message_age_ms"`
	MaxAgeMs       int       `json:"max_age_ms"`
	HelloTimeMs    int       `json:"hello_time_ms"`
	ForwardDelayMs int       `json:"forward_delay_ms"`
}

// BridgeID is the Root Bridge ID and Bridge ID 8-byte
// structure (priority + system ID extension + MAC). Per IEEE
// 802.1t the original 16-bit priority field was split into a
// 4-bit Priority (in multiples of 4096) plus a 12-bit System
// ID Extension — typically the VLAN ID for PVST+ or 0 for
// classic STP.
type BridgeID struct {
	Priority             int    `json:"priority"`
	SystemIDExtension    int    `json:"system_id_extension"`
	SystemIDExtensionHex string `json:"system_id_extension_hex"`
	MAC                  string `json:"mac"`
}

// TCN is the body of a Topology Change Notification BPDU
// (which is actually empty; the struct exists to surface
// the type in the JSON output).
type TCN struct{}

// Decode parses an STP BPDU from hex.
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
	if len(b) < 4 {
		return nil, fmt.Errorf("BPDU header truncated (%d bytes; need ≥4)", len(b))
	}

	r := &Result{
		TotalBytes:  len(b),
		ProtocolID:  int(binary.BigEndian.Uint16(b[0:2])),
		Version:     int(b[2]),
		BPDUType:    int(b[3]),
		BPDUTypeHex: fmt.Sprintf("0x%02X", b[3]),
	}
	r.VersionName = versionName(r.Version)
	r.BPDUTypeName = bpduTypeName(r.BPDUType)

	if r.ProtocolID != 0 {
		return nil, fmt.Errorf("invalid Protocol ID 0x%04X (must be 0x0000)",
			r.ProtocolID)
	}

	switch r.BPDUType {
	case 0x00, 0x02: // Configuration or RSTP/MSTP
		if len(b) < 4+31 {
			return nil, fmt.Errorf("configuration BPDU truncated (%d bytes; need ≥35)",
				len(b))
		}
		cfg, err := decodeConfig(b[4:])
		if err != nil {
			return nil, err
		}
		r.Configuration = cfg
		// RSTP/MSTP appends a Version 1 Length byte (always
		// 0) at offset 4+31 = 35. MSTP (Version 3) further
		// appends a Version 3 Length (2 bytes) + MSTI
		// Configuration (≥64 bytes) trailer. Surface as raw
		// hex if present.
		if r.Version == 3 && len(b) > 4+31 {
			r.MSTITrailerHex = strings.ToUpper(hex.EncodeToString(b[4+31:]))
		}
	case 0x80: // TCN
		r.TCN = &TCN{}
		if len(b) > 4 {
			r.Notes = append(r.Notes, fmt.Sprintf(
				"TCN BPDU has trailing %d bytes; RFC IEEE 802.1D §17 says TCN is "+
					"exactly 4 bytes (Protocol ID + Version + Type)",
				len(b)-4))
		}
	default:
		return nil, fmt.Errorf("unknown BPDU Type 0x%02X", r.BPDUType)
	}

	return r, nil
}

func decodeConfig(b []byte) (*Config, error) {
	if len(b) < 31 {
		return nil, fmt.Errorf("configuration body too short (%d bytes; need 31)",
			len(b))
	}
	flags := int(b[0])
	cfg := &Config{
		Flags:    flags,
		FlagsHex: fmt.Sprintf("0x%02X", flags),
		PortRole: (flags >> 2) & 0x03,
	}
	cfg.FlagsDecoded = decodeFlags(flags)
	cfg.PortRoleName = portRoleName(cfg.PortRole)

	cfg.RootBridgeID = decodeBridgeID(b[1:9])
	cfg.RootPathCost = binary.BigEndian.Uint32(b[9:13])
	cfg.BridgeID = decodeBridgeID(b[13:21])

	portID := binary.BigEndian.Uint16(b[21:23])
	cfg.PortPriority = int(portID >> 12)
	cfg.PortNumber = int(portID & 0x0FFF)

	cfg.MessageAgeMs = unitsToMs(binary.BigEndian.Uint16(b[23:25]))
	cfg.MaxAgeMs = unitsToMs(binary.BigEndian.Uint16(b[25:27]))
	cfg.HelloTimeMs = unitsToMs(binary.BigEndian.Uint16(b[27:29]))
	cfg.ForwardDelayMs = unitsToMs(binary.BigEndian.Uint16(b[29:31]))

	return cfg, nil
}

func decodeBridgeID(b []byte) *BridgeID {
	if len(b) != 8 {
		return nil
	}
	leading := binary.BigEndian.Uint16(b[0:2])
	bid := &BridgeID{
		Priority:          int(leading & 0xF000),
		SystemIDExtension: int(leading & 0x0FFF),
		MAC: fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
			b[2], b[3], b[4], b[5], b[6], b[7]),
	}
	bid.SystemIDExtensionHex = fmt.Sprintf("0x%03X", bid.SystemIDExtension)
	return bid
}

func unitsToMs(units uint16) int {
	// 1/256-second units.
	return int(units) * 1000 / 256
}

func decodeFlags(flags int) []string {
	parts := []string{}
	if flags&0x01 != 0 {
		parts = append(parts, "TC (Topology Change)")
	}
	if flags&0x02 != 0 {
		parts = append(parts, "Proposal")
	}
	// bits 2-3 are Port Role (decoded separately)
	if flags&0x10 != 0 {
		parts = append(parts, "Learning")
	}
	if flags&0x20 != 0 {
		parts = append(parts, "Forwarding")
	}
	if flags&0x40 != 0 {
		parts = append(parts, "Agreement")
	}
	if flags&0x80 != 0 {
		parts = append(parts, "TC Ack (Topology Change Acknowledgement)")
	}
	return parts
}

func portRoleName(r int) string {
	switch r {
	case 0:
		return "Unknown / Master"
	case 1:
		return "Alternate or Backup"
	case 2:
		return "Root"
	case 3:
		return "Designated"
	}
	return fmt.Sprintf("port role %d", r)
}

func versionName(v int) string {
	switch v {
	case 0:
		return "STP (IEEE 802.1D)"
	case 2:
		return "RSTP (IEEE 802.1D-2004)"
	case 3:
		return "MSTP (IEEE 802.1Q-2014 §13)"
	}
	return fmt.Sprintf("unknown version %d", v)
}

func bpduTypeName(t int) string {
	switch t {
	case 0x00:
		return "Configuration BPDU"
	case 0x02:
		return "RSTP/MSTP BPDU"
	case 0x80:
		return "Topology Change Notification (TCN)"
	}
	return fmt.Sprintf("unknown BPDU type 0x%02X", t)
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
