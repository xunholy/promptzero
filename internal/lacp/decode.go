// Package lacp decodes Link Aggregation Control Protocol
// (LACP) PDUs per IEEE 802.1AX-2020 (formerly 802.3ad). LACP
// is the universal link-aggregation control plane: every
// multi-NIC server with a bonded interface and every datacenter
// / enterprise switch with a LAG (Link Aggregation Group) speaks
// it to coordinate which physical links join an aggregate.
//
// Wrap-vs-native judgement
//
//	Native. The IEEE 802.1AX-2020 wire format is fully public;
//	LACP rides over Slow Protocols (EtherType 0x8809), subtype
//	0x01 (LACP), and uses a tight TLV-based PDU. No crypto, no
//	compression — operators paste LACPDU bytes (multicast to
//	the Slow Protocols Multicast Address 01:80:C2:00:00:02)
//	from a `tcpdump -X ether proto 0x8809` line or a Wireshark
//	Follow-Frame view and get the documented Actor / Partner /
//	Collector breakdown.
//
// What this package covers
//
//   - **Subtype byte** — the leading byte after the Slow Protocols
//     EtherType. Value 0x01 = LACP, 0x02 = Marker (rare;
//     surfaced as a Note). A non-1/2 subtype is rejected.
//
//   - **1-byte Version Number** — typically 1; v2 reserved by
//     IEEE 802.1AX-2014 but not yet widely deployed (surfaced
//     verbatim).
//
//   - **TLV walker** — repeated (Type uint8, Length uint8,
//     Value) records. **4-entry TLV type table**:
//     0 Terminator (Length 0; signals end of TLV chain),
//     1 Actor Information (Length 20),
//     2 Partner Information (Length 20),
//     3 Collector Information (Length 16).
//
//   - **Actor / Partner Information** (Type 1/2, body 20 bytes):
//
//   - bytes 0-1: System Priority (uint16 BE — lower wins the
//     Aggregator Master role when both ends could be master).
//
//   - bytes 2-7: System ID (6-byte MAC — the system's
//     canonical MAC address).
//
//   - bytes 8-9: Key (uint16 BE — operationally the LAG
//     identifier; ports with the same Key on the same System
//     ID can be bundled together).
//
//   - bytes 10-11: Port Priority (uint16 BE — tie-breaker for
//     which member port is the Aggregator).
//
//   - bytes 12-13: Port ID (uint16 BE — per-port identifier
//     unique within a System).
//
//   - byte 14: **State** — 8-bit bitfield with **8 named
//     flags** (LSB first per 802.1AX §6.4.2.3):
//
//   - bit 0: **LACP_Activity** (1 = Active, 0 = Passive —
//     Active end sends LACPDUs; Passive only responds)
//
//   - bit 1: **LACP_Timeout** (1 = Short / 1 s, 0 = Long /
//     30 s — controls partner LACPDU expectation rate)
//
//   - bit 2: **Aggregation** (1 = Aggregatable, 0 =
//     Individual — set if the port can join a bundle)
//
//   - bit 3: **Synchronization** (1 = In Sync; 0 = Out of
//     Sync with the partner's state machine)
//
//   - bit 4: **Collecting** (1 = receive path is active on
//     this port)
//
//   - bit 5: **Distributing** (1 = transmit path is active
//     on this port)
//
//   - bit 6: **Defaulted** (1 = using administratively-
//     configured defaults rather than received LACPDU info)
//
//   - bit 7: **Expired** (1 = current_while timer expired;
//     partner info is stale)
//
//   - bytes 15-17: Reserved (typically 0).
//
//   - **Collector Information** (Type 3, body 16 bytes):
//
//   - bytes 0-1: Max Delay (uint16 BE; in 10 µs units;
//     maximum time the Frame Distributor will hold a frame
//     before delivering it to the Aggregator Client).
//
//   - bytes 2-15: Reserved.
//
//   - **Terminator** (Type 0, Length 0; end of TLV chain).
//
// What this package does NOT cover (deliberately out of scope)
//
//   - Ethernet framing — feed LACPDU bytes starting at the
//     Slow Protocols subtype byte (i.e. after the destination
//     MAC + source MAC + 0x8809 EtherType strip). The 802.1AX
//     spec defines the destination MAC as 01:80:C2:00:00:02.
//
//   - 802.3 Marker Protocol (Subtype 0x02) — used during
//     port-removal flushing; same Slow Protocols envelope but
//     a different body. Surfaced as a Note rather than parsed.
//
//   - LACP state-machine simulation — the State bitfield is
//     decoded with named flags; reasoning about Selection /
//     Mux state machine transitions is higher-level.
package lacp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the top-level decoded view.
type Result struct {
	Subtype     int      `json:"subtype"`
	SubtypeName string   `json:"subtype_name"`
	Version     int      `json:"version,omitempty"`
	TLVs        []TLV    `json:"tlvs,omitempty"`
	TotalBytes  int      `json:"total_bytes"`
	Notes       []string `json:"notes,omitempty"`
}

// TLV is one (Type, Length, Value) record from the LACPDU.
type TLV struct {
	Type     int    `json:"type"`
	TypeName string `json:"type_name"`
	Length   int    `json:"length"`
	ValueHex string `json:"value_hex,omitempty"`

	// Decoded forms populated for known Types.
	Actor     *ActorPartnerInfo `json:"actor,omitempty"`
	Partner   *ActorPartnerInfo `json:"partner,omitempty"`
	Collector *CollectorInfo    `json:"collector,omitempty"`
}

// ActorPartnerInfo is the decoded body of Type 1 (Actor) or
// Type 2 (Partner) Information TLV.
type ActorPartnerInfo struct {
	SystemPriority int        `json:"system_priority"`
	SystemID       string     `json:"system_id"`
	Key            int        `json:"key"`
	PortPriority   int        `json:"port_priority"`
	PortID         int        `json:"port_id"`
	State          int        `json:"state"`
	StateHex       string     `json:"state_hex"`
	StateFlags     StateFlags `json:"state_flags"`
}

// StateFlags is the decoded 8-bit State bitfield from an Actor
// or Partner Information TLV.
type StateFlags struct {
	LACPActivity    bool `json:"lacp_activity"`
	LACPTimeout     bool `json:"lacp_timeout_short"`
	Aggregation     bool `json:"aggregation"`
	Synchronization bool `json:"synchronization"`
	Collecting      bool `json:"collecting"`
	Distributing    bool `json:"distributing"`
	Defaulted       bool `json:"defaulted"`
	Expired         bool `json:"expired"`
}

// CollectorInfo is the decoded body of Type 3 Collector
// Information TLV.
type CollectorInfo struct {
	MaxDelay       int `json:"max_delay"`
	MaxDelayMicros int `json:"max_delay_microseconds"`
}

// Decode parses a single LACPDU starting at the Slow Protocols
// subtype byte (i.e. after the Ethernet header strip).
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
	if len(b) < 2 {
		return nil, fmt.Errorf("LACPDU truncated (%d bytes; need ≥2 for subtype + version)",
			len(b))
	}

	r := &Result{
		TotalBytes:  len(b),
		Subtype:     int(b[0]),
		SubtypeName: subtypeName(int(b[0])),
		Version:     int(b[1]),
	}

	switch r.Subtype {
	case 1: // LACP
	case 2: // Marker
		r.Notes = append(r.Notes,
			"subtype 0x02 = Slow Protocols Marker; body layout differs from LACP and is not decoded here")
		return r, nil
	default:
		return r, fmt.Errorf("unsupported slow-protocols subtype 0x%02X (1=LACP, 2=Marker)",
			r.Subtype)
	}

	tlvs, err := decodeTLVs(b[2:])
	r.TLVs = tlvs
	if err != nil {
		return r, err
	}
	return r, nil
}

func decodeTLVs(b []byte) ([]TLV, error) {
	var out []TLV
	off := 0
	for off+2 <= len(b) {
		typ := int(b[off])
		ln := int(b[off+1])
		if typ == 0 && ln == 0 {
			out = append(out, TLV{Type: 0, TypeName: "Terminator", Length: 0})
			return out, nil
		}
		bodyLen := ln - 2
		if bodyLen < 0 {
			return out, fmt.Errorf("TLV type %d length %d underflows header", typ, ln)
		}
		if off+2+bodyLen > len(b) {
			return out, fmt.Errorf("TLV type %d length %d truncates packet at offset %d",
				typ, ln, off)
		}
		v := b[off+2 : off+2+bodyLen]
		t := TLV{
			Type:     typ,
			TypeName: typeName(typ),
			Length:   ln,
			ValueHex: strings.ToUpper(hex.EncodeToString(v)),
		}
		switch typ {
		case 1:
			ap, err := decodeActorPartner(v)
			if err != nil {
				return out, fmt.Errorf("actor info: %w", err)
			}
			t.Actor = ap
		case 2:
			ap, err := decodeActorPartner(v)
			if err != nil {
				return out, fmt.Errorf("partner info: %w", err)
			}
			t.Partner = ap
		case 3:
			c, err := decodeCollector(v)
			if err != nil {
				return out, fmt.Errorf("collector info: %w", err)
			}
			t.Collector = c
		}
		out = append(out, t)
		off += 2 + bodyLen
	}
	return out, nil
}

func decodeActorPartner(v []byte) (*ActorPartnerInfo, error) {
	if len(v) < 18 {
		return nil, fmt.Errorf("body truncated (%d; need 18)", len(v))
	}
	ap := &ActorPartnerInfo{
		SystemPriority: int(binary.BigEndian.Uint16(v[0:2])),
		SystemID:       formatMAC(v[2:8]),
		Key:            int(binary.BigEndian.Uint16(v[8:10])),
		PortPriority:   int(binary.BigEndian.Uint16(v[10:12])),
		PortID:         int(binary.BigEndian.Uint16(v[12:14])),
		State:          int(v[14]),
		StateHex:       fmt.Sprintf("0x%02X", v[14]),
	}
	ap.StateFlags = decodeStateFlags(v[14])
	return ap, nil
}

func decodeCollector(v []byte) (*CollectorInfo, error) {
	if len(v) < 2 {
		return nil, fmt.Errorf("body truncated (%d; need 2)", len(v))
	}
	delay := int(binary.BigEndian.Uint16(v[0:2]))
	return &CollectorInfo{
		MaxDelay:       delay,
		MaxDelayMicros: delay * 10,
	}, nil
}

func decodeStateFlags(s byte) StateFlags {
	return StateFlags{
		LACPActivity:    s&0x01 != 0,
		LACPTimeout:     s&0x02 != 0,
		Aggregation:     s&0x04 != 0,
		Synchronization: s&0x08 != 0,
		Collecting:      s&0x10 != 0,
		Distributing:    s&0x20 != 0,
		Defaulted:       s&0x40 != 0,
		Expired:         s&0x80 != 0,
	}
}

func subtypeName(s int) string {
	switch s {
	case 1:
		return "LACP"
	case 2:
		return "Marker"
	}
	return fmt.Sprintf("uncatalogued subtype 0x%02X", s)
}

func typeName(t int) string {
	switch t {
	case 0:
		return "Terminator"
	case 1:
		return "Actor Information"
	case 2:
		return "Partner Information"
	case 3:
		return "Collector Information"
	}
	return fmt.Sprintf("uncatalogued TLV type %d", t)
}

func formatMAC(b []byte) string {
	if len(b) != 6 {
		return strings.ToUpper(hex.EncodeToString(b))
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		b[0], b[1], b[2], b[3], b[4], b[5])
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
