// Package hsrp decodes Hot Standby Router Protocol (HSRP)
// packets per RFC 2281 (HSRPv1) and the Cisco HSRPv2 TLV
// extensions. HSRP is Cisco's proprietary first-hop gateway
// redundancy protocol — the sibling of VRRP (RFC 5798) that
// predates the IETF standard and is still extremely common in
// Cisco-heavy enterprise + datacenter cores.
//
// Wrap-vs-native judgement
//
//	Native. RFC 2281 is fully public; the v1 packet is a tight
//	20-byte fixed structure (Version + Op Code + State + 3
//	timers + Priority + Group + Reserved + 8-byte ASCII
//	authentication data + 4-byte Virtual IPv4 Address). Cisco
//	HSRPv2 uses an explicit TLV envelope (Type + Length +
//	Value) where Type 1 carries the 40-byte Group State, Type
//	2 carries Text Authentication, Type 3 carries MD5
//	Authentication. No crypto at the parse layer (MD5
//	digests are surfaced as hex for traceability). Operators
//	paste HSRP bytes (UDP destination port 1985 to 224.0.0.2
//	for v1, 224.0.0.102 / FF02::66 for v2, port 1985 / 2029)
//	from a `tcpdump -X port 1985` line or a Wireshark Follow-
//	UDP-Stream view and get the documented packet breakdown.
//
// What this package covers
//
//   - **Version auto-detection** — byte 0 = 0 implies HSRPv1
//     (1-byte version, 19 more bytes); bytes 0-1 forming a
//     plausible (Type, Length) TLV pair (Type ∈ {1, 2, 3},
//     Length ∈ {38, 9, 26}) implies HSRPv2.
//
//   - **HSRPv1 fixed 20-byte packet** (RFC 2281 §5):
//
//   - byte 0: **Version** (0 for v1).
//
//   - byte 1: **Op Code** with **3-entry name table**:
//     0 Hello, 1 Coup, 2 Resign.
//
//   - byte 2: **State** with **6-entry name table**:
//     0 Initial, 1 Learn, 2 Listen, 4 Speak, 8 Standby,
//     16 Active. (Encoded as a sparse 0/1/2/4/8/16 ladder
//     so that bit-OR comparisons can express transitions.)
//
//   - byte 3: Hellotime (uint8 seconds; default 3).
//
//   - byte 4: Holdtime (uint8 seconds; default 10).
//
//   - byte 5: **Priority** (uint8 — higher wins; default
//     100; the standard's Master/Backup ordering knob).
//
//   - byte 6: Group (uint8 — the HSRP group number on the
//     LAN; 0-255).
//
//   - byte 7: Reserved (0).
//
//   - bytes 8-15: **Authentication Data** — 8 bytes of
//     ASCII; default "cisco\0\0\0" (deprecated cleartext
//     auth per RFC 2281 §3.5, kept here for plaintext
//     extraction).
//
//   - bytes 16-19: **Virtual IPv4 Address** (the virtual
//     default gateway IP that end hosts use).
//
//   - **HSRPv2 TLV envelope** — repeated (Type uint8, Length
//     uint8, Value) records. **3-entry TLV type table**:
//
//   - Type **1 Group State TLV** (Length 40; Cisco
//     proprietary). Body:
//
//   - byte 0: Version (always 2 for v2).
//
//   - byte 1: Op Code (0 Hello, 1 Coup, 2 Resign,
//     3 Advertise — v2 addition).
//
//   - byte 2: State (sparse ladder; 0 Initial, 1 Learn,
//     2 Listen, 3 Speak, 4 Standby, 5 Active — v2 packs
//     this densely unlike v1).
//
//   - byte 3: **IP Version** (4 IPv4 / 6 IPv6).
//
//   - bytes 4-5: Group (uint16 BE — v2 extends to 16
//     bits so groups can exceed 255).
//
//   - bytes 6-11: **Identifier** — the router's source
//     MAC address (6 bytes; surfaced colon-separated).
//
//   - bytes 12-15: Priority (uint32 BE — v2 widens to 32
//     bits for finer election control).
//
//   - bytes 16-19: Hello Time (uint32 BE, milliseconds —
//     v2 supports sub-second hellos).
//
//   - bytes 20-23: Hold Time (uint32 BE, milliseconds).
//
//   - bytes 24-39: Virtual IP Address — 16-byte slot
//     (full IPv6 when v=6; IPv4 in first 4 bytes with
//     the remaining 12 zero-padded when v=4).
//
//   - Type **2 Text Authentication TLV** (Length 9). Body:
//
//   - byte 0: Auth Type (always 0 for text).
//
//   - bytes 1-8: 8-byte ASCII password.
//
//   - Type **3 MD5 Authentication TLV** (Length 28). Body:
//
//   - byte 0: Algorithm (1 = MD5).
//
//   - byte 1: Padding (0).
//
//   - bytes 2-3: Flags.
//
//   - bytes 4-7: IP Address (the sender's source IP).
//
//   - bytes 8-11: Key ID.
//
//   - bytes 12-27: 16-byte MD5 digest (surfaced as hex).
//
// What this package does NOT cover (deliberately out of scope)
//
//   - UDP framing — feed HSRP bytes after the UDP header
//     strip. HSRP runs over UDP port 1985 (v1 + v2 IPv4) or
//     2029 (v2 IPv6).
//
//   - HSRP Authentication verification — text passwords are
//     surfaced as ASCII; MD5 digests as hex. Verifying the
//     MD5 digest requires the receiver to know the shared
//     key + reconstruct the exact byte sequence the sender
//     hashed (RFC 2281 §3.5 — deliberately deferred).
//
//   - HSRP Master/Backup election simulation — Priority,
//     Hellotime, Holdtime are surfaced; the multi-router
//     state machine reasoning is higher-level.
package hsrp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Result is the top-level decoded view.
type Result struct {
	Version    int      `json:"version"`
	V1         *V1Body  `json:"v1,omitempty"`
	V2TLVs     []TLV    `json:"v2_tlvs,omitempty"`
	TotalBytes int      `json:"total_bytes"`
	Notes      []string `json:"notes,omitempty"`
}

// V1Body is the parsed HSRPv1 fixed 20-byte packet.
type V1Body struct {
	OpCode             int    `json:"op_code"`
	OpCodeName         string `json:"op_code_name"`
	State              int    `json:"state"`
	StateName          string `json:"state_name"`
	HelloTimeSeconds   int    `json:"hello_time_seconds"`
	HoldTimeSeconds    int    `json:"hold_time_seconds"`
	Priority           int    `json:"priority"`
	PriorityNote       string `json:"priority_note,omitempty"`
	Group              int    `json:"group"`
	Reserved           int    `json:"reserved"`
	AuthenticationText string `json:"authentication_text"`
	AuthenticationHex  string `json:"authentication_hex"`
	VirtualIPv4Address string `json:"virtual_ipv4_address"`
}

// TLV is one HSRPv2 (Type, Length, Value) record.
type TLV struct {
	Type     int    `json:"type"`
	TypeName string `json:"type_name"`
	Length   int    `json:"length"`
	ValueHex string `json:"value_hex,omitempty"`

	// Decoded forms populated for known Types.
	GroupState *V2GroupState `json:"group_state,omitempty"`
	TextAuth   *V2TextAuth   `json:"text_auth,omitempty"`
	MD5Auth    *V2MD5Auth    `json:"md5_auth,omitempty"`
}

// V2GroupState is the decoded form of TLV Type 1.
type V2GroupState struct {
	Version          int    `json:"version"`
	OpCode           int    `json:"op_code"`
	OpCodeName       string `json:"op_code_name"`
	State            int    `json:"state"`
	StateName        string `json:"state_name"`
	IPVersion        int    `json:"ip_version"`
	Group            int    `json:"group"`
	IdentifierMAC    string `json:"identifier_mac"`
	Priority         uint32 `json:"priority"`
	HelloTimeMs      uint32 `json:"hello_time_ms"`
	HoldTimeMs       uint32 `json:"hold_time_ms"`
	VirtualIPAddress string `json:"virtual_ip_address"`
}

// V2TextAuth is the decoded form of TLV Type 2.
type V2TextAuth struct {
	AuthType int    `json:"auth_type"`
	Password string `json:"password"`
}

// V2MD5Auth is the decoded form of TLV Type 3.
type V2MD5Auth struct {
	Algorithm int    `json:"algorithm"`
	Padding   int    `json:"padding"`
	Flags     int    `json:"flags"`
	IPAddress string `json:"ip_address"`
	KeyID     uint32 `json:"key_id"`
	DigestHex string `json:"digest_hex"`
}

// Decode parses a single HSRP packet from hex.
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
		return nil, fmt.Errorf("HSRP packet truncated (%d bytes; need ≥2 to dispatch)",
			len(b))
	}
	r := &Result{TotalBytes: len(b)}

	if looksLikeV2(b) {
		r.Version = 2
		tlvs, err := decodeV2TLVs(b)
		if err != nil {
			return r, err
		}
		r.V2TLVs = tlvs
		return r, nil
	}

	// Default to v1 (Version byte must be 0).
	if len(b) < 20 {
		return nil, fmt.Errorf("HSRPv1 packet truncated (%d bytes; need 20)", len(b))
	}
	if b[0] != 0 {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"version byte is 0x%02X (HSRPv1 expects 0x00; falling back to v1 layout)",
			b[0]))
	}
	r.Version = int(b[0])
	v1, err := decodeV1(b)
	if err != nil {
		return r, err
	}
	r.V1 = v1
	return r, nil
}

// looksLikeV2 returns true when the first two bytes form a
// plausible HSRPv2 TLV (Type ∈ {1,2,3}, Length matches the
// known body sizes).
func looksLikeV2(b []byte) bool {
	if len(b) < 2 {
		return false
	}
	switch b[0] {
	case 1:
		return b[1] == 40
	case 2:
		return b[1] == 9
	case 3:
		return b[1] == 28
	}
	return false
}

func decodeV1(b []byte) (*V1Body, error) {
	v := &V1Body{
		OpCode:             int(b[1]),
		State:              int(b[2]),
		HelloTimeSeconds:   int(b[3]),
		HoldTimeSeconds:    int(b[4]),
		Priority:           int(b[5]),
		Group:              int(b[6]),
		Reserved:           int(b[7]),
		AuthenticationHex:  strings.ToUpper(hex.EncodeToString(b[8:16])),
		AuthenticationText: trimNuls(string(b[8:16])),
		VirtualIPv4Address: net.IPv4(b[16], b[17], b[18], b[19]).String(),
	}
	v.OpCodeName = opCodeName(v.OpCode)
	v.StateName = stateName(v.State)
	v.PriorityNote = priorityNote(v.Priority)
	return v, nil
}

func decodeV2TLVs(b []byte) ([]TLV, error) {
	var out []TLV
	off := 0
	for off+2 <= len(b) {
		typ := int(b[off])
		ln := int(b[off+1])
		if off+2+ln > len(b) {
			return out, fmt.Errorf("TLV type %d length %d truncates packet at offset %d",
				typ, ln, off)
		}
		v := b[off+2 : off+2+ln]
		t := TLV{
			Type:     typ,
			TypeName: tlvTypeName(typ),
			Length:   ln,
			ValueHex: strings.ToUpper(hex.EncodeToString(v)),
		}
		switch typ {
		case 1:
			gs, err := decodeV2GroupState(v)
			if err != nil {
				return out, fmt.Errorf("group state TLV: %w", err)
			}
			t.GroupState = gs
		case 2:
			if len(v) >= 9 {
				t.TextAuth = &V2TextAuth{
					AuthType: int(v[0]),
					Password: trimNuls(string(v[1:9])),
				}
			}
		case 3:
			if len(v) >= 28 {
				t.MD5Auth = &V2MD5Auth{
					Algorithm: int(v[0]),
					Padding:   int(v[1]),
					Flags:     int(binary.BigEndian.Uint16(v[2:4])),
					IPAddress: net.IPv4(v[4], v[5], v[6], v[7]).String(),
					KeyID:     binary.BigEndian.Uint32(v[8:12]),
					DigestHex: strings.ToUpper(hex.EncodeToString(v[12:28])),
				}
			}
		}
		out = append(out, t)
		off += 2 + ln
	}
	return out, nil
}

func decodeV2GroupState(v []byte) (*V2GroupState, error) {
	if len(v) < 40 {
		return nil, fmt.Errorf("group state body truncated (%d; need 40)", len(v))
	}
	gs := &V2GroupState{
		Version:     int(v[0]),
		OpCode:      int(v[1]),
		State:       int(v[2]),
		IPVersion:   int(v[3]),
		Group:       int(binary.BigEndian.Uint16(v[4:6])),
		Priority:    binary.BigEndian.Uint32(v[12:16]),
		HelloTimeMs: binary.BigEndian.Uint32(v[16:20]),
		HoldTimeMs:  binary.BigEndian.Uint32(v[20:24]),
	}
	gs.IdentifierMAC = formatMAC(v[6:12])
	gs.OpCodeName = v2OpCodeName(gs.OpCode)
	gs.StateName = v2StateName(gs.State)
	switch gs.IPVersion {
	case 4:
		gs.VirtualIPAddress = net.IPv4(v[24], v[25], v[26], v[27]).String()
	case 6:
		ip := make(net.IP, 16)
		copy(ip, v[24:40])
		gs.VirtualIPAddress = ip.String()
	default:
		gs.VirtualIPAddress = strings.ToUpper(hex.EncodeToString(v[24:40]))
	}
	return gs, nil
}

func opCodeName(c int) string {
	switch c {
	case 0:
		return "Hello"
	case 1:
		return "Coup"
	case 2:
		return "Resign"
	}
	return fmt.Sprintf("uncatalogued op code %d", c)
}

func stateName(s int) string {
	switch s {
	case 0:
		return "Initial"
	case 1:
		return "Learn"
	case 2:
		return "Listen"
	case 4:
		return "Speak"
	case 8:
		return "Standby"
	case 16:
		return "Active"
	}
	return fmt.Sprintf("uncatalogued state %d", s)
}

func priorityNote(p int) string {
	switch p {
	case 0:
		return "0 — withdraw (router signalling shutdown)"
	case 100:
		return "100 — default Cisco priority"
	case 255:
		return "255 — maximum (always wins election)"
	}
	return ""
}

func v2OpCodeName(c int) string {
	switch c {
	case 0:
		return "Hello"
	case 1:
		return "Coup"
	case 2:
		return "Resign"
	case 3:
		return "Advertise"
	}
	return fmt.Sprintf("uncatalogued op code %d", c)
}

func v2StateName(s int) string {
	switch s {
	case 0:
		return "Initial"
	case 1:
		return "Learn"
	case 2:
		return "Listen"
	case 3:
		return "Speak"
	case 4:
		return "Standby"
	case 5:
		return "Active"
	}
	return fmt.Sprintf("uncatalogued state %d", s)
}

func tlvTypeName(t int) string {
	switch t {
	case 1:
		return "Group State"
	case 2:
		return "Text Authentication"
	case 3:
		return "MD5 Authentication"
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

func trimNuls(s string) string {
	return strings.TrimRight(s, "\x00")
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
