// Package pim decodes Protocol Independent Multicast (PIM)
// version 2 packets per RFC 7761 (PIM-SM v2; the dominant
// multicast routing protocol). PIM Sparse-Mode is the de-facto
// multicast routing protocol in every enterprise + ISP + cloud
// fabric that carries multicast traffic; the Dense-Mode +
// BIDIR variants share the same packet envelope and the same
// type space.
//
// Wrap-vs-native judgement
//
//	Native. RFC 7761 is fully public; PIM uses a tight 4-byte
//	common header (Version + Type + Reserved + Checksum)
//	followed by a per-type body. Bodies use a small set of
//	well-defined "Encoded Address" formats (Unicast / Group /
//	Source — RFC 7761 §4.9) plus typed TLV options for Hello.
//	No crypto, no compression — operators paste PIM bytes (IP
//	protocol number 103, multicast to 224.0.0.13 for Hello /
//	Bootstrap / Assert / Join-Prune, unicast to RPs for
//	Register) from a `tcpdump -X proto 103` line, a Wireshark
//	Follow-IP-Stream view, or any PIM-speaking router's
//	tcpdump and get the documented header + per-type body
//	breakdown.
//
// What this package covers
//
//   - **4-byte common header** (RFC 7761 §4.9):
//
//   - byte 0: Version (4 bits; always 2) + Type (4 bits).
//
//   - byte 1: Reserved (0; some PIM variants use this byte
//     as a subtype — surfaced as a Note when non-zero).
//
//   - bytes 2-3: Checksum (uint16 BE, hex-formatted).
//
//   - **11-entry Type name table** (RFC 7761 §4.9 + the older
//     PIM-DM / BIDIR / PIM-MIB registries):
//     0 Hello, 1 Register, 2 Register-Stop, 3 Join/Prune,
//     4 Bootstrap, 5 Assert, 6 Graft (PIM-DM only), 7 Graft-Ack
//     (PIM-DM only), 8 Candidate-RP-Advertisement, 9 State
//     Refresh (PIM-DM only), 10 DF Election (PIM-BIDIR).
//
//   - **Hello body** (Type 0; RFC 7761 §4.3) — TLV option
//     walker over (Type uint16 BE, Length uint16 BE, Value)
//     records. **5-entry option type table**:
//     1 Holdtime (uint16 seconds; 0xFFFF = never timeout),
//     2 LAN Prune Delay (uint16 propagation_delay + uint16
//     override_interval with T-bit in the high bit of
//     propagation_delay),
//     19 DR Priority (uint32 — higher wins; absence = treat
//     as priority 0 per RFC 7761 §4.3.2),
//     20 Generation ID (uint32 — changes on neighbor reset; a
//     change is the canonical detection of a PIM neighbor reboot),
//     24 Address List (encoded-address list of secondary
//     addresses the router owns on the LAN).
//
//   - **Register body** (Type 1; RFC 7761 §4.4) — 4-byte flags
//     (B = Border-bit, N = Null-Register-bit) + encapsulated
//     multicast IP datagram (surfaced as raw hex; first nibble
//     heuristic for inner IPv4 vs IPv6).
//
//   - **Register-Stop body** (Type 2; RFC 7761 §4.4) — Encoded
//     Group Address + Encoded Unicast Source Address.
//
//   - **Join/Prune body** (Type 3; RFC 7761 §4.5) — Encoded
//     Unicast Upstream Neighbor + Reserved + Num Groups + Hold
//     Time (uint16 seconds) + N × Group records:
//
//   - Multicast Group Address (Encoded Group)
//
//   - Number of Joined Sources (uint16)
//
//   - Number of Pruned Sources (uint16)
//
//   - Joined Source Addresses (N × Encoded Source)
//
//   - Pruned Source Addresses (N × Encoded Source)
//
//   - **Bootstrap body** (Type 4; RFC 5059) — Fragment Tag +
//     Hash Mask Len + BSR Priority + Encoded Unicast BSR
//     Address + per-group RP-Set records (decoded structurally,
//     including the RP records inside each group).
//
//   - **Assert body** (Type 5; RFC 7761 §4.6) — Encoded Group
//     Address + Encoded Unicast Source Address + 1-bit R (RPT
//     bit, high bit of byte 0) + 31-bit Metric Preference +
//     32-bit Metric. Used for tie-breaking when multiple PIM
//     routers see the same multicast forwarder candidate on a LAN.
//
//   - **Encoded Address parsing** (RFC 7761 §4.9.1):
//
//   - **Encoded Unicast** — Addr Family (1 byte: 1 IPv4 / 2
//     IPv6) + Encoding Type (1 byte; 0 native) + Address (4
//     bytes IPv4 / 16 bytes IPv6).
//
//   - **Encoded Group** — Addr Family + Encoding Type + Flags
//     byte (B-bit + Z-bit) + Mask Length + Group Address.
//
//   - **Encoded Source** — Addr Family + Encoding Type + Flags
//     byte (S/W/R bits in the low 3 bits of byte 2) + Mask
//     Length + Source Address.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - IP framing — feed PIM bytes after the IPv4/IPv6 header
//     strip. PIM runs over IP protocol 103.
//
//   - PIMv1 — the pre-RFC 2117 "DVMRP-like" form is obsolete
//     (no production deployments since the late 1990s); the
//     Version field will be flagged in a Note if it is not 2.
//
//   - Multicast routing-table reasoning — RPF check, (*,G) and
//     (S,G) tree state — that's higher-level analysis.
//
//   - PIM checksum verification — surfaced as a hex string but
//     not recomputed (the IPv4 pseudo-header dependency would
//     require the operator to provide the IP src/dst).
package pim

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Result is the top-level decoded view.
type Result struct {
	Version     int    `json:"version"`
	Type        int    `json:"type"`
	TypeName    string `json:"type_name"`
	Reserved    int    `json:"reserved"`
	ChecksumHex string `json:"checksum_hex"`
	TotalBytes  int    `json:"total_bytes"`

	Hello        *HelloBody        `json:"hello,omitempty"`
	Register     *RegisterBody     `json:"register,omitempty"`
	RegisterStop *RegisterStopBody `json:"register_stop,omitempty"`
	JoinPrune    *JoinPruneBody    `json:"join_prune,omitempty"`
	Assert       *AssertBody       `json:"assert,omitempty"`
	Bootstrap    *BootstrapBody    `json:"bootstrap,omitempty"`

	Notes []string `json:"notes,omitempty"`
}

// HelloBody is the TLV option list from a PIM Hello.
type HelloBody struct {
	Options []HelloOption `json:"options"`
}

// HelloOption is one TLV record from a PIM Hello.
type HelloOption struct {
	Type     int    `json:"type"`
	TypeName string `json:"type_name"`
	Length   int    `json:"length"`
	ValueHex string `json:"value_hex,omitempty"`

	// Decoded forms (populated for known types).
	HoldtimeSeconds       *int     `json:"holdtime_seconds,omitempty"`
	HoldtimeNote          string   `json:"holdtime_note,omitempty"`
	DRPriority            *uint32  `json:"dr_priority,omitempty"`
	GenerationID          *uint32  `json:"generation_id,omitempty"`
	LANPropagationDelayMs *uint16  `json:"lan_propagation_delay_ms,omitempty"`
	LANOverrideIntervalMs *uint16  `json:"lan_override_interval_ms,omitempty"`
	LANTBit               *bool    `json:"lan_t_bit,omitempty"`
	AddressList           []string `json:"address_list,omitempty"`
}

// RegisterBody is the unicast-tunnelled multicast datagram body.
type RegisterBody struct {
	FlagBorder   bool   `json:"flag_border"`
	FlagNull     bool   `json:"flag_null_register"`
	FlagsHex     string `json:"flags_hex"`
	EncapHex     string `json:"encapsulated_datagram_hex,omitempty"`
	EncapBytes   int    `json:"encapsulated_datagram_bytes"`
	EncapVersion int    `json:"encapsulated_ip_version,omitempty"`
}

// RegisterStopBody is the stop signal for a Register tunnel.
type RegisterStopBody struct {
	Group  EncodedGroup   `json:"group"`
	Source EncodedUnicast `json:"source"`
}

// JoinPruneBody is the Join/Prune state for one upstream
// neighbor.
type JoinPruneBody struct {
	UpstreamNeighbor EncodedUnicast   `json:"upstream_neighbor"`
	NumGroups        int              `json:"num_groups"`
	HoldTimeSeconds  int              `json:"hold_time_seconds"`
	Groups           []JoinPruneGroup `json:"groups"`
}

// JoinPruneGroup is one group record inside a Join/Prune.
type JoinPruneGroup struct {
	Group         EncodedGroup    `json:"group"`
	NumJoined     int             `json:"num_joined_sources"`
	NumPruned     int             `json:"num_pruned_sources"`
	JoinedSources []EncodedSource `json:"joined_sources,omitempty"`
	PrunedSources []EncodedSource `json:"pruned_sources,omitempty"`
}

// AssertBody is a PIM Assert with the (group, source) tuple
// and the metric.
type AssertBody struct {
	Group            EncodedGroup   `json:"group"`
	Source           EncodedUnicast `json:"source"`
	RPTBit           bool           `json:"rpt_bit"`
	MetricPreference uint32         `json:"metric_preference"`
	Metric           uint32         `json:"metric"`
}

// BootstrapBody is a PIM-BSR Bootstrap message.
type BootstrapBody struct {
	FragmentTag    uint16         `json:"fragment_tag"`
	HashMaskLen    int            `json:"hash_mask_length"`
	BSRPriority    int            `json:"bsr_priority"`
	BSRAddress     EncodedUnicast `json:"bsr_address"`
	RemainderHex   string         `json:"remainder_hex,omitempty"`
	RemainderBytes int            `json:"remainder_bytes"`
}

// EncodedUnicast is RFC 7761 §4.9.1 Encoded-Unicast-Address.
type EncodedUnicast struct {
	AddressFamily int    `json:"address_family"`
	EncodingType  int    `json:"encoding_type"`
	Address       string `json:"address"`
}

// EncodedGroup is RFC 7761 §4.9.1 Encoded-Group-Address.
type EncodedGroup struct {
	AddressFamily int    `json:"address_family"`
	EncodingType  int    `json:"encoding_type"`
	BBit          bool   `json:"b_bit_bidir"`
	ZBit          bool   `json:"z_bit_admin_scope_zone"`
	MaskLength    int    `json:"mask_length"`
	Address       string `json:"address"`
}

// EncodedSource is RFC 7761 §4.9.1 Encoded-Source-Address.
type EncodedSource struct {
	AddressFamily int    `json:"address_family"`
	EncodingType  int    `json:"encoding_type"`
	SBit          bool   `json:"s_bit_sparse"`
	WBit          bool   `json:"w_bit_wildcard"`
	RBit          bool   `json:"r_bit_rpt"`
	MaskLength    int    `json:"mask_length"`
	Address       string `json:"address"`
}

// Decode parses a single PIMv2 packet from hex.
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
		return nil, fmt.Errorf("PIM packet truncated (%d bytes; need ≥4)", len(b))
	}

	r := &Result{
		TotalBytes:  len(b),
		Version:     int(b[0] >> 4),
		Type:        int(b[0] & 0x0F),
		Reserved:    int(b[1]),
		ChecksumHex: fmt.Sprintf("0x%04X", binary.BigEndian.Uint16(b[2:4])),
	}
	r.TypeName = typeName(r.Type)

	if r.Version != 2 {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"version is %d (only PIMv2 — RFC 7761 — is currently defined)",
			r.Version))
	}
	if r.Reserved != 0 {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"Reserved byte is 0x%02X (expected 0x00; some PIM extensions overload this byte as a subtype)",
			r.Reserved))
	}

	body := b[4:]
	switch r.Type {
	case 0:
		r.Hello, err = decodeHello(body)
	case 1:
		r.Register, err = decodeRegister(body)
	case 2:
		r.RegisterStop, err = decodeRegisterStop(body)
	case 3:
		r.JoinPrune, err = decodeJoinPrune(body)
	case 4:
		r.Bootstrap, err = decodeBootstrap(body)
	case 5:
		r.Assert, err = decodeAssert(body)
	default:
		if r.Type > 10 {
			r.Notes = append(r.Notes, fmt.Sprintf(
				"uncatalogued PIM Type %d (RFC 7761 + PIM-DM + BIDIR define 0-10)",
				r.Type))
		}
	}
	if err != nil {
		return r, fmt.Errorf("%s body: %w", r.TypeName, err)
	}
	return r, nil
}

func decodeHello(b []byte) (*HelloBody, error) {
	h := &HelloBody{}
	off := 0
	for off+4 <= len(b) {
		typ := int(binary.BigEndian.Uint16(b[off : off+2]))
		ln := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		if off+4+ln > len(b) {
			return h, fmt.Errorf("hello option %d truncated (need %d bytes)", typ, ln)
		}
		v := b[off+4 : off+4+ln]
		opt := HelloOption{
			Type:     typ,
			TypeName: helloOptionName(typ),
			Length:   ln,
			ValueHex: strings.ToUpper(hex.EncodeToString(v)),
		}
		switch typ {
		case 1:
			if ln == 2 {
				ht := int(binary.BigEndian.Uint16(v))
				opt.HoldtimeSeconds = &ht
				switch ht {
				case 0:
					opt.HoldtimeNote = "0 — withdraw (router shutting down)"
				case 0xFFFF:
					opt.HoldtimeNote = "0xFFFF — never timeout"
				}
			}
		case 2:
			if ln == 4 {
				pd := binary.BigEndian.Uint16(v[0:2])
				oi := binary.BigEndian.Uint16(v[2:4])
				tBit := pd&0x8000 != 0
				pdVal := pd & 0x7FFF
				opt.LANPropagationDelayMs = &pdVal
				opt.LANOverrideIntervalMs = &oi
				opt.LANTBit = &tBit
			}
		case 19:
			if ln == 4 {
				dr := binary.BigEndian.Uint32(v)
				opt.DRPriority = &dr
			}
		case 20:
			if ln == 4 {
				gid := binary.BigEndian.Uint32(v)
				opt.GenerationID = &gid
			}
		case 24:
			i := 0
			for i+2 <= len(v) {
				ea, used, err := parseEncodedUnicast(v[i:])
				if err != nil {
					break
				}
				opt.AddressList = append(opt.AddressList, ea.Address)
				i += used
			}
		}
		h.Options = append(h.Options, opt)
		off += 4 + ln
	}
	return h, nil
}

func decodeRegister(b []byte) (*RegisterBody, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("register body truncated (%d; need ≥4)", len(b))
	}
	flags := binary.BigEndian.Uint32(b[0:4])
	r := &RegisterBody{
		FlagBorder: flags&0x80000000 != 0,
		FlagNull:   flags&0x40000000 != 0,
		FlagsHex:   fmt.Sprintf("0x%08X", flags),
		EncapBytes: len(b) - 4,
	}
	if len(b) > 4 {
		r.EncapHex = strings.ToUpper(hex.EncodeToString(b[4:]))
		first := b[4] >> 4
		switch first {
		case 4:
			r.EncapVersion = 4
		case 6:
			r.EncapVersion = 6
		}
	}
	return r, nil
}

func decodeRegisterStop(b []byte) (*RegisterStopBody, error) {
	g, used, err := parseEncodedGroup(b)
	if err != nil {
		return nil, fmt.Errorf("group: %w", err)
	}
	s, _, err := parseEncodedUnicast(b[used:])
	if err != nil {
		return nil, fmt.Errorf("source: %w", err)
	}
	return &RegisterStopBody{Group: g, Source: s}, nil
}

func decodeJoinPrune(b []byte) (*JoinPruneBody, error) {
	up, used, err := parseEncodedUnicast(b)
	if err != nil {
		return nil, fmt.Errorf("upstream: %w", err)
	}
	off := used
	if off+4 > len(b) {
		return nil, fmt.Errorf("Join/Prune body truncated after upstream neighbor")
	}
	numGroups := int(b[off+1])
	holdTime := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
	off += 4
	jp := &JoinPruneBody{
		UpstreamNeighbor: up,
		NumGroups:        numGroups,
		HoldTimeSeconds:  holdTime,
	}
	for i := 0; i < numGroups && off < len(b); i++ {
		g, gu, err := parseEncodedGroup(b[off:])
		if err != nil {
			return jp, fmt.Errorf("group %d: %w", i, err)
		}
		off += gu
		if off+4 > len(b) {
			return jp, fmt.Errorf("group %d header truncated", i)
		}
		nj := int(binary.BigEndian.Uint16(b[off : off+2]))
		np := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		off += 4
		rec := JoinPruneGroup{
			Group:     g,
			NumJoined: nj,
			NumPruned: np,
		}
		for j := 0; j < nj && off < len(b); j++ {
			s, su, err := parseEncodedSource(b[off:])
			if err != nil {
				return jp, fmt.Errorf("group %d joined source %d: %w", i, j, err)
			}
			rec.JoinedSources = append(rec.JoinedSources, s)
			off += su
		}
		for j := 0; j < np && off < len(b); j++ {
			s, su, err := parseEncodedSource(b[off:])
			if err != nil {
				return jp, fmt.Errorf("group %d pruned source %d: %w", i, j, err)
			}
			rec.PrunedSources = append(rec.PrunedSources, s)
			off += su
		}
		jp.Groups = append(jp.Groups, rec)
	}
	return jp, nil
}

func decodeAssert(b []byte) (*AssertBody, error) {
	g, used, err := parseEncodedGroup(b)
	if err != nil {
		return nil, fmt.Errorf("group: %w", err)
	}
	s, su, err := parseEncodedUnicast(b[used:])
	if err != nil {
		return nil, fmt.Errorf("source: %w", err)
	}
	off := used + su
	if off+8 > len(b) {
		return nil, fmt.Errorf("assert metric truncated")
	}
	mp := binary.BigEndian.Uint32(b[off : off+4])
	met := binary.BigEndian.Uint32(b[off+4 : off+8])
	return &AssertBody{
		Group:            g,
		Source:           s,
		RPTBit:           mp&0x80000000 != 0,
		MetricPreference: mp & 0x7FFFFFFF,
		Metric:           met,
	}, nil
}

func decodeBootstrap(b []byte) (*BootstrapBody, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("bootstrap header truncated")
	}
	bs := &BootstrapBody{
		FragmentTag: binary.BigEndian.Uint16(b[0:2]),
		HashMaskLen: int(b[2]),
		BSRPriority: int(b[3]),
	}
	addr, used, err := parseEncodedUnicast(b[4:])
	if err != nil {
		return bs, fmt.Errorf("BSR address: %w", err)
	}
	bs.BSRAddress = addr
	rem := b[4+used:]
	bs.RemainderBytes = len(rem)
	if len(rem) > 0 {
		bs.RemainderHex = strings.ToUpper(hex.EncodeToString(rem))
	}
	return bs, nil
}

// parseEncodedUnicast reads an Encoded-Unicast-Address per RFC
// 7761 §4.9.1. Returns the parsed address and the number of
// bytes consumed.
func parseEncodedUnicast(b []byte) (EncodedUnicast, int, error) {
	if len(b) < 2 {
		return EncodedUnicast{}, 0, fmt.Errorf("encoded-unicast header truncated")
	}
	af := int(b[0])
	et := int(b[1])
	addrLen, err := addressLength(af)
	if err != nil {
		return EncodedUnicast{}, 0, err
	}
	if len(b) < 2+addrLen {
		return EncodedUnicast{}, 0, fmt.Errorf("encoded-unicast address truncated")
	}
	return EncodedUnicast{
		AddressFamily: af,
		EncodingType:  et,
		Address:       formatAddress(af, b[2:2+addrLen]),
	}, 2 + addrLen, nil
}

// parseEncodedGroup reads an Encoded-Group-Address per RFC
// 7761 §4.9.1: 2-byte family/type + 1-byte flags (B/Z) + 1-byte
// mask length + address.
func parseEncodedGroup(b []byte) (EncodedGroup, int, error) {
	if len(b) < 4 {
		return EncodedGroup{}, 0, fmt.Errorf("encoded-group header truncated")
	}
	af := int(b[0])
	et := int(b[1])
	flags := b[2]
	ml := int(b[3])
	addrLen, err := addressLength(af)
	if err != nil {
		return EncodedGroup{}, 0, err
	}
	if len(b) < 4+addrLen {
		return EncodedGroup{}, 0, fmt.Errorf("encoded-group address truncated")
	}
	return EncodedGroup{
		AddressFamily: af,
		EncodingType:  et,
		BBit:          flags&0x80 != 0,
		ZBit:          flags&0x01 != 0,
		MaskLength:    ml,
		Address:       formatAddress(af, b[4:4+addrLen]),
	}, 4 + addrLen, nil
}

// parseEncodedSource reads an Encoded-Source-Address per RFC
// 7761 §4.9.1: 2-byte family/type + 1-byte flags (S/W/R in
// the low 3 bits) + 1-byte mask length + address.
func parseEncodedSource(b []byte) (EncodedSource, int, error) {
	if len(b) < 4 {
		return EncodedSource{}, 0, fmt.Errorf("encoded-source header truncated")
	}
	af := int(b[0])
	et := int(b[1])
	flags := b[2]
	ml := int(b[3])
	addrLen, err := addressLength(af)
	if err != nil {
		return EncodedSource{}, 0, err
	}
	if len(b) < 4+addrLen {
		return EncodedSource{}, 0, fmt.Errorf("encoded-source address truncated")
	}
	return EncodedSource{
		AddressFamily: af,
		EncodingType:  et,
		SBit:          flags&0x04 != 0,
		WBit:          flags&0x02 != 0,
		RBit:          flags&0x01 != 0,
		MaskLength:    ml,
		Address:       formatAddress(af, b[4:4+addrLen]),
	}, 4 + addrLen, nil
}

func addressLength(af int) (int, error) {
	switch af {
	case 1:
		return 4, nil
	case 2:
		return 16, nil
	}
	return 0, fmt.Errorf("unknown address family %d (1 IPv4 / 2 IPv6 supported)", af)
}

func formatAddress(af int, b []byte) string {
	switch af {
	case 1:
		if len(b) == 4 {
			return net.IPv4(b[0], b[1], b[2], b[3]).String()
		}
	case 2:
		if len(b) == 16 {
			return net.IP(b).String()
		}
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

func typeName(t int) string {
	switch t {
	case 0:
		return "Hello"
	case 1:
		return "Register"
	case 2:
		return "Register-Stop"
	case 3:
		return "Join/Prune"
	case 4:
		return "Bootstrap"
	case 5:
		return "Assert"
	case 6:
		return "Graft"
	case 7:
		return "Graft-Ack"
	case 8:
		return "Candidate-RP-Advertisement"
	case 9:
		return "State Refresh"
	case 10:
		return "DF Election"
	}
	return fmt.Sprintf("uncatalogued type %d", t)
}

func helloOptionName(t int) string {
	switch t {
	case 1:
		return "Holdtime"
	case 2:
		return "LAN Prune Delay"
	case 19:
		return "DR Priority"
	case 20:
		return "Generation ID"
	case 24:
		return "Address List"
	}
	return fmt.Sprintf("uncatalogued option type %d", t)
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
