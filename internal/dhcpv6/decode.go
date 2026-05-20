// Package dhcpv6 decodes DHCPv6 packets per RFC 8415 (which
// consolidates RFC 3315 + RFC 3633 prefix delegation + RFC 3646
// DNS configuration + RFC 4242 information refresh time +
// RFC 7083 rapid-commit / unicast updates into one current
// spec). DHCPv6 is the stateful IPv6 address assignment +
// configuration protocol used alongside SLAAC on every dual-
// stack network; every consumer IPv6 router (M-bit set in RA),
// every cellular IPv6 carrier, every enterprise IPv6 deployment
// runs DHCPv6 for at least DNS / NTP / Prefix Delegation.
//
// Wrap-vs-native judgement
//
//	Native. RFC 8415 is fully public; DHCPv6 has a tight
//	4-byte fixed header (msg type + 3-byte transaction ID,
//	or a 34-byte header for Relay-Forward/Reply messages)
//	followed by a uniform TLV option list (2-byte code +
//	2-byte length + value bytes). No crypto, no compression.
//	Operators paste DHCPv6 bytes (UDP destination port 547
//	server-side / 546 client-side, multicast to
//	FF02::1:2 for the all-DHCP-relay-agents-and-servers
//	address) from a `tcpdump -X 'udp port 547'` line or a
//	Wireshark Follow-UDP-Stream view and get the documented
//	header + per-option breakdown.
//
// What this package covers
//
//   - **4-byte fixed header** (RFC 8415 §8):
//
//   - byte 0: **Message Type** with **13-entry name table**:
//     1 SOLICIT, 2 ADVERTISE, 3 REQUEST, 4 CONFIRM, 5 RENEW,
//     6 REBIND, 7 REPLY, 8 RELEASE, 9 DECLINE, 10
//     RECONFIGURE, 11 INFORMATION-REQUEST, 12 RELAY-FORW,
//     13 RELAY-REPL.
//
//   - bytes 1-3: **Transaction ID** (24-bit BE; uniquely
//     identifies a single transaction within a session).
//
//   - **Relay-Forward / Relay-Reply 34-byte header** (msg
//     types 12 + 13, RFC 8415 §9):
//
//   - byte 0: Message Type.
//
//   - byte 1: Hop Count (uint8; relay-agent depth limit).
//
//   - bytes 2-17: Link-Address (IPv6 — the link the agent
//     received the original packet on).
//
//   - bytes 18-33: Peer-Address (IPv6 — the original
//     client's address or the next-relay's address).
//
//   - Followed by the option list (which typically contains
//     OPTION_RELAY_MSG carrying the encapsulated packet).
//
//   - **TLV option walker** — repeated (Code uint16 BE,
//     Length uint16 BE, Value) records. **~20-entry option
//     code name table** covering the most common options from
//     RFC 8415 §21 + the IANA DHCPv6 Options registry:
//     1 OPTION_CLIENTID (DUID parsing — 4-entry DUID type
//     table: LLT / EN / LL / UUID),
//     2 OPTION_SERVERID (also DUID),
//     3 OPTION_IA_NA (Identity Association for Non-temporary
//     Addresses; IAID + T1/T2 + nested IAADDR options),
//     4 OPTION_IA_TA (Temporary Addresses),
//     5 OPTION_IAADDR (IPv6 address + preferred + valid
//     lifetimes; nested inside IA_NA / IA_TA),
//     6 OPTION_ORO (Option Request Option — uint16 list of
//     requested option codes),
//     7 OPTION_PREFERENCE (uint8; server preference for client
//     selection),
//     8 OPTION_ELAPSED_TIME (uint16 hundredths of second since
//     transaction start),
//     9 OPTION_RELAY_MSG (encapsulated DHCPv6 message inside
//     a Relay-Forward / Relay-Reply),
//     11 OPTION_AUTH (legacy auth — surfaced as hex),
//     12 OPTION_UNICAST (IPv6 — server preferred unicast),
//     13 OPTION_STATUS_CODE (uint16 status + UTF-8 message),
//     14 OPTION_RAPID_COMMIT (no value; 2-RT exchange marker),
//     16 OPTION_VENDOR_CLASS (Enterprise Number + opaque),
//     18 OPTION_INTERFACE_ID (relay-agent interface ID),
//     20 OPTION_RECONF_ACCEPT (no value),
//     23 OPTION_DNS_SERVERS (per RFC 3646; list of IPv6),
//     24 OPTION_DOMAIN_LIST (DNS search list — RFC 1035 wire
//     format),
//     25 OPTION_IA_PD (Identity Association for Prefix
//     Delegation — IAID + T1/T2 + nested IAPREFIX),
//     26 OPTION_IAPREFIX (preferred + valid + prefix length +
//     IPv6 prefix),
//     39 OPTION_CLIENT_FQDN (RFC 4704),
//     56 OPTION_NTP_SERVER (RFC 5908).
//
//   - **DUID parsing** (RFC 8415 §11) — inside ClientID +
//     ServerID:
//
//   - uint16 BE DUID Type (4-entry table):
//
//   - 1 DUID-LLT: Hardware type uint16 + Time uint32
//     (seconds since 2000-01-01 UTC) + Link-Layer Address.
//
//   - 2 DUID-EN: Enterprise Number uint32 + opaque
//     identifier.
//
//   - 3 DUID-LL: Hardware type uint16 + Link-Layer Address.
//
//   - 4 DUID-UUID: 16-byte UUID.
//
//   - **IA_NA / IA_PD body** — first 12 bytes are IAID
//     (uint32 BE) + T1 (uint32 BE seconds) + T2 (uint32 BE
//     seconds); remainder is a nested TLV list (typically
//     IAADDR for IA_NA or IAPREFIX for IA_PD).
//
//   - **IAADDR body** — IPv6 (16 bytes) + Preferred Lifetime
//     (uint32 BE seconds) + Valid Lifetime (uint32 BE
//     seconds) + nested options.
//
//   - **IAPREFIX body** — Preferred Lifetime (uint32 BE) +
//     Valid Lifetime (uint32 BE) + Prefix Length (uint8) +
//     IPv6 Prefix (16 bytes) + nested options.
//
//   - **Status Code body** — uint16 BE status code with
//     6-entry name table (0 Success, 1 UnspecFail, 2
//     NoAddrsAvail, 3 NoBinding, 4 NotOnLink, 5 UseMulticast,
//     6 NoPrefixAvail) + UTF-8 message string.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - UDP / IPv6 framing — feed DHCPv6 bytes after the UDP
//     header strip. DHCPv6 ships on UDP, destination port 547
//     server-side / 546 client-side.
//
//   - DHCPv4 — that's `internal/dhcp` (the existing
//     `dhcp_packet_decode` Spec); this Spec handles only the
//     v6 protocol.
//
//   - OPTION_AUTH integrity verification — RFC 8415 §21.11
//     surfaces the auth payload as hex; verifying the digest
//     would require the receiver to know the shared key.
//
//   - DHCPv6 Authentication / Reconfigure Key bookkeeping —
//     surfaced as hex; the multi-message state machine
//     reasoning is higher-level.
package dhcpv6

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode/utf8"
)

// Result is the top-level decoded view of a DHCPv6 packet.
type Result struct {
	MessageType     int    `json:"message_type"`
	MessageTypeName string `json:"message_type_name"`
	TransactionID   uint32 `json:"transaction_id,omitempty"`

	// Relay header (populated only for Relay-Forward / Reply).
	HopCount    *int   `json:"hop_count,omitempty"`
	LinkAddress string `json:"link_address,omitempty"`
	PeerAddress string `json:"peer_address,omitempty"`

	Options    []Option `json:"options"`
	TotalBytes int      `json:"total_bytes"`
	Notes      []string `json:"notes,omitempty"`
}

// Option is one DHCPv6 TLV option record with decoded body.
type Option struct {
	Code     int    `json:"code"`
	CodeName string `json:"code_name"`
	Length   int    `json:"length"`
	ValueHex string `json:"value_hex,omitempty"`

	// Decoded forms populated for known option codes.
	ClientID       *DUID         `json:"client_id,omitempty"`
	ServerID       *DUID         `json:"server_id,omitempty"`
	IANonTemp      *IABody       `json:"ia_na,omitempty"`
	IATemp         *IABody       `json:"ia_ta,omitempty"`
	IAPDelegate    *IABody       `json:"ia_pd,omitempty"`
	IAAddress      *IAAddrBody   `json:"ia_address,omitempty"`
	IAPrefix       *IAPrefixBody `json:"ia_prefix,omitempty"`
	OptionRequest  []int         `json:"option_request,omitempty"`
	Preference     *int          `json:"preference,omitempty"`
	ElapsedTimeCs  *int          `json:"elapsed_time_centiseconds,omitempty"`
	ElapsedTimeS   *float64      `json:"elapsed_time_seconds,omitempty"`
	RelayMsgHex    *string       `json:"relay_message_hex,omitempty"`
	UnicastAddress *string       `json:"unicast_address,omitempty"`
	StatusCode     *StatusCode   `json:"status_code,omitempty"`
	VendorClass    *VendorClass  `json:"vendor_class,omitempty"`
	DNSServers     []string      `json:"dns_servers,omitempty"`
	NTPServers     []string      `json:"ntp_servers,omitempty"`
	Text           string        `json:"text,omitempty"`
}

// DUID is the decoded form of OPTION_CLIENTID + OPTION_SERVERID.
type DUID struct {
	Type     int    `json:"type"`
	TypeName string `json:"type_name"`

	// LLT (Type 1):
	HardwareType *int   `json:"hardware_type,omitempty"`
	Time         *int64 `json:"time_seconds_since_2000,omitempty"`
	TimeISO      string `json:"time_iso,omitempty"`
	LinkLayerHex string `json:"link_layer_address_hex,omitempty"`

	// EN (Type 2):
	EnterpriseNumber *uint32 `json:"enterprise_number,omitempty"`
	IdentifierHex    string  `json:"identifier_hex,omitempty"`

	// UUID (Type 4):
	UUIDHex string `json:"uuid_hex,omitempty"`
}

// IABody is the decoded body of IA_NA / IA_TA / IA_PD options.
// IA_TA omits T1 / T2 — but exposing them as zero is harmless.
type IABody struct {
	IAID       uint32   `json:"iaid"`
	T1Seconds  uint32   `json:"t1_seconds"`
	T2Seconds  uint32   `json:"t2_seconds"`
	SubOptions []Option `json:"sub_options,omitempty"`
}

// IAAddrBody is the decoded body of OPTION_IAADDR.
type IAAddrBody struct {
	Address              string   `json:"address"`
	PreferredLifetimeSec uint32   `json:"preferred_lifetime_seconds"`
	ValidLifetimeSec     uint32   `json:"valid_lifetime_seconds"`
	SubOptions           []Option `json:"sub_options,omitempty"`
}

// IAPrefixBody is the decoded body of OPTION_IAPREFIX.
type IAPrefixBody struct {
	PreferredLifetimeSec uint32   `json:"preferred_lifetime_seconds"`
	ValidLifetimeSec     uint32   `json:"valid_lifetime_seconds"`
	PrefixLength         int      `json:"prefix_length"`
	Prefix               string   `json:"prefix"`
	SubOptions           []Option `json:"sub_options,omitempty"`
}

// StatusCode is the decoded body of OPTION_STATUS_CODE.
type StatusCode struct {
	Code     int    `json:"code"`
	CodeName string `json:"code_name"`
	Message  string `json:"message,omitempty"`
}

// VendorClass is the decoded body of OPTION_VENDOR_CLASS.
type VendorClass struct {
	EnterpriseNumber uint32   `json:"enterprise_number"`
	Items            []string `json:"items,omitempty"`
	RemainderHex     string   `json:"remainder_hex,omitempty"`
}

// Decode parses a single DHCPv6 packet from hex.
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
		return nil, fmt.Errorf("DHCPv6 packet truncated (%d bytes; need ≥4 for header)",
			len(b))
	}
	r := &Result{
		TotalBytes:      len(b),
		MessageType:     int(b[0]),
		MessageTypeName: messageTypeName(int(b[0])),
	}

	switch r.MessageType {
	case 12, 13: // Relay-Forward / Relay-Reply
		if len(b) < 34 {
			return r, fmt.Errorf("relay header truncated (%d; need 34)", len(b))
		}
		hop := int(b[1])
		r.HopCount = &hop
		r.LinkAddress = formatIPv6(b[2:18])
		r.PeerAddress = formatIPv6(b[18:34])
		opts, err := decodeOptions(b[34:])
		r.Options = opts
		if err != nil {
			r.Notes = append(r.Notes, err.Error())
		}
	default:
		r.TransactionID = uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		opts, err := decodeOptions(b[4:])
		r.Options = opts
		if err != nil {
			r.Notes = append(r.Notes, err.Error())
		}
	}
	return r, nil
}

func decodeOptions(b []byte) ([]Option, error) {
	var out []Option
	off := 0
	for off+4 <= len(b) {
		code := int(binary.BigEndian.Uint16(b[off : off+2]))
		ln := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		if off+4+ln > len(b) {
			return out, fmt.Errorf("option %d (length %d) truncates packet at offset %d",
				code, ln, off)
		}
		v := b[off+4 : off+4+ln]
		opt := Option{
			Code:     code,
			CodeName: optionCodeName(code),
			Length:   ln,
			ValueHex: strings.ToUpper(hex.EncodeToString(v)),
		}
		decodeOptionBody(&opt, v)
		out = append(out, opt)
		off += 4 + ln
	}
	return out, nil
}

func decodeOptionBody(opt *Option, v []byte) {
	switch opt.Code {
	case 1, 2:
		duid := decodeDUID(v)
		if opt.Code == 1 {
			opt.ClientID = duid
		} else {
			opt.ServerID = duid
		}
	case 3, 4, 25:
		ia := decodeIA(v)
		switch opt.Code {
		case 3:
			opt.IANonTemp = ia
		case 4:
			opt.IATemp = ia
		case 25:
			opt.IAPDelegate = ia
		}
	case 5:
		opt.IAAddress = decodeIAAddr(v)
	case 26:
		opt.IAPrefix = decodeIAPrefix(v)
	case 6:
		if len(v)%2 == 0 {
			for i := 0; i < len(v); i += 2 {
				opt.OptionRequest = append(opt.OptionRequest,
					int(binary.BigEndian.Uint16(v[i:i+2])))
			}
		}
	case 7:
		if len(v) >= 1 {
			p := int(v[0])
			opt.Preference = &p
		}
	case 8:
		if len(v) >= 2 {
			cs := int(binary.BigEndian.Uint16(v[0:2]))
			s := float64(cs) / 100
			opt.ElapsedTimeCs = &cs
			opt.ElapsedTimeS = &s
		}
	case 9:
		h := strings.ToUpper(hex.EncodeToString(v))
		opt.RelayMsgHex = &h
	case 12:
		if len(v) >= 16 {
			a := formatIPv6(v[0:16])
			opt.UnicastAddress = &a
		}
	case 13:
		if len(v) >= 2 {
			sc := &StatusCode{
				Code: int(binary.BigEndian.Uint16(v[0:2])),
			}
			sc.CodeName = statusCodeName(sc.Code)
			if len(v) > 2 && utf8.Valid(v[2:]) {
				sc.Message = string(v[2:])
			}
			opt.StatusCode = sc
		}
	case 16:
		opt.VendorClass = decodeVendorClass(v)
	case 23:
		opt.DNSServers = decodeIPv6List(v)
	case 56:
		opt.NTPServers = decodeIPv6List(v)
	case 24:
		// Domain search list — RFC 1035 wire format. For
		// simplicity surface as raw text (decoder for the
		// label-pointer form would duplicate dns_packet_decode).
	case 14, 20:
		// no body — flag-only.
	}
}

func decodeDUID(v []byte) *DUID {
	if len(v) < 2 {
		return nil
	}
	t := int(binary.BigEndian.Uint16(v[0:2]))
	d := &DUID{Type: t, TypeName: duidTypeName(t)}
	body := v[2:]
	switch t {
	case 1: // LLT
		if len(body) >= 6 {
			hw := int(binary.BigEndian.Uint16(body[0:2]))
			ts := int64(binary.BigEndian.Uint32(body[2:6]))
			d.HardwareType = &hw
			d.Time = &ts
			epoch := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(ts) * time.Second)
			d.TimeISO = epoch.Format(time.RFC3339)
			d.LinkLayerHex = strings.ToUpper(hex.EncodeToString(body[6:]))
		}
	case 2: // EN
		if len(body) >= 4 {
			en := binary.BigEndian.Uint32(body[0:4])
			d.EnterpriseNumber = &en
			d.IdentifierHex = strings.ToUpper(hex.EncodeToString(body[4:]))
		}
	case 3: // LL
		if len(body) >= 2 {
			hw := int(binary.BigEndian.Uint16(body[0:2]))
			d.HardwareType = &hw
			d.LinkLayerHex = strings.ToUpper(hex.EncodeToString(body[2:]))
		}
	case 4: // UUID
		if len(body) >= 16 {
			d.UUIDHex = strings.ToUpper(hex.EncodeToString(body[0:16]))
		}
	}
	return d
}

func decodeIA(v []byte) *IABody {
	if len(v) < 12 {
		return nil
	}
	ia := &IABody{
		IAID:      binary.BigEndian.Uint32(v[0:4]),
		T1Seconds: binary.BigEndian.Uint32(v[4:8]),
		T2Seconds: binary.BigEndian.Uint32(v[8:12]),
	}
	if len(v) > 12 {
		sub, _ := decodeOptions(v[12:])
		ia.SubOptions = sub
	}
	return ia
}

func decodeIAAddr(v []byte) *IAAddrBody {
	if len(v) < 24 {
		return nil
	}
	a := &IAAddrBody{
		Address:              formatIPv6(v[0:16]),
		PreferredLifetimeSec: binary.BigEndian.Uint32(v[16:20]),
		ValidLifetimeSec:     binary.BigEndian.Uint32(v[20:24]),
	}
	if len(v) > 24 {
		sub, _ := decodeOptions(v[24:])
		a.SubOptions = sub
	}
	return a
}

func decodeIAPrefix(v []byte) *IAPrefixBody {
	if len(v) < 25 {
		return nil
	}
	p := &IAPrefixBody{
		PreferredLifetimeSec: binary.BigEndian.Uint32(v[0:4]),
		ValidLifetimeSec:     binary.BigEndian.Uint32(v[4:8]),
		PrefixLength:         int(v[8]),
		Prefix:               formatIPv6(v[9:25]),
	}
	if len(v) > 25 {
		sub, _ := decodeOptions(v[25:])
		p.SubOptions = sub
	}
	return p
}

func decodeVendorClass(v []byte) *VendorClass {
	if len(v) < 4 {
		return nil
	}
	vc := &VendorClass{
		EnterpriseNumber: binary.BigEndian.Uint32(v[0:4]),
	}
	off := 4
	for off+2 <= len(v) {
		itemLen := int(binary.BigEndian.Uint16(v[off : off+2]))
		off += 2
		if off+itemLen > len(v) {
			vc.RemainderHex = strings.ToUpper(hex.EncodeToString(v[off-2:]))
			break
		}
		item := v[off : off+itemLen]
		if utf8.Valid(item) {
			vc.Items = append(vc.Items, string(item))
		} else {
			vc.Items = append(vc.Items, strings.ToUpper(hex.EncodeToString(item)))
		}
		off += itemLen
	}
	return vc
}

func decodeIPv6List(v []byte) []string {
	if len(v)%16 != 0 {
		return nil
	}
	var out []string
	for i := 0; i < len(v); i += 16 {
		out = append(out, formatIPv6(v[i:i+16]))
	}
	return out
}

func messageTypeName(t int) string {
	switch t {
	case 1:
		return "SOLICIT"
	case 2:
		return "ADVERTISE"
	case 3:
		return "REQUEST"
	case 4:
		return "CONFIRM"
	case 5:
		return "RENEW"
	case 6:
		return "REBIND"
	case 7:
		return "REPLY"
	case 8:
		return "RELEASE"
	case 9:
		return "DECLINE"
	case 10:
		return "RECONFIGURE"
	case 11:
		return "INFORMATION-REQUEST"
	case 12:
		return "RELAY-FORW"
	case 13:
		return "RELAY-REPL"
	}
	return fmt.Sprintf("uncatalogued message type %d", t)
}

func optionCodeName(c int) string {
	switch c {
	case 1:
		return "OPTION_CLIENTID"
	case 2:
		return "OPTION_SERVERID"
	case 3:
		return "OPTION_IA_NA"
	case 4:
		return "OPTION_IA_TA"
	case 5:
		return "OPTION_IAADDR"
	case 6:
		return "OPTION_ORO"
	case 7:
		return "OPTION_PREFERENCE"
	case 8:
		return "OPTION_ELAPSED_TIME"
	case 9:
		return "OPTION_RELAY_MSG"
	case 11:
		return "OPTION_AUTH"
	case 12:
		return "OPTION_UNICAST"
	case 13:
		return "OPTION_STATUS_CODE"
	case 14:
		return "OPTION_RAPID_COMMIT"
	case 15:
		return "OPTION_USER_CLASS"
	case 16:
		return "OPTION_VENDOR_CLASS"
	case 17:
		return "OPTION_VENDOR_OPTS"
	case 18:
		return "OPTION_INTERFACE_ID"
	case 19:
		return "OPTION_RECONF_MSG"
	case 20:
		return "OPTION_RECONF_ACCEPT"
	case 23:
		return "OPTION_DNS_SERVERS"
	case 24:
		return "OPTION_DOMAIN_LIST"
	case 25:
		return "OPTION_IA_PD"
	case 26:
		return "OPTION_IAPREFIX"
	case 39:
		return "OPTION_CLIENT_FQDN"
	case 56:
		return "OPTION_NTP_SERVER"
	}
	return fmt.Sprintf("uncatalogued option %d", c)
}

func duidTypeName(t int) string {
	switch t {
	case 1:
		return "DUID-LLT (Link-Layer + Time)"
	case 2:
		return "DUID-EN (Enterprise)"
	case 3:
		return "DUID-LL (Link-Layer)"
	case 4:
		return "DUID-UUID"
	}
	return fmt.Sprintf("uncatalogued DUID type %d", t)
}

func statusCodeName(c int) string {
	switch c {
	case 0:
		return "Success"
	case 1:
		return "UnspecFail"
	case 2:
		return "NoAddrsAvail"
	case 3:
		return "NoBinding"
	case 4:
		return "NotOnLink"
	case 5:
		return "UseMulticast"
	case 6:
		return "NoPrefixAvail"
	}
	return fmt.Sprintf("uncatalogued status %d", c)
}

func formatIPv6(b []byte) string {
	if len(b) != 16 {
		return strings.ToUpper(hex.EncodeToString(b))
	}
	return net.IP(b).String()
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
