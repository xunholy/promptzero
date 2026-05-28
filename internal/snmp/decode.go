// SPDX-License-Identifier: AGPL-3.0-or-later

// Package snmp decodes SNMP v1, v2c, and v3 packets — the
// dominant network-management protocol on enterprise networks,
// found on every router / switch / firewall / printer / UPS /
// PDU / managed AP / managed VM-host since the late '80s.
//
// # Wrap-vs-native judgement
//
// Native. SNMP is defined by RFC 1157 (v1), RFC 1905 / 3416
// (v2c PDU formats), and RFC 3411-3418 (v3 framework + USM
// + VACM). Every packet is ASN.1 BER-encoded with a small,
// well-bounded set of types (INTEGER, OCTET STRING, NULL,
// OBJECT IDENTIFIER, IpAddress, Counter32, Gauge32, TimeTicks,
// Counter64, plus the constructed SEQUENCE and the SNMP-
// specific PDU tags 0xA0..0xA8). A hand-rolled BER walker is
// ~200 lines and avoids dragging in encoding/asn1's stricter
// DER expectations. Pasting a hex blob from Wireshark /
// tshark / a tcpdump-of-161/162 / a community-string scan
// tool is enough — no SNMP agent, no MIB compilation.
//
// # What this package covers
//
//   - SNMP envelope decode: outer SEQUENCE, version (v1=0,
//     v2c=1, v3=3), community string (v1/v2c) or msgGlobalData
//   - msgSecurityParameters (v3, labeled with raw payload).
//   - PDU dispatch with the 9 documented PDU types:
//   - 0xA0 GetRequest
//   - 0xA1 GetNextRequest
//   - 0xA2 Response (a.k.a. GetResponse in v1 parlance)
//   - 0xA3 SetRequest
//   - 0xA4 Trap-PDU (SNMPv1 only — different shape from
//     v2c traps)
//   - 0xA5 GetBulkRequest (v2c+)
//   - 0xA6 InformRequest (v2c+)
//   - 0xA7 SNMPv2-Trap (v2c+)
//   - 0xA8 Report (v3)
//   - PDU body fields: request-id, error-status (named
//     NoError / TooBig / NoSuchName / BadValue / ReadOnly /
//     GenErr / NoAccess / WrongType / WrongLength /
//     WrongEncoding / WrongValue / NoCreation /
//     InconsistentValue / ResourceUnavailable /
//     CommitFailed / UndoFailed / AuthorizationError /
//     NotWritable / InconsistentName), error-index.
//   - GetBulkRequest non-repeaters + max-repetitions
//     (different from error-status / error-index).
//   - SNMPv1 Trap PDU: enterprise OID, agent-addr (IP),
//     generic-trap (named: ColdStart / WarmStart / LinkDown /
//     LinkUp / AuthenticationFailure / EGPNeighborLoss /
//     enterpriseSpecific), specific-trap, time-stamp.
//   - VarBindList walker: OID + tagged value where the value
//     is one of NULL (no-such-instance / pending / etc.),
//     INTEGER, OCTET STRING (rendered as ASCII if printable
//     else hex), OID, IpAddress (4-byte IPv4), Counter32,
//     Gauge32, TimeTicks (centiseconds, rendered as a
//     duration string), Counter64, noSuchObject,
//     noSuchInstance, endOfMibView.
//   - OID decoding: first byte = 40 * arc1 + arc2 (special-
//     cased per X.690 §8.19), subsequent arcs as base-128
//     with high bit = continuation.
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - SNMPv3 USM authentication (HMAC-MD5 / HMAC-SHA-*) and
//     privacy (DES-CBC / AES-128 / AES-256 / 3DES) — these
//     require the agent's auth/priv keys; the v3 envelope is
//     decoded but the encrypted scopedPDU body is surfaced
//     as raw hex.
//   - VACM (View-based Access Control Model) — runtime
//     authorization decision; not relevant to packet decode.
//   - MIB compilation / OID-to-name lookup beyond the well-
//     known OIDs (sysDescr, sysObjectID, sysUpTime, etc.) —
//     full MIB compilation is a separate ~1500-line effort.
//   - SNMP over TLS / DTLS / SSH transport — operators feed
//     the inner SNMP message after stripping the transport.
//   - AgentX (RFC 2741) — separate protocol, separate spec.
package snmp

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"unicode"
)

// Packet is the decoded SNMP message view.
type Packet struct {
	HexInput   string      `json:"hex_input"`
	Version    int         `json:"version"`
	VersionStr string      `json:"version_str"`
	Community  string      `json:"community,omitempty"`
	V3Header   *V3Header   `json:"v3_header,omitempty"`
	V3RawBody  string      `json:"v3_raw_body_hex,omitempty"`
	PDU        *PDU        `json:"pdu,omitempty"`
	TrapV1     *TrapV1Body `json:"trap_v1,omitempty"`
}

// V3Header is the SNMPv3 envelope before the encrypted/
// scoped PDU body.
type V3Header struct {
	MsgIDHex          string `json:"msg_id_hex"`
	MaxSizeHex        string `json:"max_size_hex"`
	FlagsHex          string `json:"flags_hex"`
	FlagAuth          bool   `json:"flag_auth"`
	FlagPriv          bool   `json:"flag_priv"`
	FlagReportable    bool   `json:"flag_reportable"`
	SecurityModel     int    `json:"security_model"`
	SecurityParamsHex string `json:"security_params_hex"`
}

// PDU is the decoded PDU body (for v1/v2c GetRequest /
// GetNextRequest / Response / SetRequest / GetBulkRequest /
// InformRequest / TrapV2 / Report). Trap-PDU (v1, tag 0xA4)
// uses TrapV1Body instead.
type PDU struct {
	Tag             int       `json:"tag"`
	TypeName        string    `json:"type_name"`
	RequestID       int       `json:"request_id"`
	ErrorStatus     int       `json:"error_status,omitempty"`
	ErrorStatusName string    `json:"error_status_name,omitempty"`
	ErrorIndex      int       `json:"error_index,omitempty"`
	NonRepeaters    int       `json:"non_repeaters,omitempty"`
	MaxRepetitions  int       `json:"max_repetitions,omitempty"`
	VarBinds        []VarBind `json:"var_binds,omitempty"`
}

// TrapV1Body is the SNMPv1 Trap-PDU (tag 0xA4) — a different
// shape from every other PDU.
type TrapV1Body struct {
	EnterpriseOID   string    `json:"enterprise_oid"`
	AgentAddrIPv4   string    `json:"agent_address_ipv4"`
	GenericTrap     int       `json:"generic_trap"`
	GenericTrapName string    `json:"generic_trap_name"`
	SpecificTrap    int       `json:"specific_trap"`
	TimestampTicks  uint64    `json:"timestamp_ticks"`
	VarBinds        []VarBind `json:"var_binds,omitempty"`
}

// VarBind is one (OID, value) pair from a VarBindList.
type VarBind struct {
	OID         string          `json:"oid"`
	OIDName     string          `json:"oid_name,omitempty"`
	ValueTag    int             `json:"value_tag"`
	ValueType   string          `json:"value_type"`
	StringValue string          `json:"string_value,omitempty"`
	IntValue    int64           `json:"int_value,omitempty"`
	UintValue   uint64          `json:"uint_value,omitempty"`
	OIDValue    string          `json:"oid_value,omitempty"`
	IPValue     string          `json:"ip_value,omitempty"`
	TimeTicks   *TimeTicksValue `json:"time_ticks,omitempty"`
	RawHex      string          `json:"raw_hex,omitempty"`
}

// TimeTicksValue is the centisecond-resolution duration used
// by SNMP timeticks values (RFC 1155 §6).
type TimeTicksValue struct {
	Centiseconds uint32 `json:"centiseconds"`
	Pretty       string `json:"pretty"`
}

// Decode parses a hex-encoded SNMP packet.
func Decode(hexBlob string) (*Packet, error) {
	b, err := parseHex(hexBlob)
	if err != nil {
		return nil, err
	}
	return DecodeBytes(b)
}

// DecodeBytes parses a raw SNMP packet.
func DecodeBytes(b []byte) (*Packet, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("snmp: input too short (%d bytes)", len(b))
	}
	p := &Packet{HexInput: strings.ToUpper(hex.EncodeToString(b))}
	// Outer wrapper: SEQUENCE.
	tag, val, _, err := readTLV(b, 0)
	if err != nil {
		return nil, fmt.Errorf("snmp: outer SEQUENCE: %w", err)
	}
	if tag != 0x30 {
		return nil, fmt.Errorf("snmp: outer tag 0x%02X is not SEQUENCE (0x30)", tag)
	}
	// Inside the SEQUENCE: version, community/v3-stuff, PDU.
	off := 0
	versionTag, versionVal, used, err := readTLV(val, off)
	if err != nil {
		return nil, fmt.Errorf("snmp: version: %w", err)
	}
	if versionTag != 0x02 {
		return nil, fmt.Errorf("snmp: version tag 0x%02X is not INTEGER", versionTag)
	}
	v, err := decodeInt(versionVal)
	if err != nil {
		return nil, fmt.Errorf("snmp: version: %w", err)
	}
	p.Version = int(v)
	p.VersionStr = versionName(p.Version)
	off += used
	if p.Version == 3 {
		if err := decodeV3(p, val, off); err != nil {
			return nil, fmt.Errorf("snmp: v3: %w", err)
		}
		return p, nil
	}
	// v1 / v2c: community + PDU.
	commTag, commVal, used, err := readTLV(val, off)
	if err != nil {
		return nil, fmt.Errorf("snmp: community: %w", err)
	}
	if commTag != 0x04 {
		return nil, fmt.Errorf("snmp: community tag 0x%02X is not OCTET STRING", commTag)
	}
	p.Community = string(commVal)
	off += used
	pduTag, pduVal, _, err := readTLV(val, off)
	if err != nil {
		return nil, fmt.Errorf("snmp: PDU: %w", err)
	}
	if pduTag == 0xA4 {
		body, err := decodeTrapV1(pduVal)
		if err != nil {
			return nil, err
		}
		p.TrapV1 = body
	} else {
		pdu, err := decodePDU(pduTag, pduVal)
		if err != nil {
			return nil, err
		}
		p.PDU = pdu
	}
	return p, nil
}

func decodeV3(p *Packet, b []byte, off int) error {
	// SNMPv3 envelope:
	//   msgGlobalData SEQUENCE {msgID, msgMaxSize, msgFlags, msgSecurityModel}
	//   msgSecurityParameters OCTET STRING
	//   msgData (either scopedPDU plaintext or encrypted)
	hdrTag, hdrVal, used, err := readTLV(b, off)
	if err != nil {
		return fmt.Errorf("msgGlobalData: %w", err)
	}
	if hdrTag != 0x30 {
		return fmt.Errorf("msgGlobalData tag 0x%02X is not SEQUENCE", hdrTag)
	}
	hdr, err := decodeV3Header(hdrVal)
	if err != nil {
		return err
	}
	p.V3Header = hdr
	off += used
	// msgSecurityParameters
	spTag, spVal, used, err := readTLV(b, off)
	if err != nil {
		return fmt.Errorf("msgSecurityParameters: %w", err)
	}
	if spTag != 0x04 {
		return fmt.Errorf("msgSecurityParameters tag 0x%02X is not OCTET STRING", spTag)
	}
	hdr.SecurityParamsHex = strings.ToUpper(hex.EncodeToString(spVal))
	off += used
	// msgData — could be plaintext SEQUENCE or encrypted
	// OCTET STRING. Surface raw for now.
	if off < len(b) {
		p.V3RawBody = strings.ToUpper(hex.EncodeToString(b[off:]))
	}
	return nil
}

func decodeV3Header(b []byte) (*V3Header, error) {
	h := &V3Header{}
	off := 0
	fields := [4]string{"msgID", "msgMaxSize", "msgFlags", "msgSecurityModel"}
	for i := 0; i < 4; i++ {
		t, v, used, err := readTLV(b, off)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", fields[i], err)
		}
		switch i {
		case 0:
			h.MsgIDHex = strings.ToUpper(hex.EncodeToString(v))
		case 1:
			h.MaxSizeHex = strings.ToUpper(hex.EncodeToString(v))
		case 2:
			h.FlagsHex = strings.ToUpper(hex.EncodeToString(v))
			if len(v) > 0 {
				h.FlagAuth = v[0]&0x01 != 0
				h.FlagPriv = v[0]&0x02 != 0
				h.FlagReportable = v[0]&0x04 != 0
			}
		case 3:
			n, err := decodeInt(v)
			if err == nil {
				h.SecurityModel = int(n)
			}
		}
		_ = t
		off += used
	}
	return h, nil
}

func decodePDU(tag int, b []byte) (*PDU, error) {
	pdu := &PDU{Tag: tag, TypeName: pduTypeName(tag)}
	off := 0
	// request-id
	t, v, used, err := readTLV(b, off)
	if err != nil {
		return nil, fmt.Errorf("request-id: %w", err)
	}
	if t != 0x02 {
		return nil, fmt.Errorf("request-id tag 0x%02X is not INTEGER", t)
	}
	rid, err := decodeInt(v)
	if err != nil {
		return nil, err
	}
	pdu.RequestID = int(rid)
	off += used
	// error-status / non-repeaters
	_, v, used, err = readTLV(b, off)
	if err != nil {
		return nil, fmt.Errorf("error-status: %w", err)
	}
	n, err := decodeInt(v)
	if err != nil {
		return nil, err
	}
	if tag == 0xA5 {
		pdu.NonRepeaters = int(n)
	} else {
		pdu.ErrorStatus = int(n)
		pdu.ErrorStatusName = errorStatusName(pdu.ErrorStatus)
	}
	off += used
	// error-index / max-repetitions
	_, v, used, err = readTLV(b, off)
	if err != nil {
		return nil, fmt.Errorf("error-index: %w", err)
	}
	n, err = decodeInt(v)
	if err != nil {
		return nil, err
	}
	if tag == 0xA5 {
		pdu.MaxRepetitions = int(n)
	} else {
		pdu.ErrorIndex = int(n)
	}
	off += used
	// variable-bindings SEQUENCE OF
	vbTag, vbVal, _, err := readTLV(b, off)
	if err != nil {
		return nil, fmt.Errorf("var-binds: %w", err)
	}
	if vbTag != 0x30 {
		return nil, fmt.Errorf("var-binds tag 0x%02X is not SEQUENCE", vbTag)
	}
	vbs, err := decodeVarBindList(vbVal)
	if err != nil {
		return nil, err
	}
	pdu.VarBinds = vbs
	return pdu, nil
}

func decodeTrapV1(b []byte) (*TrapV1Body, error) {
	body := &TrapV1Body{}
	off := 0
	// enterprise OID
	t, v, used, err := readTLV(b, off)
	if err != nil {
		return nil, fmt.Errorf("enterprise: %w", err)
	}
	if t != 0x06 {
		return nil, fmt.Errorf("enterprise tag 0x%02X is not OID", t)
	}
	body.EnterpriseOID = decodeOID(v)
	off += used
	// agent-addr (IpAddress, tag 0x40)
	_, v, used, err = readTLV(b, off)
	if err != nil {
		return nil, fmt.Errorf("agent-addr: %w", err)
	}
	if len(v) == 4 {
		body.AgentAddrIPv4 = net.IP(v).String()
	}
	off += used
	// generic-trap INTEGER
	_, v, used, err = readTLV(b, off)
	if err != nil {
		return nil, err
	}
	g, err := decodeInt(v)
	if err == nil {
		body.GenericTrap = int(g)
		body.GenericTrapName = genericTrapName(body.GenericTrap)
	}
	off += used
	// specific-trap INTEGER
	_, v, used, err = readTLV(b, off)
	if err != nil {
		return nil, err
	}
	s, err := decodeInt(v)
	if err == nil {
		body.SpecificTrap = int(s)
	}
	off += used
	// time-stamp TimeTicks
	_, v, used, err = readTLV(b, off)
	if err != nil {
		return nil, err
	}
	body.TimestampTicks = decodeUint(v)
	off += used
	// variable-bindings
	vbTag, vbVal, _, err := readTLV(b, off)
	if err != nil {
		return nil, err
	}
	if vbTag == 0x30 {
		vbs, err := decodeVarBindList(vbVal)
		if err == nil {
			body.VarBinds = vbs
		}
	}
	return body, nil
}

func decodeVarBindList(b []byte) ([]VarBind, error) {
	var out []VarBind
	off := 0
	for off < len(b) {
		t, v, used, err := readTLV(b, off)
		if err != nil {
			return nil, fmt.Errorf("var-bind: %w", err)
		}
		if t != 0x30 {
			return nil, fmt.Errorf("var-bind tag 0x%02X is not SEQUENCE", t)
		}
		vb, err := decodeVarBind(v)
		if err != nil {
			return nil, err
		}
		out = append(out, vb)
		off += used
	}
	return out, nil
}

func decodeVarBind(b []byte) (VarBind, error) {
	var vb VarBind
	// Name OID
	t, v, used, err := readTLV(b, 0)
	if err != nil {
		return vb, fmt.Errorf("name: %w", err)
	}
	if t != 0x06 {
		return vb, fmt.Errorf("name tag 0x%02X is not OID", t)
	}
	vb.OID = decodeOID(v)
	vb.OIDName = wellKnownOIDName(vb.OID)
	// Value (tagged)
	vt, vv, _, err := readTLV(b, used)
	if err != nil {
		return vb, fmt.Errorf("value: %w", err)
	}
	vb.ValueTag = vt
	vb.ValueType = valueTypeName(vt)
	switch vt {
	case 0x02: // INTEGER
		n, _ := decodeInt(vv)
		vb.IntValue = n
	case 0x04: // OCTET STRING
		vb.StringValue = renderOctetString(vv)
		vb.RawHex = strings.ToUpper(hex.EncodeToString(vv))
	case 0x05: // NULL
		// no value
	case 0x06: // OID
		vb.OIDValue = decodeOID(vv)
	case 0x40: // IpAddress
		if len(vv) == 4 {
			vb.IPValue = net.IP(vv).String()
		}
	case 0x41, 0x42: // Counter32, Gauge32
		vb.UintValue = decodeUint(vv)
	case 0x43: // TimeTicks
		ts := uint32(decodeUint(vv))
		vb.TimeTicks = &TimeTicksValue{
			Centiseconds: ts,
			Pretty:       timeTicksPretty(ts),
		}
	case 0x46: // Counter64
		vb.UintValue = decodeUint(vv)
	case 0x80, 0x81, 0x82: // noSuchObject / noSuchInstance / endOfMibView
		// type name is enough
	default:
		vb.RawHex = strings.ToUpper(hex.EncodeToString(vv))
	}
	return vb, nil
}

// readTLV parses one BER TLV starting at off and returns
// (tag, value-bytes, total-bytes-consumed, error). Only
// definite-length encoding is supported (SNMP doesn't use
// indefinite length).
func readTLV(b []byte, off int) (int, []byte, int, error) {
	if off >= len(b) {
		return 0, nil, 0, fmt.Errorf("offset %d past buffer (len %d)", off, len(b))
	}
	tag := int(b[off])
	idx := off + 1
	if idx >= len(b) {
		return 0, nil, 0, fmt.Errorf("length byte missing")
	}
	first := b[idx]
	idx++
	var length int
	if first&0x80 == 0 {
		length = int(first)
	} else {
		nb := int(first & 0x7F)
		if nb == 0 {
			return 0, nil, 0, fmt.Errorf("indefinite length not supported in SNMP")
		}
		// A length field wider than 4 bytes (>4 GiB) cannot describe a
		// real SNMP PDU and, more importantly, accumulating 5+ bytes
		// into an int overflows it to a negative value — which would
		// slip past the bounds check below and produce an inverted
		// slice b[idx:idx+length] (start > end) panic. Reject early.
		if nb > 4 {
			return 0, nil, 0, fmt.Errorf("length field too wide (%d bytes)", nb)
		}
		if idx+nb > len(b) {
			return 0, nil, 0, fmt.Errorf("long-form length bytes truncated")
		}
		for i := 0; i < nb; i++ {
			length = length<<8 | int(b[idx+i])
		}
		idx += nb
	}
	if length < 0 || idx+length > len(b) {
		return 0, nil, 0, fmt.Errorf("value (length %d) exceeds buffer", length)
	}
	return tag, b[idx : idx+length], idx + length - off, nil
}

// decodeInt parses a BER INTEGER body as signed int64.
func decodeInt(b []byte) (int64, error) {
	if len(b) == 0 {
		return 0, fmt.Errorf("empty integer")
	}
	if len(b) > 8 {
		return 0, fmt.Errorf("integer wider than int64")
	}
	v := int64(0)
	if b[0]&0x80 != 0 {
		// Sign-extend
		v = -1
	}
	for _, x := range b {
		v = (v << 8) | int64(x)
	}
	return v, nil
}

// decodeUint parses an unsigned integer (used for Counter32 /
// Gauge32 / Counter64 / TimeTicks).
func decodeUint(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = (v << 8) | uint64(x)
	}
	return v
}

// decodeOID parses a BER OID body into a dot-separated string
// per X.690 §8.19. First sub-identifier is 40*X+Y; subsequent
// arcs use base-128 with high bit = continuation.
func decodeOID(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	first := int(b[0])
	arc1 := first / 40
	arc2 := first % 40
	if arc1 > 2 {
		arc1 = 2
		arc2 = first - 80
	}
	out := []string{fmt.Sprintf("%d", arc1), fmt.Sprintf("%d", arc2)}
	var v uint64
	for i := 1; i < len(b); i++ {
		v = (v << 7) | uint64(b[i]&0x7F)
		if b[i]&0x80 == 0 {
			out = append(out, fmt.Sprintf("%d", v))
			v = 0
		}
	}
	return strings.Join(out, ".")
}

// renderOctetString returns the value as a printable string
// if all bytes are printable ASCII, otherwise as a hex string.
func renderOctetString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	for _, c := range b {
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			return "0x" + strings.ToUpper(hex.EncodeToString(b))
		}
		if c > 0x7E {
			return "0x" + strings.ToUpper(hex.EncodeToString(b))
		}
		if !unicode.IsPrint(rune(c)) && c != ' ' {
			return "0x" + strings.ToUpper(hex.EncodeToString(b))
		}
	}
	return string(b)
}

func timeTicksPretty(t uint32) string {
	// TimeTicks are centiseconds. Render as Dd HHh MMm SSs ccc.
	totalSec := t / 100
	days := totalSec / 86400
	hours := (totalSec % 86400) / 3600
	mins := (totalSec % 3600) / 60
	secs := totalSec % 60
	cs := t % 100
	if days > 0 {
		return fmt.Sprintf("%dd %02dh %02dm %02d.%02ds", days, hours, mins, secs, cs)
	}
	return fmt.Sprintf("%02dh %02dm %02d.%02ds", hours, mins, secs, cs)
}

func versionName(v int) string {
	switch v {
	case 0:
		return "SNMPv1"
	case 1:
		return "SNMPv2c"
	case 2:
		return "SNMPv2u (historical)"
	case 3:
		return "SNMPv3"
	}
	return fmt.Sprintf("Unknown (version %d)", v)
}

func pduTypeName(tag int) string {
	switch tag {
	case 0xA0:
		return "GetRequest"
	case 0xA1:
		return "GetNextRequest"
	case 0xA2:
		return "Response"
	case 0xA3:
		return "SetRequest"
	case 0xA4:
		return "Trap-PDU (SNMPv1)"
	case 0xA5:
		return "GetBulkRequest"
	case 0xA6:
		return "InformRequest"
	case 0xA7:
		return "SNMPv2-Trap"
	case 0xA8:
		return "Report"
	}
	return fmt.Sprintf("Unknown PDU (0x%02X)", tag)
}

func errorStatusName(e int) string {
	switch e {
	case 0:
		return "noError"
	case 1:
		return "tooBig"
	case 2:
		return "noSuchName"
	case 3:
		return "badValue"
	case 4:
		return "readOnly"
	case 5:
		return "genErr"
	case 6:
		return "noAccess"
	case 7:
		return "wrongType"
	case 8:
		return "wrongLength"
	case 9:
		return "wrongEncoding"
	case 10:
		return "wrongValue"
	case 11:
		return "noCreation"
	case 12:
		return "inconsistentValue"
	case 13:
		return "resourceUnavailable"
	case 14:
		return "commitFailed"
	case 15:
		return "undoFailed"
	case 16:
		return "authorizationError"
	case 17:
		return "notWritable"
	case 18:
		return "inconsistentName"
	}
	return fmt.Sprintf("error %d", e)
}

func genericTrapName(g int) string {
	switch g {
	case 0:
		return "coldStart"
	case 1:
		return "warmStart"
	case 2:
		return "linkDown"
	case 3:
		return "linkUp"
	case 4:
		return "authenticationFailure"
	case 5:
		return "egpNeighborLoss"
	case 6:
		return "enterpriseSpecific"
	}
	return fmt.Sprintf("generic %d", g)
}

func valueTypeName(t int) string {
	switch t {
	case 0x02:
		return "INTEGER"
	case 0x04:
		return "OCTET STRING"
	case 0x05:
		return "NULL"
	case 0x06:
		return "OBJECT IDENTIFIER"
	case 0x40:
		return "IpAddress"
	case 0x41:
		return "Counter32"
	case 0x42:
		return "Gauge32 / Unsigned32"
	case 0x43:
		return "TimeTicks"
	case 0x44:
		return "Opaque"
	case 0x46:
		return "Counter64"
	case 0x80:
		return "noSuchObject"
	case 0x81:
		return "noSuchInstance"
	case 0x82:
		return "endOfMibView"
	}
	return fmt.Sprintf("Unknown (0x%02X)", t)
}

// wellKnownOIDName labels the most-quoted SNMP OIDs that
// every operator recognises. Full MIB compilation is out of
// scope for this Spec; the table covers the ~25 OIDs that
// account for >90% of real-world SNMP traffic.
func wellKnownOIDName(oid string) string {
	switch oid {
	case "1.3.6.1.2.1.1.1.0":
		return "sysDescr.0"
	case "1.3.6.1.2.1.1.2.0":
		return "sysObjectID.0"
	case "1.3.6.1.2.1.1.3.0":
		return "sysUpTime.0"
	case "1.3.6.1.2.1.1.4.0":
		return "sysContact.0"
	case "1.3.6.1.2.1.1.5.0":
		return "sysName.0"
	case "1.3.6.1.2.1.1.6.0":
		return "sysLocation.0"
	case "1.3.6.1.2.1.1.7.0":
		return "sysServices.0"
	case "1.3.6.1.2.1.2.1.0":
		return "ifNumber.0"
	case "1.3.6.1.2.1.2.2.1.1":
		return "ifIndex"
	case "1.3.6.1.2.1.2.2.1.2":
		return "ifDescr"
	case "1.3.6.1.2.1.2.2.1.3":
		return "ifType"
	case "1.3.6.1.2.1.2.2.1.5":
		return "ifSpeed"
	case "1.3.6.1.2.1.2.2.1.6":
		return "ifPhysAddress"
	case "1.3.6.1.2.1.2.2.1.7":
		return "ifAdminStatus"
	case "1.3.6.1.2.1.2.2.1.8":
		return "ifOperStatus"
	case "1.3.6.1.2.1.2.2.1.10":
		return "ifInOctets"
	case "1.3.6.1.2.1.2.2.1.16":
		return "ifOutOctets"
	case "1.3.6.1.6.3.1.1.4.1.0":
		return "snmpTrapOID.0"
	case "1.3.6.1.6.3.1.1.5.1":
		return "coldStart"
	case "1.3.6.1.6.3.1.1.5.2":
		return "warmStart"
	case "1.3.6.1.6.3.1.1.5.3":
		return "linkDown"
	case "1.3.6.1.6.3.1.1.5.4":
		return "linkUp"
	case "1.3.6.1.6.3.1.1.5.5":
		return "authenticationFailure"
	}
	return ""
}

func parseHex(s string) ([]byte, error) {
	s = stripSeparators(s)
	if s == "" {
		return nil, fmt.Errorf("snmp: empty hex input")
	}
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("snmp: invalid hex: %w", err)
	}
	return b, nil
}

func stripSeparators(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
