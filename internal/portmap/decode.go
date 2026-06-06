// SPDX-License-Identifier: AGPL-3.0-or-later

// Package portmap decodes ONC RPC (RFC 5531) portmapper / rpcbind v2
// messages (program 100000, UDP/TCP 111) — the classic Sun-RPC service
// directory. Enumerating it is a textbook LAN-reconnaissance step (the
// `rpcinfo -p` technique): the **DUMP reply** lists every RPC program a
// host has registered — NFS, mountd, NIS/yp, nlockmgr, status — with the
// program number, version, transport and **port**, mapping out the host's
// RPC attack surface; a **GETPORT call** reveals which specific service a
// client is locating. This is the RPC-enumeration complement to the
// project's other service-recon decoders.
//
// # Wrap-vs-native judgement
//
//	Native. An ONC RPC message is a fixed header (xid, message type) plus
//	a call or reply body of 32-bit XDR fields (with variable-length
//	auth/verifier blobs), and the portmap procedures are short 32-bit
//	field lists. A byte-field read + a couple of bounded walks; stdlib
//	only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The RPC call/reply header, the GETPORT call/reply and the DUMP reply
//	mapping list were verified field-for-field against scapy's ONC RPC +
//	portmap layers (scapy.contrib.oncrpc / portmap). Because an RPC reply
//	does not carry the program/procedure it answers (the client
//	correlates by xid), a reply body is typed by structure, not guessed:
//	a DUMP mapping list is reported only when it parses exhaustively to a
//	clean value-follows terminator with sane transports, and a bare
//	4-byte accepted reply as a GETPORT port; anything else is surfaced as
//	raw hex.
package portmap

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Mapping is one registered RPC service from a DUMP reply.
type Mapping struct {
	Program     uint32 `json:"program"`
	ProgramName string `json:"program_name,omitempty"`
	Version     uint32 `json:"version"`
	Protocol    uint32 `json:"protocol"`
	ProtocolStr string `json:"protocol_str"`
	Port        uint32 `json:"port"`
}

// Result is the decoded view of a portmapper RPC message.
type Result struct {
	XID         string `json:"xid"`
	MessageType int    `json:"message_type"`
	MessageName string `json:"message_name"`

	// Call (message type 0).
	RPCVersion  *uint32 `json:"rpc_version,omitempty"`
	Program     *uint32 `json:"program,omitempty"`
	ProgramName string  `json:"program_name,omitempty"`
	ProgVersion *uint32 `json:"program_version,omitempty"`
	Procedure   *uint32 `json:"procedure,omitempty"`
	ProcName    string  `json:"procedure_name,omitempty"`
	AuthFlavor  *uint32 `json:"auth_flavor,omitempty"`

	// GETPORT call body.
	Query *Mapping `json:"getport_query,omitempty"`

	// Reply (message type 1).
	ReplyStat  *uint32 `json:"reply_stat,omitempty"`
	ReplyName  string  `json:"reply_stat_name,omitempty"`
	AcceptStat *uint32 `json:"accept_stat,omitempty"`
	AcceptName string  `json:"accept_stat_name,omitempty"`

	// GETPORT reply / DUMP reply (structurally inferred).
	Port     *uint32   `json:"getport_port,omitempty"`
	Mappings []Mapping `json:"mappings,omitempty"`

	BodyHex string   `json:"body_hex,omitempty"`
	Notes   []string `json:"notes,omitempty"`
}

const portmapProgram = 100000

// Decode parses an ONC RPC portmapper message (the UDP/TCP-111 payload,
// without any TCP record marker) from hex (whitespace / ':' / '-' / '_'
// separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 8 {
		return nil, fmt.Errorf("portmap: %d bytes — too short for an RPC header", len(b))
	}
	mtype := binary.BigEndian.Uint32(b[4:8])
	r := &Result{
		XID:         fmt.Sprintf("0x%08X", binary.BigEndian.Uint32(b[0:4])),
		MessageType: int(mtype),
		MessageName: msgTypeName(mtype),
	}
	switch mtype {
	case 0:
		return decodeCall(r, b[8:])
	case 1:
		return decodeReply(r, b[8:])
	default:
		return nil, fmt.Errorf("portmap: message type %d is not CALL (0) or REPLY (1)", mtype)
	}
}

func decodeCall(r *Result, b []byte) (*Result, error) {
	if len(b) < 24 {
		return nil, fmt.Errorf("portmap: CALL header truncated")
	}
	ver := binary.BigEndian.Uint32(b[0:4])
	prog := binary.BigEndian.Uint32(b[4:8])
	pver := binary.BigEndian.Uint32(b[8:12])
	proc := binary.BigEndian.Uint32(b[12:16])
	r.RPCVersion, r.Program, r.ProgVersion, r.Procedure = &ver, &prog, &pver, &proc
	r.ProgramName = programName(prog)
	if prog == portmapProgram {
		r.ProcName = portmapProcName(proc)
	}
	// Auth: aflavor(4) alength(4) [alength bytes] vflavor(4) vlength(4) [vlength bytes].
	off := 16
	aflavor := binary.BigEndian.Uint32(b[off : off+4])
	r.AuthFlavor = &aflavor
	alength := int(binary.BigEndian.Uint32(b[off+4 : off+8]))
	off += 8 + alength
	if off+8 > len(b) {
		r.Notes = append(r.Notes, "auth body overruns the captured bytes")
		return r, nil
	}
	vlength := int(binary.BigEndian.Uint32(b[off+4 : off+8]))
	off += 8 + vlength
	if off > len(b) {
		r.Notes = append(r.Notes, "verifier body overruns the captured bytes")
		return r, nil
	}
	args := b[off:]
	if prog == portmapProgram && proc == 3 && len(args) >= 16 { // GETPORT
		r.Query = &Mapping{
			Program:     binary.BigEndian.Uint32(args[0:4]),
			Version:     binary.BigEndian.Uint32(args[4:8]),
			Protocol:    binary.BigEndian.Uint32(args[8:12]),
			Port:        binary.BigEndian.Uint32(args[12:16]),
			ProgramName: programName(binary.BigEndian.Uint32(args[0:4])),
			ProtocolStr: protocolName(binary.BigEndian.Uint32(args[8:12])),
		}
		r.Notes = append(r.Notes, "GETPORT call: a client is locating the port of "+r.Query.ProgramName)
	} else if len(args) > 0 {
		r.BodyHex = hexUpper(args)
	}
	return r, nil
}

func decodeReply(r *Result, b []byte) (*Result, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("portmap: REPLY truncated")
	}
	rs := binary.BigEndian.Uint32(b[0:4])
	r.ReplyStat, r.ReplyName = &rs, replyStatName(rs)
	if rs != 0 { // DENIED — surface the rest raw
		r.BodyHex = hexUpper(b[4:])
		r.Notes = append(r.Notes, "RPC reply denied (auth or RPC-version mismatch)")
		return r, nil
	}
	// ACCEPTED: verf flavor(4) length(4) [length bytes] accept_stat(4).
	if len(b) < 12 {
		return nil, fmt.Errorf("portmap: accepted REPLY header truncated")
	}
	vlength := int(binary.BigEndian.Uint32(b[8:12]))
	off := 12 + vlength
	if off+4 > len(b) {
		r.Notes = append(r.Notes, "verifier body overruns the captured bytes")
		return r, nil
	}
	as := binary.BigEndian.Uint32(b[off : off+4])
	r.AcceptStat, r.AcceptName = &as, acceptStatName(as)
	off += 4
	body := b[off:]
	if as != 0 || len(body) == 0 { // not SUCCESS, or empty body
		if len(body) > 0 {
			r.BodyHex = hexUpper(body)
		}
		return r, nil
	}
	// The reply does not say which procedure it answers; type the body by
	// structure. A bare 4-byte accepted result is a GETPORT port (the common
	// case) — note that an all-zero 4-byte body is byte-identical to an empty
	// DUMP reply (no registrations), so the two cannot be distinguished here.
	// A longer body that parses exhaustively as a value-follows list is a
	// DUMP service enumeration (the recon headline).
	if len(body) == 4 {
		port := binary.BigEndian.Uint32(body)
		r.Port = &port
		note := "GETPORT reply: the located service port (inferred from a bare 4-byte accepted result)"
		if port == 0 {
			note += " — port 0 means the service is not registered (also byte-identical to an empty DUMP reply)"
		}
		r.Notes = append(r.Notes, note)
		return r, nil
	}
	if maps, ok := parseDumpList(body); ok {
		r.Mappings = maps
		r.Notes = append(r.Notes, fmt.Sprintf("DUMP reply: %d registered RPC services (rpcinfo-style enumeration) — inferred from the value-follows list structure", len(maps)))
		return r, nil
	}
	r.BodyHex = hexUpper(body)
	r.Notes = append(r.Notes, "accepted RPC result surfaced raw (the procedure is not identifiable from the reply alone)")
	return r, nil
}

// parseDumpList parses a portmap DUMP reply body (a leading value-follows
// boolean, then 20-byte entries each ending in a value-follows boolean)
// and returns the mappings only if it consumes the entire body exactly and
// every entry is structurally sane (a clean value-follows terminator and a
// known transport). The strict, exhaustive parse is the gate against
// mis-typing a non-DUMP reply.
func parseDumpList(b []byte) ([]Mapping, bool) {
	if len(b) < 4 {
		return nil, false
	}
	vf := binary.BigEndian.Uint32(b[0:4])
	off := 4
	if vf == 0 {
		return []Mapping{}, off == len(b) // an empty registration list
	}
	if vf != 1 {
		return nil, false
	}
	var maps []Mapping
	for {
		if off+20 > len(b) {
			return nil, false
		}
		prot := binary.BigEndian.Uint32(b[off+8 : off+12])
		if prot != 6 && prot != 17 {
			return nil, false // not TCP/UDP — not a real mapping
		}
		m := Mapping{
			Program:     binary.BigEndian.Uint32(b[off : off+4]),
			Version:     binary.BigEndian.Uint32(b[off+4 : off+8]),
			Protocol:    prot,
			Port:        binary.BigEndian.Uint32(b[off+12 : off+16]),
			ProtocolStr: protocolName(prot),
		}
		m.ProgramName = programName(m.Program)
		maps = append(maps, m)
		next := binary.BigEndian.Uint32(b[off+16 : off+20])
		off += 20
		switch next {
		case 0:
			return maps, off == len(b) // clean terminator consuming the whole body
		case 1:
			continue
		default:
			return nil, false
		}
	}
}

func msgTypeName(t uint32) string {
	switch t {
	case 0:
		return "CALL"
	case 1:
		return "REPLY"
	}
	return fmt.Sprintf("%d", t)
}

func replyStatName(s uint32) string {
	switch s {
	case 0:
		return "MSG_ACCEPTED"
	case 1:
		return "MSG_DENIED"
	}
	return fmt.Sprintf("%d", s)
}

func acceptStatName(s uint32) string {
	switch s {
	case 0:
		return "SUCCESS"
	case 1:
		return "PROG_UNAVAIL"
	case 2:
		return "PROG_MISMATCH"
	case 3:
		return "PROC_UNAVAIL"
	case 4:
		return "GARBAGE_ARGS"
	case 5:
		return "SYSTEM_ERR"
	}
	return fmt.Sprintf("%d", s)
}

func portmapProcName(p uint32) string {
	switch p {
	case 0:
		return "NULL"
	case 1:
		return "SET"
	case 2:
		return "UNSET"
	case 3:
		return "GETPORT"
	case 4:
		return "DUMP"
	case 5:
		return "CALLIT"
	}
	return fmt.Sprintf("%d", p)
}

func protocolName(p uint32) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	}
	return fmt.Sprintf("proto-%d", p)
}

// programName maps the well-known Sun-RPC program numbers — the recon
// payload: it turns a registered port into "NFS on 2049", "mountd", etc.
func programName(p uint32) string {
	switch p {
	case 100000:
		return "portmapper/rpcbind"
	case 100001:
		return "rstatd"
	case 100002:
		return "rusersd"
	case 100003:
		return "nfs"
	case 100004:
		return "ypserv (NIS)"
	case 100005:
		return "mountd"
	case 100007:
		return "ypbind"
	case 100009:
		return "yppasswdd"
	case 100011:
		return "rquotad"
	case 100021:
		return "nlockmgr (NFS lock)"
	case 100024:
		return "status (statd)"
	case 100068:
		return "cmsd"
	case 100083:
		return "ttdbserverd"
	case 100227:
		return "nfs_acl"
	case 100229:
		return "metad"
	case 100300:
		return "nisd"
	case 391002:
		return "sgi_fam"
	case 1073741824:
		return "amd"
	}
	return ""
}

func hexUpper(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("portmap: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("portmap: input is not valid hex: %w", err)
	}
	return b, nil
}
