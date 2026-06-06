// SPDX-License-Identifier: AGPL-3.0-or-later

// Package oncrpc parses the ONC RPC (Sun RPC, RFC 5531) message header
// shared by the project's RPC-protocol decoders — internal/portmap
// (rpcbind), internal/mount (NFS MOUNT) and internal/nfs (NFS v3). Each of
// those decodes the same call/reply framing (transaction id, message
// type, the call program/version/procedure + auth/verifier, or the reply
// accept status) before its procedure-specific body; this package owns
// that framing once so the protocol decoders only implement their own
// procedure bodies.
//
// # Wrap-vs-native judgement
//
//	Native. The RPC message header is a short sequence of 32-bit XDR
//	fields with two variable-length auth/verifier opaque blobs — a
//	byte-field read with bounds checks. stdlib only, no new go.mod dep.
//
// # Scope
//
//	The message header only: the transaction id, the call fields
//	(rpcvers / program / version / procedure / auth flavor, skipping the
//	auth + verifier opaque bodies) or the reply fields (reply status,
//	and for an accepted reply the accept status), and the byte offset of
//	the procedure-specific Body. The body itself is decoded by the
//	per-program packages. RPCSEC_GSS auth bodies are skipped by their
//	declared length like any other flavor.
package oncrpc

import (
	"encoding/binary"
	"fmt"
)

// Message is a parsed ONC RPC message header with the procedure-specific
// body isolated in Body.
type Message struct {
	XID  uint32
	Type uint32 // 0 = CALL, 1 = REPLY

	// CALL fields (valid when Type == 0).
	RPCVersion     uint32
	Program        uint32
	ProgramVersion uint32
	Procedure      uint32
	AuthFlavor     uint32

	// REPLY fields (valid when Type == 1).
	ReplyStat  uint32 // 0 = MSG_ACCEPTED, 1 = MSG_DENIED
	Accepted   bool
	AcceptStat uint32 // valid when Accepted

	// Body is the procedure arguments (CALL), the accepted result (REPLY,
	// after the accept status), or the reject info (a denied REPLY).
	Body []byte
}

// IsCall reports whether the message is an RPC CALL.
func (m *Message) IsCall() bool { return m.Type == 0 }

// IsReply reports whether the message is an RPC REPLY.
func (m *Message) IsReply() bool { return m.Type == 1 }

// Parse decodes the ONC RPC message header from b (the RPC payload without
// any TCP record marker) and isolates the procedure-specific body.
func Parse(b []byte) (*Message, error) {
	if len(b) < 8 {
		return nil, fmt.Errorf("oncrpc: %d bytes — too short for an RPC header", len(b))
	}
	m := &Message{
		XID:  binary.BigEndian.Uint32(b[0:4]),
		Type: binary.BigEndian.Uint32(b[4:8]),
	}
	switch m.Type {
	case 0:
		return parseCall(m, b[8:])
	case 1:
		return parseReply(m, b[8:])
	default:
		return nil, fmt.Errorf("oncrpc: message type %d is not CALL (0) or REPLY (1)", m.Type)
	}
}

func parseCall(m *Message, b []byte) (*Message, error) {
	if len(b) < 24 {
		return nil, fmt.Errorf("oncrpc: CALL header truncated")
	}
	m.RPCVersion = binary.BigEndian.Uint32(b[0:4])
	m.Program = binary.BigEndian.Uint32(b[4:8])
	m.ProgramVersion = binary.BigEndian.Uint32(b[8:12])
	m.Procedure = binary.BigEndian.Uint32(b[12:16])
	m.AuthFlavor = binary.BigEndian.Uint32(b[16:20])
	// Auth: flavor(4) length(4) [length bytes], then verifier: flavor(4)
	// length(4) [length bytes].
	off := 16
	alength := int(binary.BigEndian.Uint32(b[off+4 : off+8]))
	off += 8 + alength
	if off+8 > len(b) {
		return nil, fmt.Errorf("oncrpc: auth body overruns the RPC call header")
	}
	vlength := int(binary.BigEndian.Uint32(b[off+4 : off+8]))
	off += 8 + vlength
	if off > len(b) {
		return nil, fmt.Errorf("oncrpc: verifier body overruns the RPC call header")
	}
	m.Body = b[off:]
	return m, nil
}

func parseReply(m *Message, b []byte) (*Message, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("oncrpc: REPLY truncated")
	}
	m.ReplyStat = binary.BigEndian.Uint32(b[0:4])
	if m.ReplyStat != 0 { // MSG_DENIED — the rest is reject info.
		m.Body = b[4:]
		return m, nil
	}
	// MSG_ACCEPTED: verifier flavor(4) length(4) [length bytes], accept_stat(4).
	if len(b) < 12 {
		return nil, fmt.Errorf("oncrpc: accepted REPLY header truncated")
	}
	vlength := int(binary.BigEndian.Uint32(b[8:12]))
	off := 12 + vlength
	if off+4 > len(b) {
		return nil, fmt.Errorf("oncrpc: verifier body overruns the RPC reply header")
	}
	m.Accepted = true
	m.AcceptStat = binary.BigEndian.Uint32(b[off : off+4])
	m.Body = b[off+4:]
	return m, nil
}

// AcceptStatName maps the RFC 5531 accept_stat enumeration.
func AcceptStatName(s uint32) string {
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
