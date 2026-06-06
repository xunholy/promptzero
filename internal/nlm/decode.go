// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nlm decodes the ONC RPC NFS Lock Manager protocol v4 (NLM,
// program 100021) — the byte-range / advisory locking sidecar of NFS, run
// by rpc.lockd. It is the fourth member of the project's Sun-RPC decoder
// suite (internal/portmap, internal/mount, internal/nfs) and shares their
// internal/oncrpc framing. rpc.lockd is a long-standing remote attack
// surface, and a captured NLM exchange is recon in its own right: a
// LOCK / TEST / CANCEL / UNLOCK call carries the **caller name** (the
// client host identity it announces), the **file handle** being locked,
// the **lock owner** (a client/process identity string), the locked byte
// range (offset + length) and whether the lock is exclusive — so an NLM
// stream maps which hosts are contending for which files.
//
// # Wrap-vs-native judgement
//
//	Native. An NLM message is an ONC RPC header (parsed by the shared
//	internal/oncrpc package) plus a procedure body of XDR fields — an
//	opaque cookie, flag words, length-prefixed strings (caller name, lock
//	owner), an opaque file handle and 64-bit offset/length. A byte-field
//	read + bounded XDR walks; stdlib only, no new go.mod dep. This package
//	implements only the NLM procedure bodies.
//
// # Verifiable / no confidently-wrong output
//
//	The RPC header and the lock-call arguments (caller / file handle /
//	owner / svid / offset / length, with the per-procedure leading flag
//	fields) and the reply status were verified field-for-field against
//	scapy's NLM layer (scapy.contrib.nlm). Arguments are decoded for the
//	four core lock procedures (TEST / LOCK / CANCEL / UNLOCK), whose XDR
//	layout is unambiguous; the other procedures (the *_MSG / *_RES async
//	variants, SHARE / UNSHARE / FREE_ALL) are named with their body
//	surfaced raw. A reply is decoded as its cookie + the nlm4_stats result
//	(gated on a defined code) with the body surfaced raw otherwise.
package nlm

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/oncrpc"
)

const nlmProgram = 100021

// Result is the decoded view of an NLM RPC message.
type Result struct {
	XID         string `json:"xid"`
	MessageType int    `json:"message_type"`
	MessageName string `json:"message_name"`

	// Call.
	Program     *uint32 `json:"program,omitempty"`
	ProgVersion *uint32 `json:"program_version,omitempty"`
	Procedure   *uint32 `json:"procedure,omitempty"`
	ProcName    string  `json:"procedure_name,omitempty"`
	Caller      string  `json:"caller_name,omitempty"`
	FileHandle  string  `json:"file_handle,omitempty"`
	Owner       string  `json:"lock_owner,omitempty"`
	SVID        *uint32 `json:"svid,omitempty"`
	Offset      *uint64 `json:"offset,omitempty"`
	Length      *uint64 `json:"length,omitempty"`
	Exclusive   *bool   `json:"exclusive,omitempty"`

	// Reply.
	AcceptStat *uint32 `json:"accept_stat,omitempty"`
	AcceptName string  `json:"accept_stat_name,omitempty"`
	Status     *int    `json:"nlm_status,omitempty"`
	StatusName string  `json:"nlm_status_name,omitempty"`

	BodyHex string   `json:"body_hex,omitempty"`
	Notes   []string `json:"notes,omitempty"`
}

// Decode parses an NLM ONC RPC message (the lockd payload, without any TCP
// record marker) from hex (whitespace / ':' / '-' / '_' separators and a
// '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	m, err := oncrpc.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("nlm: %w", err)
	}
	r := &Result{XID: fmt.Sprintf("0x%08X", m.XID), MessageType: int(m.Type)}
	if m.IsCall() {
		r.MessageName = "CALL"
		return decodeCall(r, m), nil
	}
	r.MessageName = "REPLY"
	return decodeReply(r, m), nil
}

func decodeCall(r *Result, m *oncrpc.Message) *Result {
	prog, pver, proc := m.Program, m.ProgramVersion, m.Procedure
	r.Program, r.ProgVersion, r.Procedure = &prog, &pver, &proc
	r.ProcName = procName(proc)
	if prog != nlmProgram {
		r.Notes = append(r.Notes, fmt.Sprintf("program %d is not NLM (100021)", prog))
		if len(m.Body) > 0 {
			r.BodyHex = hexUpper(m.Body)
		}
		return r
	}
	switch proc {
	case 1, 2, 3, 4: // TEST / LOCK / CANCEL / UNLOCK carry a lock argument
		decodeLockArgs(r, proc, m.Body)
	default:
		if len(m.Body) > 0 {
			r.BodyHex = hexUpper(m.Body)
		}
		r.Notes = append(r.Notes, "NLM "+procName(proc)+": body surfaced raw (only the TEST/LOCK/CANCEL/UNLOCK lock arguments are decoded)")
	}
	return r
}

// decodeLockArgs decodes the nlm4_lock argument that the four core lock
// procedures carry. The fields before the caller name differ per procedure:
// LOCK/CANCEL prefix block + exclusive, TEST prefixes exclusive only, UNLOCK
// has neither.
func decodeLockArgs(r *Result, proc uint32, a []byte) {
	rd := &reader{b: a}
	if _, ok := rd.opaque(); !ok { // cookie
		return
	}
	switch proc {
	case 2, 3: // LOCK / CANCEL: block + exclusive
		if _, ok := rd.u32(); !ok { // block
			return
		}
		ex, ok := rd.u32()
		if !ok {
			return
		}
		b := ex != 0
		r.Exclusive = &b
	case 1: // TEST: exclusive only
		ex, ok := rd.u32()
		if !ok {
			return
		}
		b := ex != 0
		r.Exclusive = &b
	}
	caller, ok := rd.str()
	fh, ok2 := rd.hexOpaque()
	owner, ok3 := rd.str()
	svid, ok4 := rd.u32()
	off, ok5 := rd.u64()
	ln, ok6 := rd.u64()
	if !ok || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 {
		r.Notes = append(r.Notes, "lock argument truncated")
		return
	}
	r.Caller, r.FileHandle, r.Owner = caller, fh, owner
	r.SVID, r.Offset, r.Length = &svid, &off, &ln
	r.Notes = append(r.Notes, fmt.Sprintf("NLM %s: host %q locking bytes %d..%d of file %s (owner %q)", procName(proc), caller, off, off+ln, fh, owner))
}

func decodeReply(r *Result, m *oncrpc.Message) *Result {
	if m.ReplyStat != 0 {
		r.BodyHex = hexUpper(m.Body)
		r.Notes = append(r.Notes, "RPC reply denied")
		return r
	}
	as := m.AcceptStat
	r.AcceptStat, r.AcceptName = &as, oncrpc.AcceptStatName(as)
	body := m.Body
	if as == 0 {
		// An NLM reply is a cookie (opaque) followed by an nlm4_stats code.
		rd := &reader{b: body}
		if _, ok := rd.opaque(); ok {
			if st, ok2 := rd.u32(); ok2 {
				if name, known := nlmStat(int(st)); known {
					s := int(st)
					r.Status, r.StatusName = &s, name
				}
			}
		}
	}
	if len(body) > 0 {
		r.BodyHex = hexUpper(body)
	}
	return r
}

// reader walks XDR fields with bounds checking.
type reader struct {
	b   []byte
	off int
}

func (r *reader) u32() (uint32, bool) {
	if r.off+4 > len(r.b) {
		return 0, false
	}
	v := binary.BigEndian.Uint32(r.b[r.off : r.off+4])
	r.off += 4
	return v, true
}

func (r *reader) u64() (uint64, bool) {
	if r.off+8 > len(r.b) {
		return 0, false
	}
	v := binary.BigEndian.Uint64(r.b[r.off : r.off+8])
	r.off += 8
	return v, true
}

func (r *reader) opaque() ([]byte, bool) {
	n, ok := r.u32()
	if !ok {
		return nil, false
	}
	ln := int(n)
	if ln < 0 || r.off+ln > len(r.b) {
		return nil, false
	}
	v := r.b[r.off : r.off+ln]
	r.off += ln + (4-ln%4)%4
	if r.off > len(r.b) {
		r.off = len(r.b)
	}
	return v, true
}

func (r *reader) str() (string, bool) {
	v, ok := r.opaque()
	if !ok {
		return "", false
	}
	return string(v), true
}

func (r *reader) hexOpaque() (string, bool) {
	v, ok := r.opaque()
	if !ok {
		return "", false
	}
	return hexUpper(v), true
}

func procName(p uint32) string {
	names := map[uint32]string{
		0: "NULL", 1: "TEST", 2: "LOCK", 3: "CANCEL", 4: "UNLOCK", 5: "GRANTED",
		6: "TEST_MSG", 7: "LOCK_MSG", 8: "CANCEL_MSG", 9: "UNLOCK_MSG", 10: "GRANTED_MSG",
		11: "TEST_RES", 12: "LOCK_RES", 13: "CANCEL_RES", 14: "UNLOCK_RES", 15: "GRANTED_RES",
		20: "SHARE", 21: "UNSHARE", 22: "NM_LOCK", 23: "FREE_ALL",
	}
	if n, ok := names[p]; ok {
		return n
	}
	return fmt.Sprintf("proc-%d", p)
}

func nlmStat(s int) (string, bool) {
	m := map[int]string{
		0: "NLM4_GRANTED", 1: "NLM4_DENIED", 2: "NLM4_DENIED_NOLOCKS", 3: "NLM4_BLOCKED",
		4: "NLM4_DENIED_GRACE_PERIOD", 5: "NLM4_DEADLCK", 6: "NLM4_ROFS", 7: "NLM4_STALE_FH",
		8: "NLM4_FBIG", 9: "NLM4_FAILED",
	}
	n, ok := m[s]
	return n, ok
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
		return nil, fmt.Errorf("nlm: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("nlm: input is not valid hex: %w", err)
	}
	return b, nil
}
