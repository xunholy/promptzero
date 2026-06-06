// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nfs decodes ONC RPC NFS v3 (RFC 1813, program 100003) call
// messages — the file-access layer that completes the project's NFS
// reconnaissance chain after internal/portmap (rpcbind, locate the
// service) and internal/mount (get the export root file handle). A
// captured NFS call stream is the record of what a client actually does
// on the share: the **dir-operation calls carry filenames** — a LOOKUP /
// CREATE / REMOVE / RENAME / MKDIR names the exact file being accessed
// ("a client is reading /etc/shadow off the export"), and READ / WRITE
// expose the file handle + offset + length being transferred. Decoding
// the calls surfaces the NFS access pattern from a passive capture.
//
// # Wrap-vs-native judgement
//
//	Native. An NFS message is an ONC RPC header (xid, type, call fields)
//	plus a procedure body of XDR fields — file handles (length-prefixed
//	opaque) and names (length-prefixed strings), 4-byte aligned. A
//	byte-field read + bounded XDR walks; stdlib only, no new go.mod dep.
//	The RPC framing is parsed by the shared internal/oncrpc package (used
//	by portmap, mount and nfs); this package implements only the NFS
//	procedure bodies.
//
// # Verifiable / no confidently-wrong output
//
//	The RPC header and the recon-bearing v3 call arguments (the file
//	handle, the operand filenames, and the READ/WRITE offset+count) were
//	verified field-for-field against scapy's NFS layer
//	(scapy.contrib.nfs). The procedure is named for every call; arguments
//	are decoded only for the calls whose leading fields are unambiguous
//	(handle / name / offset). NFS *replies* are large, procedure-specific
//	and not self-identifying (the client correlates by xid), so a reply is
//	reported as its accept status + a recognised nfsstat3 result code with
//	the body surfaced raw — never guessed. Procedures whose arguments
//	carry trailing attribute structures are decoded up to the
//	recon-bearing fields and the remainder left implicit.
package nfs

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/oncrpc"
)

// Result is the decoded view of an NFS v3 RPC message.
type Result struct {
	XID         string `json:"xid"`
	MessageType int    `json:"message_type"`
	MessageName string `json:"message_name"`

	// Call.
	Program     *uint32 `json:"program,omitempty"`
	ProgVersion *uint32 `json:"program_version,omitempty"`
	Procedure   *uint32 `json:"procedure,omitempty"`
	ProcName    string  `json:"procedure_name,omitempty"`
	FileHandle  string  `json:"file_handle,omitempty"`
	FileHandle2 string  `json:"file_handle2,omitempty"`
	Filename    string  `json:"filename,omitempty"`
	Filename2   string  `json:"filename2,omitempty"`
	Offset      *uint64 `json:"offset,omitempty"`
	Count       *uint32 `json:"count,omitempty"`

	// Reply.
	AcceptStat *uint32 `json:"accept_stat,omitempty"`
	AcceptName string  `json:"accept_stat_name,omitempty"`
	Status     *int    `json:"nfs_status,omitempty"`
	StatusName string  `json:"nfs_status_name,omitempty"`

	BodyHex string   `json:"body_hex,omitempty"`
	Notes   []string `json:"notes,omitempty"`
}

const nfsProgram = 100003

// Decode parses an NFS v3 ONC RPC message (the NFS payload, without any
// TCP record marker) from hex (whitespace / ':' / '-' / '_' separators
// and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	m, err := oncrpc.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("nfs: %w", err)
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
	args := m.Body
	if prog != nfsProgram {
		r.Notes = append(r.Notes, fmt.Sprintf("program %d is not NFS (100003)", prog))
		if len(args) > 0 {
			r.BodyHex = hexUpper(args)
		}
		return r
	}
	decodeArgs(r, proc, args)
	return r
}

// decodeArgs decodes the recon-bearing leading arguments of an NFSv3 call.
func decodeArgs(r *Result, proc uint32, a []byte) {
	rd := &reader{b: a}
	switch proc {
	case 1, 2, 4, 5, 18, 19, 20: // GETATTR/SETATTR/ACCESS/READLINK/FSSTAT/FSINFO/PATHCONF: a file handle
		if fh, ok := rd.handle(); ok {
			r.FileHandle = fh
		}
	case 3, 8, 9, 10, 11, 12, 13: // LOOKUP/CREATE/MKDIR/SYMLINK/MKNOD/REMOVE/RMDIR: dir handle + name
		fh, ok := rd.handle()
		nm, ok2 := rd.name()
		if ok && ok2 {
			r.FileHandle, r.Filename = fh, nm
			r.Notes = append(r.Notes, "NFS "+procName(proc)+" of "+nm+" — the filename being accessed on the export")
		}
	case 6, 7: // READ/WRITE: file handle + offset(8) + count(4)
		fh, ok := rd.handle()
		o, ok2 := rd.u64()
		c, ok3 := rd.u32()
		if ok && ok2 && ok3 {
			r.FileHandle, r.Offset, r.Count = fh, &o, &c
			r.Notes = append(r.Notes, fmt.Sprintf("NFS %s at offset %d, %d bytes", procName(proc), o, c))
		}
	case 14: // RENAME: dir_from + name_from + dir_to + name_to
		fh, ok := rd.handle()
		nm, ok2 := rd.name()
		fh2, ok3 := rd.handle()
		nm2, ok4 := rd.name()
		if ok && ok2 && ok3 && ok4 {
			r.FileHandle, r.Filename, r.FileHandle2, r.Filename2 = fh, nm, fh2, nm2
			r.Notes = append(r.Notes, "NFS RENAME "+nm+" -> "+nm2)
		}
	case 15: // LINK: file handle + dir handle + name
		fh, ok := rd.handle()
		fh2, ok2 := rd.handle()
		nm, ok3 := rd.name()
		if ok && ok2 && ok3 {
			r.FileHandle, r.FileHandle2, r.Filename = fh, fh2, nm
		}
	case 16, 17: // READDIR/READDIRPLUS: dir handle (+ cookie etc., left implicit)
		if fh, ok := rd.handle(); ok {
			r.FileHandle = fh
			r.Notes = append(r.Notes, "NFS "+procName(proc)+": directory enumeration of file handle "+fh)
		}
	default:
		if len(a) > 0 {
			r.BodyHex = hexUpper(a)
		}
	}
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
	if as == 0 && len(body) >= 4 {
		if status := int(binary.BigEndian.Uint32(body[0:4])); knownNFSStat(status) {
			name := nfsStatName(status)
			r.Status, r.StatusName = &status, name
		}
	}
	if len(body) > 0 {
		r.BodyHex = hexUpper(body)
	}
	r.Notes = append(r.Notes, "NFS reply: the status is decoded; the procedure-specific body is surfaced raw (an NFS reply does not identify which call it answers)")
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

// opaque reads an XDR variable-length opaque (length + bytes + 4-byte pad).
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

func (r *reader) handle() (string, bool) {
	v, ok := r.opaque()
	if !ok {
		return "", false
	}
	return hexUpper(v), true
}

func (r *reader) name() (string, bool) {
	v, ok := r.opaque()
	if !ok {
		return "", false
	}
	return string(v), true
}

func procName(p uint32) string {
	names := map[uint32]string{
		0: "NULL", 1: "GETATTR", 2: "SETATTR", 3: "LOOKUP", 4: "ACCESS", 5: "READLINK",
		6: "READ", 7: "WRITE", 8: "CREATE", 9: "MKDIR", 10: "SYMLINK", 11: "MKNOD",
		12: "REMOVE", 13: "RMDIR", 14: "RENAME", 15: "LINK", 16: "READDIR",
		17: "READDIRPLUS", 18: "FSSTAT", 19: "FSINFO", 20: "PATHCONF", 21: "COMMIT",
	}
	if n, ok := names[p]; ok {
		return n
	}
	return fmt.Sprintf("proc-%d", p)
}

var nfsStats = map[int]string{
	0: "NFS3_OK", 1: "NFS3ERR_PERM", 2: "NFS3ERR_NOENT", 5: "NFS3ERR_IO",
	6: "NFS3ERR_NXIO", 13: "NFS3ERR_ACCES", 17: "NFS3ERR_EXIST", 18: "NFS3ERR_XDEV",
	19: "NFS3ERR_NODEV", 20: "NFS3ERR_NOTDIR", 21: "NFS3ERR_ISDIR", 22: "NFS3ERR_INVAL",
	27: "NFS3ERR_FBIG", 28: "NFS3ERR_NOSPC", 30: "NFS3ERR_ROFS", 31: "NFS3ERR_MLINK",
	63: "NFS3ERR_NAMETOOLONG", 66: "NFS3ERR_NOTEMPTY", 69: "NFS3ERR_DQUOT",
	70: "NFS3ERR_STALE", 71: "NFS3ERR_REMOTE", 10001: "NFS3ERR_BADHANDLE",
	10004: "NFS3ERR_NOTSUPP", 10006: "NFS3ERR_SERVERFAULT",
}

func knownNFSStat(s int) bool  { _, ok := nfsStats[s]; return ok }
func nfsStatName(s int) string { return nfsStats[s] }

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
		return nil, fmt.Errorf("nfs: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("nfs: input is not valid hex: %w", err)
	}
	return b, nil
}
