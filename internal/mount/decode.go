// SPDX-License-Identifier: AGPL-3.0-or-later

// Package mount decodes the ONC RPC NFS MOUNT protocol v3 (RFC 1813,
// program 100005) — the service that hands a client the root file handle
// for an NFS export. It is the NFS-reconnaissance companion to
// internal/portmap (rpcbind): after rpcinfo locates mountd, a captured
// MOUNT exchange exposes the NFS attack surface — the exact **export
// path** a client mounts, the **result** (a successful mount vs an
// MNT3ERR_ACCES denial — the export's access control in action), the
// **file handle** the server returns (the capability to read the export;
// a captured / guessable NFS file handle is the classic NFS
// file-handle-reuse attack), and the **auth flavors** the server accepts
// (AUTH_NULL / AUTH_SYS are trivially spoofable, the root of most NFS
// compromises).
//
// # Wrap-vs-native judgement
//
//	Native. A MOUNT message is an ONC RPC header (xid, type, call/reply
//	fields) plus a short procedure body — an XDR path string (call) or a
//	status + file handle + auth-flavor list (reply). A byte-field read +
//	bounded XDR walks; stdlib only, no new go.mod dep. The RPC framing is
//	parsed by the shared internal/oncrpc package (used by portmap, mount
//	and nfs); this package implements only the MOUNT procedure bodies.
//
// # Verifiable / no confidently-wrong output
//
//	The RPC header, the MOUNT / UNMOUNT call path and the MOUNT reply
//	(status / file handle / auth flavors) were verified field-for-field
//	against scapy's NFS-MOUNT layer (scapy.contrib.mount). Because an RPC
//	reply does not carry the procedure it answers, a reply body is typed
//	as a MOUNT reply only when its first word is a defined mountstat3 code
//	and the file-handle + flavor structure parses within the body — else
//	it is surfaced raw. The EXPORT / DUMP procedures (showmount) are
//	deliberately not decoded: scapy does not model them, so they cannot be
//	differentially verified here.
package mount

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/oncrpc"
)

// Result is the decoded view of an NFS MOUNT-protocol RPC message.
type Result struct {
	XID         string `json:"xid"`
	MessageType int    `json:"message_type"`
	MessageName string `json:"message_name"`

	// Call.
	Program     *uint32 `json:"program,omitempty"`
	ProgVersion *uint32 `json:"program_version,omitempty"`
	Procedure   *uint32 `json:"procedure,omitempty"`
	ProcName    string  `json:"procedure_name,omitempty"`
	Path        string  `json:"mount_path,omitempty"`

	// Reply.
	AcceptStat  *uint32  `json:"accept_stat,omitempty"`
	AcceptName  string   `json:"accept_stat_name,omitempty"`
	Status      *int     `json:"mount_status,omitempty"`
	StatusName  string   `json:"mount_status_name,omitempty"`
	FileHandle  string   `json:"file_handle,omitempty"`
	AuthFlavors []string `json:"auth_flavors,omitempty"`

	BodyHex string   `json:"body_hex,omitempty"`
	Notes   []string `json:"notes,omitempty"`
}

const mountProgram = 100005

// Decode parses an NFS MOUNT-protocol ONC RPC message (the mountd payload,
// without any TCP record marker) from hex (whitespace / ':' / '-' / '_'
// separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	m, err := oncrpc.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("mount: %w", err)
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
	if prog == mountProgram && (proc == 1 || proc == 3) { // MNT / UMNT carry a path
		if path, ok := readXDRString(args); ok {
			r.Path = path
			verb := "mounting"
			if proc == 3 {
				verb = "unmounting"
			}
			r.Notes = append(r.Notes, "MOUNT call: a client is "+verb+" the NFS export "+path)
			return r
		}
	}
	if len(args) > 0 {
		r.BodyHex = hexUpper(args)
	}
	return r
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
	if as != 0 || len(body) < 4 {
		if len(body) > 0 {
			r.BodyHex = hexUpper(body)
		}
		return r
	}
	// MOUNT reply: status(4) + (on MNT3_OK) file handle + auth-flavor list.
	// Gate on a defined mountstat3 so a non-MOUNT reply is not mis-typed.
	status := int(binary.BigEndian.Uint32(body[0:4]))
	name, known := mountStat(status)
	if !known {
		r.BodyHex = hexUpper(body)
		r.Notes = append(r.Notes, "accepted result is not a recognised MOUNT reply (first word is not a mountstat3 code) — surfaced raw")
		return r
	}
	r.Status, r.StatusName = &status, name
	if status != 0 {
		r.Notes = append(r.Notes, "MOUNT denied: "+name+" — the export's access control rejected this client")
		return r
	}
	// MNT3_OK: file handle (length + bytes + 4-byte pad), then flavor count + flavors.
	off2 := 4
	if off2+4 > len(body) {
		return r
	}
	fhLen := int(binary.BigEndian.Uint32(body[off2 : off2+4]))
	off2 += 4
	if fhLen < 0 || off2+fhLen > len(body) {
		r.Notes = append(r.Notes, "file-handle length overruns the body")
		return r
	}
	r.FileHandle = hexUpper(body[off2 : off2+fhLen])
	off2 += fhLen + (4-fhLen%4)%4 // XDR opaque is 4-byte aligned
	if off2+4 <= len(body) {
		n := int(binary.BigEndian.Uint32(body[off2 : off2+4]))
		off2 += 4
		for i := 0; i < n && off2+4 <= len(body); i++ {
			r.AuthFlavors = append(r.AuthFlavors, authFlavorName(binary.BigEndian.Uint32(body[off2:off2+4])))
			off2 += 4
		}
	}
	r.Notes = append(r.Notes,
		"MOUNT succeeded: the server returned the export root file handle (a captured / guessable NFS file handle enables the file-handle-reuse attack)",
		"auth flavors the server accepts — AUTH_NULL / AUTH_SYS are trivially spoofable (the root of most NFS compromises)")
	return r
}

// readXDRString reads an XDR variable-length opaque/string (4-byte length +
// bytes + 4-byte padding) and returns it if it fits within b.
func readXDRString(b []byte) (string, bool) {
	if len(b) < 4 {
		return "", false
	}
	n := int(binary.BigEndian.Uint32(b[0:4]))
	if n < 0 || 4+n > len(b) {
		return "", false
	}
	return string(b[4 : 4+n]), true
}

func procName(p uint32) string {
	switch p {
	case 0:
		return "NULL"
	case 1:
		return "MNT"
	case 2:
		return "DUMP"
	case 3:
		return "UMNT"
	case 4:
		return "UMNTALL"
	case 5:
		return "EXPORT"
	}
	return fmt.Sprintf("%d", p)
}

func mountStat(s int) (string, bool) {
	m := map[int]string{
		0: "MNT3_OK", 1: "MNT3ERR_PERM", 2: "MNT3ERR_NOENT", 5: "MNT3ERR_IO",
		13: "MNT3ERR_ACCES", 20: "MNT3ERR_NOTDIR", 22: "MNT3ERR_INVAL",
		63: "MNT3ERR_NAMETOOLONG", 10004: "MNT3ERR_NOTSUPP", 10006: "MNT3ERR_SERVERFAULT",
	}
	n, ok := m[s]
	return n, ok
}

func authFlavorName(f uint32) string {
	switch f {
	case 0:
		return "AUTH_NULL"
	case 1:
		return "AUTH_SYS (AUTH_UNIX)"
	case 2:
		return "AUTH_SHORT"
	case 3:
		return "AUTH_DH"
	case 6:
		return "RPCSEC_GSS"
	}
	return fmt.Sprintf("flavor-%d", f)
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
		return nil, fmt.Errorf("mount: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("mount: input is not valid hex: %w", err)
	}
	return b, nil
}
