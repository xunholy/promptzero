// Package dcerpc decodes DCE/RPC (Distributed Computing
// Environment / Remote Procedure Call) messages per DCE 1.1 +
// [MS-RPCE] — the Microsoft RPC framing layer that carries
// nearly every Windows AD attack chain. Runs over TCP/135
// (Endpoint Mapper), TCP/49152+ (ephemeral RPC ports), and
// inside SMB2 named pipes (\pipe\netlogon, \pipe\samr,
// \pipe\lsarpc, \pipe\srvsvc, \pipe\svcctl, \pipe\drsuapi,
// \pipe\spoolss).
//
// Operationally, DCE/RPC is the **MS-RPC attack-vector
// identifier**. SMB2 surfaces `\pipe\<name>` paths; DCE/RPC
// surfaces the underlying interface UUID + opnum that
// identify the exact RPC function being invoked. The
// combination is the canonical attack-chain indicator. Each
// well-known interface UUID maps to a Microsoft Windows
// service:
//
//   - **NETLOGON** (`12345678-1234-abcd-ef00-01234567cffb`) —
//     opnum 30 (`NetrServerAuthenticate3`) is the **ZeroLogon**
//     target (CVE-2020-1472). Observing BIND to the netlogon
//     UUID + REQUEST opnum 30 is the canonical ZeroLogon
//     attack signature.
//
//   - **DRSUAPI** (`e3514235-4b06-11d1-ab04-00c04fc2dcd2`) —
//     opnum 3 (`DRSGetNCChanges`) is the **DCSync** attack
//     vector. The Directory Replication Service primitive
//     used by `lsadump::dcsync` (mimikatz) and `impacket
//     secretsdump.py -just-dc` to extract all AD password
//     hashes by impersonating a DC replication partner.
//     **High-privilege requirement** (Replicating Directory
//     Changes All) — but a single compromised admin account
//     yields every domain hash.
//
//   - **SAMR** (`12345778-1234-abcd-ef00-0123456789ab`) — the
//     Security Account Manager Remote interface, used for
//     **AD user / group enumeration** (`net user /domain`,
//     `enum4linux`, `rpcclient enumdomusers`). High-runner
//     opnums: 5 `SamrOpenDomain` / 13 `SamrEnumerateUsersIn
//     Domain` / 27 `SamrLookupNamesInDomain` / 36
//     `SamrQueryInformationUser` (per-user attribute leak —
//     description, badPwdCount, lastLogon).
//
//   - **LSARPC** (`12345778-1234-abcd-ef00-0123456789ac`) —
//     Local Security Authority remote interface, used for
//     SID translation + LSA-policy access + **SAM secrets
//     dump** (`lsadump::secrets`, `lsadump::trust`).
//
//   - **SVCCTL** (`367abb81-9844-35f1-ad32-98f038001003`) —
//     Service Control Manager remote interface, used by
//     **PsExec / impacket psexec.py / smbexec.py** for
//     lateral-movement service creation + start (opnums:
//     12 `RCreateServiceW` / 19 `RStartServiceW`).
//
//   - **SPOOLSS** (`12345678-1234-abcd-ef00-0123456789ab`) —
//     Print Spooler remote interface; opnum 65
//     `RpcRemoteFindFirstPrinterChangeNotificationEx` is the
//     **PrintNightmare** target (CVE-2021-1675 /
//     CVE-2021-34527) — abused for SYSTEM RCE on print
//     spooler.
//
//   - **ATSVC** (`1ff70682-0a51-30e8-076d-740be8cee98b`) —
//     Task Scheduler Service remote interface, alternative
//     lateral-move path when svcctl is restricted (opnums:
//     0 `NetrJobAdd` / 1 `NetrJobDel`).
//
//   - **ITaskSchedulerService** (`86d35949-83c9-4044-b424-
//     db363231fd0c`) — modern XML-task-XML task scheduler
//     interface, schtasks lateral-move target.
//
//   - **WKSSVC** (`6bffd098-a112-3610-9833-46c3f87e345a`) —
//     Workstation Service, often abused for
//     `NetWkstaUserEnum` (logged-on users disclosure).
//
//   - **SRVSVC** (`4b324fc8-1670-01d3-1278-5a47bf6ee188`) —
//     Server Service, used for `NetSessionEnum` (active SMB
//     sessions enumeration → identifying logged-on admin
//     accounts), `NetShareEnum` (share enumeration).
//
//   - **EPMAPPER** (`afa8bd80-7d8a-11c9-bef4-08002b102989`)
//     — Endpoint Mapper on TCP/135; bind to look up which
//     ephemeral TCP port a target interface is exposed on
//     (the RPC `portmap`).
//
// Wrap-vs-native judgement
//
//	Native. DCE 1.1 + [MS-RPCE] are publicly documented; the
//	common header is a fixed 16-byte struct. Data
//	representation is byte-order-flagged via drep[0] (bit 4
//	= little-endian; Windows is always LE on the wire).
//	BIND / REQUEST / FAULT body decoding is straightforward.
//	NDR parameter marshalling, IDL interface inner-decode,
//	DCOM ORPCTHIS chains, and sec_trailer parsing beyond
//	auth-length surfacing are out of scope.
//
// What this package covers
//
//   - **16-byte common header** ([MS-RPCE] §2.2.6.1):
//     rpc_vers (1) = 5 / rpc_vers_minor (1) = 0 / PTYPE (1)
//     / pfc_flags (1) / drep[4] (data representation;
//     drep[0] bit 4 = little-endian) / frag_length (2) /
//     auth_length (2) / call_id (4).
//
//   - **14-entry PTYPE name table** (RFC 2237 / DCE 1.1
//     §12.1): 0 `REQUEST` / 1 `PING` / 2 `RESPONSE` / 3
//     `FAULT` / 4 `WORKING` / 5 `NOCALL` / 6 `REJECT` / 7
//     `ACK` / 8 `CL_CANCEL` / 9 `FACK` / 10 `CANCEL_ACK` /
//     11 `BIND` / 12 `BIND_ACK` / 13 `BIND_NAK` / 14
//     `ALTER_CONTEXT` / 15 `ALTER_CONTEXT_RESP` / 16
//     `SHUTDOWN` / 17 `CO_CANCEL` / 18 `ORPHANED` / 19
//     `AUTH3`.
//
//   - **6-entry pfc_flags name table**: 0x01 `FIRST_FRAG` /
//     0x02 `LAST_FRAG` / 0x04 `PENDING_CANCEL` / 0x10
//     `CONC_MPX` / 0x20 `DID_NOT_EXECUTE` / 0x80
//     `OBJECT_UUID`.
//
//   - **BIND / ALTER_CONTEXT body walker** ([MS-RPCE]
//     §2.2.6.4): max_xmit_frag (2) / max_recv_frag (2) /
//     assoc_group_id (4) / p_context_elem_count (1) /
//     reserved (3) / p_context_elem[]. The first context
//     element carries the abstract_syntax (interface UUID
//
//   - interface version) — the canonical RPC interface
//     identifier.
//
//   - **20+ entry interface UUID name table** flagging each
//     well-known interface with its canonical attack vector
//     (netlogon ZeroLogon, drsuapi DCSync, samr AD enum,
//     spoolss PrintNightmare, svcctl PsExec, atsvc Task
//     Scheduler lateral move, lsarpc SAM secrets dump,
//     srvsvc NetSessionEnum, wkssvc NetWkstaUserEnum,
//     epmapper Endpoint Mapper, DnsServer, IRemoteWinspool,
//     ITaskSchedulerService, IFileReplicaService,
//     IFlightServer).
//
//   - **REQUEST body walker** ([MS-RPCE] §2.2.6.2):
//     alloc_hint (4) / p_cont_id (2) / opnum (2) — the
//     function within the interface being called. Combined
//     with the interface UUID, opnum is the exact RPC
//     function identifier.
//
//   - **FAULT body walker** ([MS-RPCE] §2.2.6.6):
//     alloc_hint (4) / p_cont_id (2) / cancel_count (1) /
//     reserved (1) / status (4) — DCE RPC fault status code.
//     Surfaced with a fault-status name table covering
//     high-runner DCE RPC + MS-RPC NCA fault codes.
//
//   - **9-entry NCA fault status name table** (DCE 1.1
//     §12.6.4.10 + MS-RPCE §3.1.1.5.5): 0x00000005
//     `nca_s_fault_access_denied` / 0x1C010002 `nca_s_fault
//     _addr_error` / 0x1C010003 `nca_s_fault_context_mismatch`
//     / 0x1C00000B `nca_s_fault_out_of_resources` /
//     0x1C00000C `nca_s_fault_unspec_reject` / 0x1C010014
//     `nca_s_fault_invalid_pres_context_id` / 0x1C010015
//     `nca_s_fault_unsupported_type` / 0x6BD `RPC_X_BAD_STUB
//     _DATA` / 0x6F7 `RPC_S_SERVER_UNAVAILABLE`.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **NDR (Network Data Representation) parameter
//     marshalling** — each per-interface IDL function takes
//     typed parameters marshalled via NDR (the DCE 1.1
//     transfer syntax). The decoder surfaces the opnum but
//     does NOT decode the parameters; that requires the
//     full IDL definition for each interface (1000+ Microsoft
//     RPC interfaces).
//   - **DCOM (Distributed COM) ORPCTHIS / ORPCTHAT** —
//     wraps an extra header onto DCE/RPC requests for the
//     OXID/OID/IPID DCOM addressing layer; out of scope.
//   - **Connectionless DCE/RPC** (UDP/135) — the decoder
//     focuses on connection-oriented DCE/RPC (TCP); the
//     CL variant uses different PTYPE values and is rarely
//     seen in modern Windows AD environments.
//   - **sec_trailer parsing** — when auth_length > 0, the
//     last `auth_length + 8` bytes of the fragment carry an
//     authentication trailer (sec_trailer + auth_value).
//     Surfaced as `auth_length` only; per-mechanism (NTLM /
//     Kerberos / Negotiate) auth_value decode is handled by
//     ntlm_decode / kerberos_decode.
//   - **Interface-specific opnum name tables** — the
//     decoder surfaces the raw opnum integer; per-interface
//     opnum-to-function name mapping (netlogon opnum 30 =
//     NetrServerAuthenticate3, drsuapi opnum 3 =
//     DRSGetNCChanges) is out of scope (each interface has
//     30+ opnums and there are 1000+ interfaces).
package dcerpc

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

const headerSize = 16

// Result is the structured decode of a DCE/RPC message.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	RPCVersion      int      `json:"rpc_version"`
	RPCVersionMinor int      `json:"rpc_version_minor"`
	PType           int      `json:"ptype"`
	PTypeName       string   `json:"ptype_name"`
	PFCFlags        int      `json:"pfc_flags"`
	PFCFlagsNames   []string `json:"pfc_flags_names,omitempty"`
	LittleEndian    bool     `json:"little_endian"`
	FragLength      int      `json:"frag_length"`
	AuthLength      int      `json:"auth_length"`
	CallID          uint32   `json:"call_id"`

	// BIND / ALTER_CONTEXT body
	MaxXmitFrag       int    `json:"max_xmit_frag,omitempty"`
	MaxRecvFrag       int    `json:"max_recv_frag,omitempty"`
	AssocGroupID      uint32 `json:"assoc_group_id,omitempty"`
	ContextElemCount  int    `json:"context_elem_count,omitempty"`
	InterfaceUUID     string `json:"interface_uuid,omitempty"`
	InterfaceName     string `json:"interface_name,omitempty"`
	InterfaceVerMajor int    `json:"interface_version_major,omitempty"`
	InterfaceVerMinor int    `json:"interface_version_minor,omitempty"`

	// REQUEST body
	AllocHint uint32 `json:"alloc_hint,omitempty"`
	ContextID int    `json:"context_id,omitempty"`
	Opnum     int    `json:"opnum,omitempty"`

	// FAULT body
	FaultStatus     uint32 `json:"fault_status,omitempty"`
	FaultStatusName string `json:"fault_status_name,omitempty"`
}

// Decode parses a DCE/RPC message from a hex string.
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if len(clean) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex (%d nibbles)", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) < headerSize {
		return nil, fmt.Errorf("dcerpc header truncated (%d bytes; need 16)", len(b))
	}

	r := &Result{TotalBytes: len(b)}

	r.RPCVersion = int(b[0])
	r.RPCVersionMinor = int(b[1])
	if r.RPCVersion != 5 {
		return r, fmt.Errorf("not a DCE/RPC v5 message (got rpc_vers=%d)", r.RPCVersion)
	}
	r.PType = int(b[2])
	r.PTypeName = ptypeName(r.PType)
	r.PFCFlags = int(b[3])
	r.PFCFlagsNames = pfcFlagsNames(b[3])
	// drep[0] bit 4 = little-endian (1 = LE, 0 = BE)
	r.LittleEndian = (b[4]>>4)&0x01 == 1
	var bo binary.ByteOrder = binary.LittleEndian
	if !r.LittleEndian {
		bo = binary.BigEndian
	}
	r.FragLength = int(bo.Uint16(b[8:10]))
	r.AuthLength = int(bo.Uint16(b[10:12]))
	r.CallID = bo.Uint32(b[12:16])

	body := b[headerSize:]
	switch r.PType {
	case 11, 12, 14, 15:
		decodeBindBody(r, body, bo)
	case 0:
		decodeRequestBody(r, body, bo)
	case 3:
		decodeFaultBody(r, body, bo)
	}
	return r, nil
}

func decodeBindBody(r *Result, body []byte, bo binary.ByteOrder) {
	if len(body) < 12 {
		return
	}
	r.MaxXmitFrag = int(bo.Uint16(body[0:2]))
	r.MaxRecvFrag = int(bo.Uint16(body[2:4]))
	r.AssocGroupID = bo.Uint32(body[4:8])
	r.ContextElemCount = int(body[8])
	// First p_cont_elem starts at body[12]:
	//   p_cont_id (2) / n_transfer_syn (1) / reserved (1) /
	//   abstract_syntax (UUID(16) + version(4))
	if len(body) < 12+24 {
		return
	}
	// UUID is 16 bytes at body[16:32]. Microsoft RPC encodes
	// UUID with the first three fields in the local byte
	// order, last two as big-endian byte arrays.
	uuid := body[16:32]
	r.InterfaceUUID = formatUUID(uuid, bo)
	r.InterfaceName = interfaceName(r.InterfaceUUID)
	r.InterfaceVerMajor = int(bo.Uint16(body[32:34]))
	r.InterfaceVerMinor = int(bo.Uint16(body[34:36]))
}

func decodeRequestBody(r *Result, body []byte, bo binary.ByteOrder) {
	if len(body) < 8 {
		return
	}
	r.AllocHint = bo.Uint32(body[0:4])
	r.ContextID = int(bo.Uint16(body[4:6]))
	r.Opnum = int(bo.Uint16(body[6:8]))
}

func decodeFaultBody(r *Result, body []byte, bo binary.ByteOrder) {
	if len(body) < 12 {
		return
	}
	r.AllocHint = bo.Uint32(body[0:4])
	r.ContextID = int(bo.Uint16(body[4:6]))
	r.FaultStatus = bo.Uint32(body[8:12])
	r.FaultStatusName = faultStatusName(r.FaultStatus)
}

// formatUUID renders a 16-byte UUID in canonical 8-4-4-4-12
// form. The first three fields are byte-order-sensitive per
// the Microsoft RPC encoding; last two are always BE byte
// arrays.
func formatUUID(b []byte, bo binary.ByteOrder) string {
	d1 := bo.Uint32(b[0:4])
	d2 := bo.Uint16(b[4:6])
	d3 := bo.Uint16(b[6:8])
	return fmt.Sprintf(
		"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		d1, d2, d3,
		b[8], b[9],
		b[10], b[11], b[12], b[13], b[14], b[15])
}

func ptypeName(t int) string {
	switch t {
	case 0:
		return "REQUEST"
	case 1:
		return "PING"
	case 2:
		return "RESPONSE"
	case 3:
		return "FAULT"
	case 4:
		return "WORKING"
	case 5:
		return "NOCALL"
	case 6:
		return "REJECT"
	case 7:
		return "ACK"
	case 8:
		return "CL_CANCEL"
	case 9:
		return "FACK"
	case 10:
		return "CANCEL_ACK"
	case 11:
		return "BIND"
	case 12:
		return "BIND_ACK"
	case 13:
		return "BIND_NAK"
	case 14:
		return "ALTER_CONTEXT"
	case 15:
		return "ALTER_CONTEXT_RESP"
	case 16:
		return "SHUTDOWN"
	case 17:
		return "CO_CANCEL"
	case 18:
		return "ORPHANED"
	case 19:
		return "AUTH3"
	}
	return fmt.Sprintf("uncatalogued PTYPE %d", t)
}

func pfcFlagsNames(f byte) []string {
	var names []string
	if f&0x01 != 0 {
		names = append(names, "FIRST_FRAG")
	}
	if f&0x02 != 0 {
		names = append(names, "LAST_FRAG")
	}
	if f&0x04 != 0 {
		names = append(names, "PENDING_CANCEL")
	}
	if f&0x10 != 0 {
		names = append(names, "CONC_MPX")
	}
	if f&0x20 != 0 {
		names = append(names, "DID_NOT_EXECUTE")
	}
	if f&0x80 != 0 {
		names = append(names, "OBJECT_UUID")
	}
	return names
}

func interfaceName(uuid string) string {
	switch strings.ToLower(uuid) {
	case "12345678-1234-abcd-ef00-01234567cffb":
		return "netlogon (ZeroLogon CVE-2020-1472 target!)"
	case "e3514235-4b06-11d1-ab04-00c04fc2dcd2":
		return "drsuapi (DCSync attack vector — extracts all AD password hashes!)"
	case "12345778-1234-abcd-ef00-0123456789ab":
		return "samr (AD user/group enumeration)"
	case "12345778-1234-abcd-ef00-0123456789ac":
		return "lsarpc (LSA-policy / SAM secrets dump)"
	case "367abb81-9844-35f1-ad32-98f038001003":
		return "svcctl (Service Control Manager — PsExec lateral move)"
	case "12345678-1234-abcd-ef00-0123456789ab":
		return "spoolss (PrintNightmare CVE-2021-1675/34527 target!)"
	case "1ff70682-0a51-30e8-076d-740be8cee98b":
		return "atsvc (Task Scheduler — lateral move)"
	case "86d35949-83c9-4044-b424-db363231fd0c":
		return "ITaskSchedulerService (modern task scheduler — schtasks lateral move)"
	case "6bffd098-a112-3610-9833-46c3f87e345a":
		return "wkssvc (Workstation Service — NetWkstaUserEnum)"
	case "4b324fc8-1670-01d3-1278-5a47bf6ee188":
		return "srvsvc (Server Service — NetSessionEnum / NetShareEnum)"
	case "afa8bd80-7d8a-11c9-bef4-08002b102989":
		return "epmapper (Endpoint Mapper — RPC portmap on TCP/135)"
	case "50abc2a4-574d-40b3-9d66-ee4fd5fba076":
		return "DnsServer (DNS RPC management)"
	case "76f226c3-ec14-4325-8a99-6a46348418af":
		return "winreg (Remote Registry — registry tampering)"
	case "338cd001-2244-31f1-aaaa-900038001003":
		return "winreg (Remote Registry — alternate UUID)"
	case "3919286a-b10c-11d0-9ba8-00c04fd92ef5":
		return "lsa_ds (LSA Directory Services)"
	case "5a7b91f8-ff00-11d0-a9b2-00c04fb6e6fc":
		return "messenger (Messenger Service)"
	case "c681d488-d850-11d0-8c52-00c04fd90f7e":
		return "EFS (Encrypting File System Remote — PetitPotam coercion!)"
	case "df1941c5-fe89-4e79-bf10-463657acf44d":
		return "EFS (alternate UUID — PetitPotam coercion)"
	case "12345678-1234-abcd-ef00-0123456789ff":
		return "browser (Computer Browser)"
	case "975201b0-59ca-11d0-a8d5-00a0c90d8051":
		return "FrsRpc (File Replication Service)"
	}
	return "uncatalogued interface"
}

func faultStatusName(s uint32) string {
	switch s {
	case 0x00000005:
		return "nca_s_fault_access_denied"
	case 0x1C010002:
		return "nca_s_fault_addr_error"
	case 0x1C010003:
		return "nca_s_fault_context_mismatch"
	case 0x1C00000B:
		return "nca_s_fault_out_of_resources"
	case 0x1C00000C:
		return "nca_s_fault_unspec_reject"
	case 0x1C010014:
		return "nca_s_fault_invalid_pres_context_id"
	case 0x1C010015:
		return "nca_s_fault_unsupported_type"
	case 0x000006BD:
		return "RPC_X_BAD_STUB_DATA"
	case 0x000006F7:
		return "RPC_S_SERVER_UNAVAILABLE"
	}
	return fmt.Sprintf("uncatalogued fault status 0x%08X", s)
}

func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', ':', '-', '_':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
