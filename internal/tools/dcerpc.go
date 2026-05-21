// dcerpc.go — host-side DCE/RPC message decoder Spec. Wraps the
// internal/dcerpc walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/dcerpc"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(dcerpcDecodeSpec)
}

var dcerpcDecodeSpec = Spec{
	Name: "dcerpc_decode",
	Description: "Decode a DCE/RPC (Distributed Computing Environment / Remote " +
		"Procedure Call) message per DCE 1.1 + Microsoft [MS-RPCE] — the " +
		"Microsoft RPC framing layer that carries nearly every Windows " +
		"AD attack chain. Runs over TCP/135 (Endpoint Mapper), TCP/49152+ " +
		"(ephemeral RPC ports), and inside SMB2 named pipes (\\pipe\\" +
		"netlogon, \\pipe\\samr, \\pipe\\lsarpc, \\pipe\\srvsvc, \\pipe\\" +
		"svcctl, \\pipe\\drsuapi, \\pipe\\spoolss). The MS-RPC attack-" +
		"vector identifier — paired with smb2_decode + kerberos_decode + " +
		"ldap_decode + ntlm_decode this completes the AD-pentest dissector " +
		"quintet. BIND carries the interface UUID identifying the target " +
		"RPC interface; REQUEST carries the opnum identifying the specific " +
		"function. The combination is the canonical attack-chain " +
		"indicator. Key attack-vector interfaces flagged in the name " +
		"table: **NETLOGON** (12345678-1234-abcd-ef00-01234567cffb) + " +
		"opnum 30 = **ZeroLogon** CVE-2020-1472 (DC password reset); " +
		"**DRSUAPI** (e3514235-4b06-11d1-ab04-00c04fc2dcd2) + opnum 3 " +
		"DRSGetNCChanges = **DCSync** (extracts all AD password hashes " +
		"via mimikatz lsadump::dcsync + impacket secretsdump.py); " +
		"**SAMR** (12345778-1234-abcd-ef00-0123456789ab) = AD user/group " +
		"enumeration (net user /domain, enum4linux, rpcclient); " +
		"**LSARPC** (12345778-1234-abcd-ef00-0123456789ac) = LSA-policy + " +
		"SAM secrets dump (lsadump::secrets, lsadump::trust); **SVCCTL** " +
		"(367abb81-9844-35f1-ad32-98f038001003) = Service Control Manager " +
		"= **PsExec** lateral move (impacket psexec.py / smbexec.py); " +
		"**SPOOLSS** (12345678-1234-abcd-ef00-0123456789ab) + opnum 65 = " +
		"**PrintNightmare** CVE-2021-1675/34527 (SYSTEM RCE on print " +
		"spooler); **ATSVC** (1ff70682-0a51-30e8-076d-740be8cee98b) = " +
		"Task Scheduler lateral move; **EFS** (c681d488-d850-11d0-8c52-" +
		"00c04fd90f7e + df1941c5-fe89-4e79-bf10-463657acf44d) = " +
		"**PetitPotam** authentication coercion; **WKSSVC** + **SRVSVC** " +
		"= NetWkstaUserEnum + NetSessionEnum logged-on-users enumeration; " +
		"**EPMAPPER** (afa8bd80-7d8a-11c9-bef4-08002b102989) = RPC " +
		"portmap on TCP/135. Decodes:\n\n" +
		"- **16-byte common header** ([MS-RPCE] §2.2.6.1): rpc_vers (1) " +
		"= 5 / rpc_vers_minor (1) = 0 / PTYPE (1) / pfc_flags (1) / " +
		"drep[4] (data representation; drep[0] bit 4 = little-endian — " +
		"Windows is always LE on the wire) / frag_length (2) / " +
		"auth_length (2) / call_id (4).\n" +
		"- **14-entry PTYPE name table** (RFC 2237 / DCE 1.1 §12.1): " +
		"REQUEST=0 / PING=1 / RESPONSE=2 / FAULT=3 / WORKING=4 / NOCALL=5 " +
		"/ REJECT=6 / ACK=7 / CL_CANCEL=8 / FACK=9 / CANCEL_ACK=10 / " +
		"BIND=11 / BIND_ACK=12 / BIND_NAK=13 / ALTER_CONTEXT=14 / " +
		"ALTER_CONTEXT_RESP=15 / SHUTDOWN=16 / CO_CANCEL=17 / ORPHANED=18 " +
		"/ AUTH3=19.\n" +
		"- **6-entry pfc_flags name table**: 0x01 FIRST_FRAG / 0x02 " +
		"LAST_FRAG / 0x04 PENDING_CANCEL / 0x10 CONC_MPX / 0x20 " +
		"DID_NOT_EXECUTE / 0x80 OBJECT_UUID.\n" +
		"- **BIND / ALTER_CONTEXT body walker** (§2.2.6.4): " +
		"max_xmit_frag + max_recv_frag + assoc_group_id + " +
		"p_context_elem_count + first context element abstract_syntax " +
		"(UUID + version). Surfaces `interface_uuid` + `interface_name` " +
		"(canonical attack-vector identification!) + " +
		"`interface_version_major` + `interface_version_minor`.\n" +
		"- **20+ entry interface UUID name table** flagging well-known " +
		"interfaces with their canonical attack vectors.\n" +
		"- **REQUEST body walker** (§2.2.6.2): alloc_hint + p_cont_id + " +
		"opnum. Surfaces `alloc_hint` + `context_id` + `opnum` (the " +
		"function within the interface being called; combined with the " +
		"interface UUID = exact RPC function identifier).\n" +
		"- **FAULT body walker** (§2.2.6.6): alloc_hint + p_cont_id + " +
		"cancel_count + status. Surfaces `fault_status` + " +
		"`fault_status_name`.\n" +
		"- **9-entry NCA fault status name table** (DCE 1.1 §12.6.4.10 + " +
		"MS-RPCE §3.1.1.5.5): nca_s_fault_access_denied (0x00000005) / " +
		"nca_s_fault_addr_error / nca_s_fault_context_mismatch / " +
		"nca_s_fault_out_of_resources / nca_s_fault_unspec_reject / " +
		"nca_s_fault_invalid_pres_context_id / nca_s_fault_unsupported_" +
		"type / RPC_X_BAD_STUB_DATA (0x6BD) / RPC_S_SERVER_UNAVAILABLE " +
		"(0x6F7).\n\n" +
		"Pure offline parser — operators paste DCE/RPC bytes (the TCP-" +
		"segment payload as hex; default ports TCP/135 EPM + TCP/49152+ " +
		"ephemeral; OR the SMB2 named-pipe payload after smb2_decode " +
		"identifies the pipe) from a `tcpdump -X port 135` line or a " +
		"Wireshark DCE/RPC dissector view and get the documented per-" +
		"PTYPE breakdown.\n\n" +
		"Out of scope (deferred): NDR (Network Data Representation) " +
		"parameter marshalling (each per-interface IDL function takes " +
		"typed parameters marshalled via NDR — 1000+ Microsoft RPC " +
		"interfaces with 30+ opnums each; the decoder surfaces the opnum " +
		"but does NOT decode the parameters); DCOM ORPCTHIS / ORPCTHAT " +
		"(extra header onto DCE/RPC requests for the OXID/OID/IPID DCOM " +
		"addressing layer); connectionless DCE/RPC (UDP/135 — different " +
		"PTYPE values, rarely seen in modern Windows AD); sec_trailer " +
		"parsing (when auth_length > 0 the last auth_length+8 bytes carry " +
		"the auth trailer; surfaced as auth_length only; per-mechanism " +
		"NTLM / Kerberos / Negotiate auth_value decode handled by " +
		"ntlm_decode / kerberos_decode); interface-specific opnum name " +
		"tables (per-interface opnum-to-function name mapping is out of " +
		"scope — 1000+ interfaces with 30+ opnums each).\n\n" +
		"Source: docs/catalog/gap-analysis.md (Windows-protocol " +
		"foundational decoder — MS-RPC framing dissector that pairs with " +
		"smb2_decode + kerberos_decode + ldap_decode + ntlm_decode for " +
		"the complete AD-pentest dissector quintet; canonical decode for " +
		"every Windows AD attack-chain RPC; common in DEF CON + Black " +
		"Hat + HITB + OffSec internal red-team engagements + every " +
		"impacket / cme / mimikatz / rubeus / SharpHound-driven AD attack " +
		"workflow). Wrap-vs-native: native — DCE 1.1 + [MS-RPCE] are " +
		"publicly documented; the common header is a fixed-shape 16-byte " +
		"struct; byte-order flagged via drep[0] bit 4 (Windows always " +
		"LE); per-PTYPE body decoding for BIND / REQUEST / FAULT is " +
		"straightforward; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"DCE/RPC message bytes as hex (the TCP-segment payload; default ports TCP/135 EPM + TCP/49152+ ephemeral; OR the SMB2 named-pipe payload after smb2_decode identifies the pipe). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   dcerpcDecodeHandler,
}

func dcerpcDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("dcerpc_decode: 'hex' is required")
	}
	res, err := dcerpc.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("dcerpc_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
