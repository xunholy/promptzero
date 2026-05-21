// tds.go — host-side TDS (Microsoft SQL Server protocol) decoder
// Spec. Wraps the internal/tds walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/tds"
)

func init() { //nolint:gochecknoinits
	Register(tdsDecodeSpec)
}

var tdsDecodeSpec = Spec{
	Name: "tds_decode",
	Description: "Decode a TDS (Tabular Data Stream) packet per Microsoft Open " +
		"Specifications [MS-TDS] — the Microsoft SQL Server protocol. " +
		"Runs on TCP/1433 (default instance), TCP dynamic ports for " +
		"named instances (TCP/49152+ — discoverable via the SQL Server " +
		"Browser on UDP/1434), and tunneled inside SMB2 named pipes " +
		"(\\pipe\\sql\\query — rare modern deployments). The canonical " +
		"SQL Server pentest decoder; the wire format leaks: **cleartext " +
		"username via Login7** (TDS7_LOGIN packet Type=0x10 carries the " +
		"username UTF-16LE in the OffsetLength variable-data block — " +
		"canonical SQL-Server credential disclosure vector on TCP/1433 " +
		"without TLS); **obfuscated password via Login7** (password is " +
		"XOR-obfuscated with 0xA5 after nibble-swapping — trivially " +
		"deobfuscatable; decoder surfaces `password_bytes` LENGTH only, " +
		"privacy-preserving while flagging the simple-auth exposure); " +
		"**TLS-downgrade vulnerability via Pre-Login ENCRYPTION token** " +
		"(0x00 ENCRYPT_OFF / 0x01 ENCRYPT_ON / **0x02 ENCRYPT_NOT_SUP = " +
		"TLS-downgrade attack vector when client expected TLS!** / 0x03 " +
		"ENCRYPT_REQ = hardened; servers with NOT_SUP or OFF allow " +
		"cleartext Login7 password capture); **SQL Server version " +
		"disclosure** (Login7 TDSVersion field maps to SQL Server " +
		"release: 0x70000000 = 7.0 / 0x71000001 = 2000 SP1 / 0x72090002 " +
		"= 2005 / 0x730A0003 = 2008 / 0x730B0003 = 2008 R2 / 0x74000004 " +
		"= 2012/2014/2016/2017/2019/2022 — canonical version-fingerprint " +
		"for CVE selection); **database + AppName disclosure** (Login7 " +
		"OffsetLength block carries requested database name — master / " +
		"msdb / tempdb / custom — and application name — often " +
		"identifies client: Microsoft SQL Server Management Studio / " +
		".Net SqlClient Data Provider / SQLCMD / osql / sqlmap); " +
		"**brute-force feedback via TABULAR_RESULT ERROR token** (failed " +
		"Login7 returns TABULAR_RESULT packet Type=0x04 with ERROR token " +
		"0xAA + error code 18456 — \"Login failed for user '...'\"); " +
		"**named-instance hostnames via Login7 ServerName** (the actual " +
		"named instance the client connected to). Decodes:\n\n" +
		"- **8-byte packet header** ([MS-TDS] §2.2.3.1): `Type` / " +
		"`Status` / `Length` (BE — total packet length incl header) / " +
		"`SPID` (BE) / `PacketID` / `Window`.\n" +
		"- **12-entry packet type name table** (§2.2.3.1.1): 0x01 " +
		"SQL_BATCH / 0x02 PRE_TDS7_LOGIN (legacy) / 0x03 RPC / 0x04 " +
		"TABULAR_RESULT (server → client) / 0x06 ATTENTION (client → " +
		"cancel) / 0x07 BULK_LOAD_DATA / 0x0E TRANSACTION_MANAGER / " +
		"0x10 TDS7_LOGIN (Login7!) / 0x11 SSPI / 0x12 PRE_LOGIN / " +
		"0x13 FEDERATED_AUTH_TOKEN.\n" +
		"- **5-entry Status flags name table** (§2.2.3.1.2): 0x01 EOM " +
		"(End-Of-Message — packet is last in stream) / 0x02 IGNORE / " +
		"0x04 EVENT_NOTIFICATION / 0x08 RESETCONNECTION / 0x10 " +
		"RESETCONNECTIONSKIPTRAN.\n" +
		"- **Pre-Login token walker** (§2.2.6.5): TLV-style table — " +
		"TokenType(1) + TokenOffset(2 BE) + TokenLength(2 BE) — " +
		"terminated by 0xFF. Surfaces each token's type + name + " +
		"offset + length; for the ENCRYPTION token (0x01) extracts the " +
		"1-byte value and surfaces `encryption_mode` + " +
		"`encryption_mode_name`.\n" +
		"- **8-entry Pre-Login token-type name table** (§2.2.6.5): 0x00 " +
		"VERSION / 0x01 ENCRYPTION / 0x02 INSTOPT / 0x03 THREADID / " +
		"0x04 MARS (Multiple Active Result Sets) / 0x05 TRACEID / 0x06 " +
		"FEDAUTHREQUIRED / 0x07 NONCEOPT.\n" +
		"- **4-entry ENCRYPTION mode name table** (§2.2.6.5): 0x00 " +
		"ENCRYPT_OFF / 0x01 ENCRYPT_ON / 0x02 ENCRYPT_NOT_SUP (TLS-" +
		"downgrade vulnerable!) / 0x03 ENCRYPT_REQ (hardened).\n" +
		"- **Login7 body walker** (§2.2.6.4): Length + TDSVersion + " +
		"PacketSize + OffsetLength block (10 offset/length entries — " +
		"HostName, UserName, Password, AppName, ServerName, Extension, " +
		"CltIntName, Language, Database, SSPI). Surfaces `host_name` + " +
		"`user_name` (cleartext!) + `password_bytes` (LENGTH only) + " +
		"`app_name` + `server_name` + `database` as UTF-16LE-decoded " +
		"strings.\n" +
		"- **6-entry TDS version name table** mapping `TDSVersion` to " +
		"SQL Server release.\n\n" +
		"Pure offline parser — operators paste TDS bytes (the TCP-" +
		"segment payload as hex; default TCP/1433 + dynamic TCP/49152+ " +
		"for named instances) from a `tcpdump -X port 1433` line or a " +
		"Wireshark TDS dissector view and get the documented per-type " +
		"breakdown.\n\n" +
		"Out of scope (deferred): TABULAR_RESULT token-stream parsing " +
		"(server responses are token-stream payloads with 30+ token " +
		"types — LOGINACK / ERROR / INFO / DONE / ROW / COLMETADATA / " +
		"COLINFO / RETURNVALUE / ORDER / SESSIONSTATE; each its own " +
		"nested TLV format; decoder surfaces packet type only); SSPI " +
		"inner blob (Type=0x11 carries SPNEGO-wrapped NTLM or Kerberos " +
		"blob — handled by `ntlm_decode` + `kerberos_decode`); TLS / " +
		"TDS encryption handshake (after Pre-Login agrees ENCRYPT_ON or " +
		"ENCRYPT_REQ, connection upgrades to TLS — handle TLS strip " +
		"first); Federated Authentication Token (Type=0x13) — Azure AD " +
		"/ Microsoft Entra ID JWT-style; RPC parameter marshalling " +
		"(Type=0x03 — surfaces packet type only); BULK LOAD DATA / " +
		"TRANSACTION MANAGER / ATTENTION bodies; **password " +
		"deobfuscation** (decoder deliberately does NOT deobfuscate — " +
		"`password_bytes` field surfaces length only to flag exposure " +
		"without leaking the credential); SQL Server Browser UDP/1434 " +
		"named-instance enumeration ([MS-SQLR] — separate protocol).\n\n" +
		"Source: docs/catalog/gap-analysis.md (database-protocol " +
		"foundational decoder — the canonical SQL Server pentest " +
		"dissector for credential capture + TLS-downgrade audit + " +
		"version fingerprint + database enumeration; pairs with the AD-" +
		"pentest quintet for the complete Microsoft-stack pentest " +
		"surface; common in DEF CON + Black Hat + HITB + OffSec " +
		"engagements + every sqlmap / impacket-mssqlclient / " +
		"powerupsql-driven SQL Server attack workflow). Wrap-vs-native: " +
		"native — [MS-TDS] is publicly documented; the 8-byte packet " +
		"header is a fixed struct; Pre-Login is a simple TLV walker; " +
		"Login7 OffsetLength table is a deterministic block at fixed " +
		"offsets; Tabular Result token-stream parsing (30+ token types) " +
		"is out of scope; no crypto at the parse layer; password " +
		"deobfuscation deliberately omitted.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"TDS packet bytes as hex (the TCP-segment payload; default TCP/1433 + dynamic TCP/49152+ for named instances). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   tdsDecodeHandler,
}

func tdsDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("tds_decode: 'hex' is required")
	}
	res, err := tds.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("tds_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
