// Package tds decodes TDS (Tabular Data Stream) messages per
// Microsoft Open Specifications [MS-TDS] — the Microsoft SQL
// Server protocol. Runs on TCP/1433 (default instance), TCP
// dynamic ports for named instances (TCP/49152+ — discoverable
// via the SQL Server Browser on UDP/1434), and tunneled inside
// SMB2 named pipes (\pipe\sql\query — rare modern deployments).
//
// Operationally, TDS is the **canonical SQL Server pentest
// decoder**. The wire format leaks:
//
//   - **Cleartext username via Login7** — TDS7_LOGIN packet
//     (Type=0x10 in TDS 7.4 — note: clash with SSPI in some
//     captures; the canonical Login7 type is `0x10` in TDS
//     7.0/7.1/7.2/7.3/7.4 per [MS-TDS] §2.2.6.4) carries
//     the username as UTF-16LE OCTET STRING in the
//     OffsetLength variable-data block. Surfaced as
//     `username` cleartext. The canonical SQL-Server
//     credential disclosure vector on TCP/1433 without TLS.
//
//   - **Obfuscated password via Login7** — the password is
//     XOR-obfuscated with `0xA5` after nibble-swapping each
//     byte: `obfuscated = byte_swap_nibbles(plaintext) XOR
//     0xA5`. The deobfuscation algorithm is trivial and
//     publicly documented; nevertheless the decoder
//     **surfaces `password_bytes` length ONLY**, not the
//     deobfuscated password (privacy-preserving while
//     flagging the simple-auth exposure).
//
//   - **TLS-downgrade vulnerability via Pre-Login
//     ENCRYPTION token** — the Pre-Login packet's
//     `ENCRYPTION` token (0x01) carries a one-byte
//     encryption capability: `0x00 ENCRYPT_OFF` (client/
//     server doesn't want encryption — STARTTLS will not
//     be negotiated), `0x01 ENCRYPT_ON` (encryption
//     possible, will be used after Login7),
//     `0x02 ENCRYPT_NOT_SUP` (encryption not available —
//     **TLS-downgrade attack vector if client expected
//     TLS!**), `0x03 ENCRYPT_REQ` (encryption mandatory —
//     hardened). Servers responding with `NOT_SUP` or
//     `OFF` allow cleartext Login7 password capture.
//
//   - **SQL Server version disclosure via Pre-Login VERSION
//     token + Login7 TDSVersion field** — every connection
//     reveals the server build (1-byte major + 1-byte
//     minor + 2-byte build BE). The `TDSVersion` field in
//     Login7 (0x71000001 SQL 2000 SP1, 0x72090002 SQL
//     2005, 0x730A0003 SQL 2008, 0x730B0003 SQL 2008 R2,
//     0x74000004 SQL 2012/2014/2016/2017/2019/2022) is
//     the canonical version-fingerprint for CVE selection.
//
//   - **Database name + AppName disclosure via Login7** —
//     OffsetLength block carries the requested database
//     name (the AD attack target — `master`, `msdb`,
//     `tempdb`, or a custom database) and the application
//     name (often identifies the client tool: `Microsoft
//     SQL Server Management Studio`, `.Net SqlClient Data
//     Provider`, `SQLCMD`, `osql`, `sqlmap`).
//
//   - **Brute-force feedback via TABULAR_RESULT ERROR
//     token** — failed Login7 returns a TABULAR_RESULT
//     packet (Type=0x04) containing an `ERROR` token
//     (0xAA) with error code 18456 ("Login failed for
//     user '...'") — the canonical SQL Server wrong-
//     password response that password-spray tools consume.
//     ERROR token parsing is out of scope here (its own
//     nested TLV format) but the packet type is surfaced.
//
//   - **Named-instance enumeration via SQL Server Browser
//     (UDP/1434)** — out of scope for this decoder (UDP/
//     1434 uses a separate request/response protocol per
//     [MS-SQLR]), but TCP/1433 + named-instance hostnames
//     surfaced from Login7 ServerName tell you the
//     enumeration was performed.
//
// Wrap-vs-native judgement
//
//	Native. [MS-TDS] is publicly documented; the 8-byte
//	packet header is a fixed struct with type + status
//	flags. Pre-Login is a simple TLV-style token walker.
//	Login7 OffsetLength table is a deterministic 5-field
//	block at fixed offsets. Tabular Result token-stream
//	parsing (LOGINACK / ERROR / INFO / DONE / ROW /
//	COLMETADATA / COLINFO — 30+ token types each with
//	its own nested TLV format) is out of scope. SSPI
//	inner blob, TLS encryption handshake, RPC parameter
//	marshalling, and bulk load data are out of scope.
//
// What this package covers
//
//   - **8-byte packet header** ([MS-TDS] §2.2.3.1):
//     `Type` (1) / `Status` (1) / `Length` (2 BE — total
//     packet length including header) / `SPID` (2 BE) /
//     `PacketID` (1 — fragmented-packet sequence) /
//     `Window` (1).
//
//   - **12-entry packet type name table** (§2.2.3.1.1):
//     `0x01` SQL_BATCH / `0x02` PRE_TDS7_LOGIN (legacy) /
//     `0x03` RPC / `0x04` TABULAR_RESULT (server →
//     client) / `0x06` ATTENTION (client → cancel) /
//     `0x07` BULK_LOAD_DATA / `0x0E` TRANSACTION_MANAGER
//     / `0x10` TDS7_LOGIN (Login7!) / `0x11` SSPI /
//     `0x12` PRE_LOGIN / `0x13` FEDERATED_AUTH_TOKEN.
//
//   - **5-entry Status flags name table** (§2.2.3.1.2):
//     `0x01` EOM (End-Of-Message — packet is last in
//     stream) / `0x02` IGNORE (server should ignore this
//     packet) / `0x04` EVENT_NOTIFICATION / `0x08`
//     RESETCONNECTION / `0x10` RESETCONNECTIONSKIPTRAN.
//
//   - **Pre-Login token walker** (§2.2.6.5): walks a
//     TLV-style token table — TokenType (1) / TokenOffset
//     (2 BE) / TokenLength (2 BE) — terminated by a
//     0xFF TERMINATOR. Surfaces each token's type +
//     name + offset + length. For the ENCRYPTION token
//     (0x01), extracts the 1-byte value and surfaces
//     `encryption_mode` + `encryption_mode_name`.
//
//   - **8-entry Pre-Login token-type name table**
//     (§2.2.6.5): `0x00` VERSION / `0x01` ENCRYPTION /
//     `0x02` INSTOPT / `0x03` THREADID / `0x04` MARS
//     (Multiple Active Result Sets) / `0x05` TRACEID /
//     `0x06` FEDAUTHREQUIRED / `0x07` NONCEOPT.
//
//   - **4-entry ENCRYPTION mode name table** (§2.2.6.5):
//     `0x00` ENCRYPT_OFF / `0x01` ENCRYPT_ON / `0x02`
//     ENCRYPT_NOT_SUP (TLS-downgrade vulnerable!) /
//     `0x03` ENCRYPT_REQ (hardened).
//
//   - **Login7 body walker** (§2.2.6.4): Length (4 LE) /
//     TDSVersion (4 LE) / PacketSize (4 LE) /
//     ClientProgVer (4 LE) / ClientPID (4 LE) /
//     ConnectionID (4 LE) / OptionFlags1/2/3 (3) /
//     TypeFlags (1) / ClientTimeZone (4 LE) / ClientLCID
//     (4 LE) / OffsetLength block (5×4-byte
//     offset+length entries for HostName, UserName,
//     Password, AppName, ServerName, Extension, CltIntName,
//     Language, Database, SSPI; the decoder surfaces
//     HostName / UserName / AppName / ServerName /
//     Database as UTF-16LE-decoded strings and Password
//     length only).
//
//   - **6-entry TDS version name table** mapping
//     `TDSVersion` to SQL Server release: `0x70000000`
//     SQL Server 7.0 / `0x71000001` SQL Server 2000 SP1 /
//     `0x72090002` SQL Server 2005 / `0x730A0003` SQL
//     Server 2008 / `0x730B0003` SQL Server 2008 R2 /
//     `0x74000004` SQL Server 2012 / 2014 / 2016 / 2017 /
//     2019 / 2022.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **TABULAR_RESULT token-stream parsing** — server
//     responses are token-stream payloads with 30+ token
//     types (LOGINACK / ERROR / INFO / DONE / ROW /
//     COLMETADATA / COLINFO / RETURNVALUE / ORDER /
//     SESSIONSTATE / etc.). Each token has its own
//     nested TLV format. The decoder surfaces the packet
//     type but does NOT decode the inner tokens.
//   - **SSPI inner blob** — SSPI packet (Type=0x11)
//     carries an SPNEGO-wrapped NTLM or Kerberos blob;
//     already handled by `ntlm_decode` and
//     `kerberos_decode`.
//   - **TLS / TDS encryption handshake** — after
//     Pre-Login agrees ENCRYPT_ON or ENCRYPT_REQ, the
//     connection upgrades to TLS; subsequent TDS packets
//     ride inside the TLS record layer. Handle TLS strip
//     first.
//   - **Federated Authentication Token** (Type=0x13) —
//     Azure AD / Microsoft Entra ID JWT-style federated
//     authentication; out of scope.
//   - **RPC parameter marshalling** — RPC packet
//     (Type=0x03) carries IDL-marshalled parameters; the
//     decoder surfaces the packet type only.
//   - **Bulk load data** (Type=0x07), **TRANSACTION
//     MANAGER** request types (Type=0x0E), **ATTENTION**
//     (Type=0x06) bodies are not decoded.
//   - **Password deobfuscation** — Login7 password is
//     XOR-obfuscated with 0xA5 after nibble-swapping;
//     deobfuscation is trivial but the decoder
//     **deliberately does not perform it**. The
//     `password_bytes` field surfaces the length only —
//     enough to flag the auth exposure without leaking
//     the credential.
package tds

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf16"
)

const headerSize = 8

// Result is the structured decode of a TDS packet.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	Type        int      `json:"type"`
	TypeName    string   `json:"type_name"`
	Status      int      `json:"status"`
	StatusNames []string `json:"status_names,omitempty"`
	Length      int      `json:"length"`
	SPID        int      `json:"spid"`
	PacketID    int      `json:"packet_id"`
	Window      int      `json:"window"`

	// Pre-Login tokens
	PreLoginTokens     []PreLoginToken `json:"prelogin_tokens,omitempty"`
	EncryptionMode     int             `json:"encryption_mode,omitempty"`
	EncryptionModeName string          `json:"encryption_mode_name,omitempty"`

	// Login7
	TDSVersion     uint32 `json:"tds_version,omitempty"`
	TDSVersionName string `json:"tds_version_name,omitempty"`
	HostName       string `json:"host_name,omitempty"`
	UserName       string `json:"user_name,omitempty"`
	PasswordBytes  int    `json:"password_bytes,omitempty"`
	AppName        string `json:"app_name,omitempty"`
	ServerName     string `json:"server_name,omitempty"`
	Database       string `json:"database,omitempty"`
}

// PreLoginToken describes a single Pre-Login token.
type PreLoginToken struct {
	Type     int    `json:"type"`
	TypeName string `json:"type_name"`
	Offset   int    `json:"offset"`
	Length   int    `json:"length"`
}

// Decode parses a TDS packet from a hex string.
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
		return nil, fmt.Errorf("tds packet truncated (%d bytes; need 8)", len(b))
	}

	r := &Result{TotalBytes: len(b)}

	r.Type = int(b[0])
	r.TypeName = typeName(r.Type)
	r.Status = int(b[1])
	r.StatusNames = statusFlagsNames(b[1])
	r.Length = int(binary.BigEndian.Uint16(b[2:4]))
	r.SPID = int(binary.BigEndian.Uint16(b[4:6]))
	r.PacketID = int(b[6])
	r.Window = int(b[7])

	body := b[headerSize:]
	switch r.Type {
	case 0x12:
		decodePreLogin(r, body)
	case 0x10:
		decodeLogin7(r, body)
	}
	return r, nil
}

// decodePreLogin walks the TLV-style token table terminated
// by 0xFF.
func decodePreLogin(r *Result, body []byte) {
	off := 0
	for off < len(body) {
		t := body[off]
		if t == 0xFF {
			break
		}
		if off+5 > len(body) {
			return
		}
		tokOff := int(binary.BigEndian.Uint16(body[off+1 : off+3]))
		tokLen := int(binary.BigEndian.Uint16(body[off+3 : off+5]))
		r.PreLoginTokens = append(r.PreLoginTokens, PreLoginToken{
			Type:     int(t),
			TypeName: preLoginTokenName(int(t)),
			Offset:   tokOff,
			Length:   tokLen,
		})
		// ENCRYPTION token value
		if t == 0x01 && tokOff+1 <= len(body) && tokLen >= 1 {
			r.EncryptionMode = int(body[tokOff])
			r.EncryptionModeName = encryptionModeName(r.EncryptionMode)
		}
		off += 5
	}
}

// decodeLogin7 walks the Login7 fixed-field header + the
// OffsetLength variable-data block.
func decodeLogin7(r *Result, body []byte) {
	if len(body) < 94 {
		return
	}
	r.TDSVersion = binary.LittleEndian.Uint32(body[4:8])
	r.TDSVersionName = tdsVersionName(r.TDSVersion)
	// OffsetLength block starts at body[36]:
	//   each entry is offset(2 LE) + length(2 LE), 10 entries
	type ol struct{ off, length int }
	read := func(idx int) ol {
		base := 36 + idx*4
		return ol{
			off:    int(binary.LittleEndian.Uint16(body[base : base+2])),
			length: int(binary.LittleEndian.Uint16(body[base+2 : base+4])),
		}
	}
	host := read(0)
	user := read(1)
	pass := read(2)
	app := read(3)
	srv := read(4)
	_ = read(5)
	_ = read(6)
	_ = read(7)
	db := read(8)
	// Variable data lives at body[<offset>] with length-in-chars
	// (UTF-16LE units of 2 bytes each).
	r.HostName = readUTF16(body, host.off, host.length)
	r.UserName = readUTF16(body, user.off, user.length)
	r.PasswordBytes = pass.length * 2
	r.AppName = readUTF16(body, app.off, app.length)
	r.ServerName = readUTF16(body, srv.off, srv.length)
	r.Database = readUTF16(body, db.off, db.length)
}

func readUTF16(b []byte, off, lenChars int) string {
	if lenChars == 0 || off >= len(b) {
		return ""
	}
	end := off + lenChars*2
	if end > len(b) {
		end = len(b)
	}
	src := b[off:end]
	if len(src)%2 != 0 {
		src = src[:len(src)-1]
	}
	u16 := make([]uint16, 0, len(src)/2)
	for i := 0; i < len(src); i += 2 {
		u16 = append(u16, binary.LittleEndian.Uint16(src[i:i+2]))
	}
	return string(utf16.Decode(u16))
}

func typeName(t int) string {
	switch t {
	case 0x01:
		return "SQL_BATCH"
	case 0x02:
		return "PRE_TDS7_LOGIN"
	case 0x03:
		return "RPC"
	case 0x04:
		return "TABULAR_RESULT"
	case 0x06:
		return "ATTENTION"
	case 0x07:
		return "BULK_LOAD_DATA"
	case 0x0E:
		return "TRANSACTION_MANAGER"
	case 0x10:
		return "TDS7_LOGIN"
	case 0x11:
		return "SSPI"
	case 0x12:
		return "PRE_LOGIN"
	case 0x13:
		return "FEDERATED_AUTH_TOKEN"
	}
	return fmt.Sprintf("uncatalogued type 0x%02X", t)
}

func statusFlagsNames(f byte) []string {
	var names []string
	if f&0x01 != 0 {
		names = append(names, "EOM")
	}
	if f&0x02 != 0 {
		names = append(names, "IGNORE")
	}
	if f&0x04 != 0 {
		names = append(names, "EVENT_NOTIFICATION")
	}
	if f&0x08 != 0 {
		names = append(names, "RESETCONNECTION")
	}
	if f&0x10 != 0 {
		names = append(names, "RESETCONNECTIONSKIPTRAN")
	}
	return names
}

func preLoginTokenName(t int) string {
	switch t {
	case 0x00:
		return "VERSION"
	case 0x01:
		return "ENCRYPTION"
	case 0x02:
		return "INSTOPT"
	case 0x03:
		return "THREADID"
	case 0x04:
		return "MARS"
	case 0x05:
		return "TRACEID"
	case 0x06:
		return "FEDAUTHREQUIRED"
	case 0x07:
		return "NONCEOPT"
	}
	return fmt.Sprintf("uncatalogued pre-login token 0x%02X", t)
}

func encryptionModeName(m int) string {
	switch m {
	case 0x00:
		return "ENCRYPT_OFF"
	case 0x01:
		return "ENCRYPT_ON"
	case 0x02:
		return "ENCRYPT_NOT_SUP (TLS-downgrade vulnerable!)"
	case 0x03:
		return "ENCRYPT_REQ (hardened)"
	}
	return fmt.Sprintf("uncatalogued encryption mode 0x%02X", m)
}

func tdsVersionName(v uint32) string {
	switch v {
	case 0x70000000:
		return "SQL Server 7.0"
	case 0x71000001:
		return "SQL Server 2000 SP1"
	case 0x72090002:
		return "SQL Server 2005"
	case 0x730A0003:
		return "SQL Server 2008"
	case 0x730B0003:
		return "SQL Server 2008 R2"
	case 0x74000004:
		return "SQL Server 2012/2014/2016/2017/2019/2022"
	}
	return fmt.Sprintf("uncatalogued TDS version 0x%08X", v)
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
