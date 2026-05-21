// Package postgres decodes PostgreSQL frontend / backend
// protocol v3 messages per the PostgreSQL documentation
// (Part VIII: "Frontend/Backend Protocol"). Runs on TCP/5432
// default; alternate ports are common in container deployments
// but the wire format is identical.
//
// Operationally, PostgreSQL is the **second-largest open-source
// database pentest target after MySQL**, deployed everywhere
// from cloud-managed Postgres (RDS / Aurora / Cloud SQL /
// Crunchy / Supabase / Neon / Timescale Cloud) to bare-metal
// installations to containerized side-cars. The wire format
// leaks:
//
//   - **Cleartext username + database via StartupMessage** —
//     the first message after TCP connect (no type byte) is a
//     StartupMessage containing a sequence of null-terminated
//     `key\0value\0` pairs. The `user` and `database` keys
//     are sent in cleartext (UTF-8) — the canonical PostgreSQL
//     credential disclosure on TCP/5432 without TLS. Common
//     keys: `user`, `database`, `application_name` (often
//     identifies the client: `psql`, `pgAdmin 4`, `DBeaver`,
//     `pgcli`, `node-postgres`, `sqlmap`), `client_encoding`,
//     `options`, `replication` (`true` indicates a streaming
//     replication connection — the canonical "I want to copy
//     all your data" connection).
//
//   - **Authentication method enumeration via
//     AuthenticationRequest** — the server's response to
//     StartupMessage is a single `R` message carrying a
//     4-byte sub-type that tells the client which auth method
//     to use. The sub-type values reveal the server's
//     authentication policy:
//
//   - `0` AuthenticationOk — authenticated already (typical
//     for `trust` auth method — **NO AUTHENTICATION
//     REQUIRED**, the canonical Postgres misconfiguration).
//
//   - `2` KerberosV5 — legacy.
//
//   - `3` CleartextPassword — **MITM-capturable!** Server
//     wants the password in cleartext over the wire
//     (typically used when SSL is required at a different
//     layer, or for `password` auth method).
//
//   - `5` MD5Password — **offline-crackable via hashcat
//     mode 12**; the server sends a 4-byte salt, the client
//     responds with `md5(md5(password||username)||salt)`.
//
//   - `7` GSS — GSSAPI (Kerberos) negotiate.
//
//   - `8` GSSContinue — GSSAPI continuation.
//
//   - `9` SSPI — Windows SSPI negotiate.
//
//   - `10` SASL — SASL negotiation, typically SCRAM-SHA-256
//     (modern Postgres default since v10).
//
//   - `11` SASLContinue / `12` SASLFinal — SCRAM exchange
//     continuation.
//
//   - **Brute-force feedback via ErrorResponse SQLSTATE** —
//     failed authentication returns an `E` (ErrorResponse)
//     message with a series of field-tag-prefixed null-
//     terminated strings. The `C` (SQLSTATE) field carries
//     a 5-character code; key codes for pentest feedback:
//
//   - `28P01` `invalid_password` — canonical wrong-password
//     response; password-spray tools consume this directly.
//
//   - `28000` `invalid_authorization_specification` — auth
//     mechanism mismatch (no matching `pg_hba.conf` entry).
//
//   - `3D000` `invalid_catalog_name` — database doesn't
//     exist (database enumeration feedback).
//
//   - `42501` `insufficient_privilege` — authenticated but
//     not authorized.
//
//   - `42P01` `undefined_table` — table doesn't exist
//     (post-auth enumeration feedback).
//
//   - `53300` `too_many_connections` — DoS detection
//     signal.
//
//   - `57P03` `cannot_connect_now` — server in shutdown /
//     recovery.
//
//   - **PostgreSQL version disclosure via ParameterStatus** —
//     after AuthenticationOk, the server emits a series of
//     `S` (ParameterStatus) messages carrying GUC parameters:
//     `server_version` (canonical version-fingerprint for
//     CVE selection — `15.4`, `16.1`, `17.2`), `server_encoding`,
//     `client_encoding`, `application_name`, `is_superuser`,
//     `session_authorization`, `DateStyle`, `IntervalStyle`,
//     `TimeZone`, `integer_datetimes`, `standard_conforming
//     _strings`. The decoder surfaces all observed
//     ParameterStatus key/value pairs.
//
//   - **SSL / GSS pre-handshake** — the SSLRequest magic
//     (length=8 + payload=0x04D2162F = 80877103) and
//     GSSENCRequest magic (length=8 + payload=0x04D21630 =
//     80877104) are sent BEFORE StartupMessage to probe
//     whether the server supports TLS / GSSAPI encryption.
//     The server replies with a single byte: `S` (accept) /
//     `N` (decline); on `S` the client upgrades to TLS via
//     the standard TLS handshake. The decoder surfaces
//     `is_ssl_request` / `is_gss_request` / `is_cancel_request`
//     boolean classifications.
//
// Wrap-vs-native judgement
//
//	Native. The PostgreSQL frontend/backend protocol is
//	publicly documented (PostgreSQL Part VIII). The message
//	format is a simple type+length+body frame (with a
//	startup-message exception). StartupMessage parameters
//	are null-terminated key/value pairs.
//	AuthenticationRequest / ErrorResponse / ParameterStatus
//	bodies are simple TLV walks. Bind / Parse parameter
//	marshalling, RowDescription type-OID parsing, extended
//	query protocol multi-message flow, COPY streaming, TLS
//	handshake, and SASL inner-mechanism decode are out of
//	scope.
//
// What this package covers
//
//   - **Type+Length+Body frame parsing**: Type (1 byte) +
//     Length (4 BE, includes self) + Body. Startup messages
//     (StartupMessage / SSLRequest / GSSENCRequest /
//     CancelRequest) have NO type byte and are discriminated
//     by Length + ProtocolVersion magic.
//
//   - **3-entry pre-startup magic name table**: `0x04D2162F`
//     SSLRequest / `0x04D21630` GSSENCRequest / `0x04D21631`
//     CancelRequest.
//
//   - **15-entry frontend message type name table**: `B`
//     Bind / `C` Close / `d` CopyData / `c` CopyDone / `f`
//     CopyFail / `D` Describe / `E` Execute / `F`
//     FunctionCall / `H` Flush / `P` Parse / `p`
//     PasswordMessage / `Q` Query / `S` Sync / `X`
//     Terminate.
//
//   - **24-entry backend message type name table**: `R`
//     Authentication / `K` BackendKeyData / `2`
//     BindComplete / `3` CloseComplete / `C`
//     CommandComplete / `G` CopyInResponse / `H`
//     CopyOutResponse / `W` CopyBothResponse / `D` DataRow
//     / `I` EmptyQueryResponse / `E` ErrorResponse / `V`
//     FunctionCallResponse / `v` NegotiateProtocolVersion /
//     `n` NoData / `N` NoticeResponse / `A`
//     NotificationResponse / `t` ParameterDescription / `S`
//     ParameterStatus / `1` ParseComplete / `s`
//     PortalSuspended / `Z` ReadyForQuery / `T`
//     RowDescription.
//
//   - **StartupMessage body walker**: ProtocolVersion (4
//     BE) + sequence of null-terminated key/value strings
//     terminated by an extra null byte. Surfaces all
//     observed key/value pairs as `startup_params` map plus
//     the canonical `user` / `database` / `application_name`
//     / `client_encoding` keys as top-level fields.
//
//   - **AuthenticationRequest body walker**: first 4 BE
//     bytes are the sub-type. Surfaces `auth_subtype` +
//     `auth_subtype_name`.
//
//   - **11-entry AuthenticationRequest sub-type name table**:
//     0 `AuthenticationOk` (trust auth — no password!) / 2
//     `KerberosV5` / 3 `CleartextPassword` (MITM-capturable!)
//     / 5 `MD5Password` (offline-crackable hashcat mode 12) /
//     7 `GSS` / 8 `GSSContinue` / 9 `SSPI` / 10 `SASL` (SCRAM-
//     SHA-256 — modern hardened) / 11 `SASLContinue` / 12
//     `SASLFinal`.
//
//   - **ErrorResponse / NoticeResponse body walker**: TLV-
//     style (1-byte field tag + null-terminated value),
//     terminated by 0-byte tag. Surfaces all observed
//     field tags as `error_fields` map.
//
//   - **18-entry ErrorResponse field-tag name table** (per
//     PostgreSQL documentation §52.8): `S` Severity (localized)
//     / `V` Severity (non-localized) / `C` SQLSTATE code /
//     `M` Message / `D` Detail / `H` Hint / `P` Position
//     (character offset) / `p` InternalPosition / `q`
//     InternalQuery / `W` Where / `s` Schema / `t` Table /
//     `c` Column / `d` DataType / `n` Constraint / `F` File
//     / `L` Line / `R` Routine.
//
//   - **8+ entry canonical SQLSTATE name table**: `28P01`
//     `invalid_password` (canonical brute-force feedback!) /
//     `28000` `invalid_authorization_specification` / `3D000`
//     `invalid_catalog_name` (database enumeration feedback)
//     / `42501` `insufficient_privilege` / `42P01`
//     `undefined_table` (post-auth enumeration feedback) /
//     `53300` `too_many_connections` (DoS signal) / `57P03`
//     `cannot_connect_now` (server shutdown/recovery) /
//     `00000` `successful_completion`.
//
//   - **ParameterStatus body walker**: two null-terminated
//     strings (parameter name + value). Surfaces all
//     observed parameters; canonical pentest-interesting:
//     `server_version` (CVE-selection fingerprint),
//     `is_superuser`, `session_authorization`.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Bind / Parse parameter marshalling** — Bind carries
//     N parameter values with per-parameter format codes
//     (text/binary) and length-prefixed binary blobs. Each
//     binary parameter is typed via the prior Parse message's
//     type OID list. Out of scope here.
//   - **RowDescription type-OID parsing** — RowDescription
//     enumerates result columns with type OID + type modifier
//   - format code; mapping type OIDs to PostgreSQL type
//     names (1700+ system catalogue OIDs) is out of scope.
//   - **DataRow body parsing** — DataRow carries N column
//     values; each is either NULL (length=-1) or
//     length-prefixed binary. Out of scope.
//   - **Extended query protocol multi-message flow** — Parse
//     / Bind / Describe / Execute / Sync form a multi-
//     message exchange; the decoder reports each individually
//     but does not track exchange state.
//   - **COPY streaming** — CopyInResponse + CopyData +
//     CopyDone / CopyFail carry raw COPY data (typically
//     CSV or PostgreSQL binary format); out of scope.
//   - **TLS / GSSAPI encryption handshake** — after
//     SSLRequest + `S` reply, the connection upgrades to
//     TLS; subsequent PostgreSQL messages ride inside the
//     TLS record layer. Handle TLS strip first.
//   - **SASL inner-mechanism decode** — for SASL auth_subtype
//     10 / 11 / 12, the SCRAM-SHA-256 client-first / server-
//     first / client-final / server-final messages are
//     base64-blob payloads in the auth body; per-step SCRAM
//     decode is out of scope.
//   - **NOTIFY / LISTEN payload semantics** —
//     NotificationResponse (`A`) carries a channel name + a
//     payload string; the channel namespace is application-
//     defined.
package postgres

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the structured decode of a PostgreSQL message.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// Pre-startup magic classification
	IsSSLRequest    bool `json:"is_ssl_request"`
	IsGSSRequest    bool `json:"is_gss_request"`
	IsCancelRequest bool `json:"is_cancel_request"`

	MessageType     string `json:"message_type,omitempty"`
	MessageTypeName string `json:"message_type_name,omitempty"`
	Direction       string `json:"direction,omitempty"`
	Length          int    `json:"length"`

	// StartupMessage
	ProtocolVersionMajor int               `json:"protocol_version_major,omitempty"`
	ProtocolVersionMinor int               `json:"protocol_version_minor,omitempty"`
	StartupParams        map[string]string `json:"startup_params,omitempty"`
	User                 string            `json:"user,omitempty"`
	Database             string            `json:"database,omitempty"`
	ApplicationName      string            `json:"application_name,omitempty"`
	ClientEncoding       string            `json:"client_encoding,omitempty"`

	// AuthenticationRequest
	AuthSubtype     int    `json:"auth_subtype,omitempty"`
	AuthSubtypeName string `json:"auth_subtype_name,omitempty"`

	// ErrorResponse / NoticeResponse
	ErrorFields   map[string]string `json:"error_fields,omitempty"`
	SQLState      string            `json:"sqlstate,omitempty"`
	SQLStateName  string            `json:"sqlstate_name,omitempty"`
	ErrorSeverity string            `json:"error_severity,omitempty"`
	ErrorMessage  string            `json:"error_message,omitempty"`

	// ParameterStatus
	ParameterName  string `json:"parameter_name,omitempty"`
	ParameterValue string `json:"parameter_value,omitempty"`
}

// Decode parses a PostgreSQL message from a hex string.
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
	if len(b) < 4 {
		return nil, fmt.Errorf("postgres message truncated (%d bytes)", len(b))
	}

	r := &Result{TotalBytes: len(b)}

	// Pre-startup magic classification (no type byte): the
	// canonical shapes are length=8 + 4-byte magic for SSL /
	// GSSENC and length=16 + 4-byte magic + 8 bytes for
	// CancelRequest.
	if len(b) >= 8 {
		l := binary.BigEndian.Uint32(b[0:4])
		magic := binary.BigEndian.Uint32(b[4:8])
		switch {
		case l == 8 && magic == 0x04D2162F:
			r.IsSSLRequest = true
			r.Length = 8
			return r, nil
		case l == 8 && magic == 0x04D21630:
			r.IsGSSRequest = true
			r.Length = 8
			return r, nil
		case l == 16 && magic == 0x04D21631:
			r.IsCancelRequest = true
			r.Length = 16
			return r, nil
		case l >= 8 && magic == 0x00030000:
			// StartupMessage v3
			r.Length = int(l)
			r.ProtocolVersionMajor = 3
			r.ProtocolVersionMinor = 0
			r.MessageType = ""
			r.MessageTypeName = "StartupMessage"
			r.Direction = "frontend"
			decodeStartup(r, b[8:])
			return r, nil
		}
	}

	// Typed message: Type(1) + Length(4 BE) + Body
	if len(b) < 5 {
		return r, fmt.Errorf("typed message truncated")
	}
	r.MessageType = string(b[0:1])
	r.Length = int(binary.BigEndian.Uint32(b[1:5]))
	body := b[5:]
	if r.Length >= 4 && r.Length-4 < len(body) {
		body = body[:r.Length-4]
	}
	r.MessageTypeName, r.Direction = messageTypeNameDir(b[0])

	switch b[0] {
	case 'R':
		decodeAuth(r, body)
	case 'E', 'N':
		decodeErrorResponse(r, body)
	case 'S':
		// 'S' is ambiguous: frontend Sync (no body) vs backend
		// ParameterStatus (two null-terminated strings).
		if len(body) > 0 {
			decodeParameterStatus(r, body)
		}
	}
	return r, nil
}

func decodeStartup(r *Result, body []byte) {
	r.StartupParams = make(map[string]string)
	off := 0
	for off < len(body) {
		k, n := readCString(body, off)
		if n == 0 {
			break
		}
		off += n
		if k == "" {
			// trailing null terminator
			break
		}
		v, m := readCString(body, off)
		off += m
		r.StartupParams[k] = v
		switch k {
		case "user":
			r.User = v
		case "database":
			r.Database = v
		case "application_name":
			r.ApplicationName = v
		case "client_encoding":
			r.ClientEncoding = v
		}
	}
}

func decodeAuth(r *Result, body []byte) {
	if len(body) < 4 {
		return
	}
	r.AuthSubtype = int(binary.BigEndian.Uint32(body[0:4]))
	r.AuthSubtypeName = authSubtypeName(r.AuthSubtype)
}

func decodeErrorResponse(r *Result, body []byte) {
	r.ErrorFields = make(map[string]string)
	off := 0
	for off < len(body) {
		t := body[off]
		if t == 0 {
			break
		}
		off++
		v, n := readCString(body, off)
		off += n
		tagName := errorFieldName(t)
		r.ErrorFields[tagName] = v
		switch t {
		case 'C':
			r.SQLState = v
			r.SQLStateName = sqlStateName(v)
		case 'S':
			r.ErrorSeverity = v
		case 'M':
			r.ErrorMessage = v
		}
	}
}

func decodeParameterStatus(r *Result, body []byte) {
	name, n := readCString(body, 0)
	value, _ := readCString(body, n)
	r.ParameterName = name
	r.ParameterValue = value
}

func readCString(b []byte, off int) (string, int) {
	if off >= len(b) {
		return "", 0
	}
	end := off
	for end < len(b) && b[end] != 0 {
		end++
	}
	s := string(b[off:end])
	if end < len(b) {
		return s, end - off + 1
	}
	return s, end - off
}

// messageTypeNameDir returns the name + direction for a typed
// message byte. Some letters are ambiguous (frontend C = Close
// / backend C = CommandComplete; frontend D = Describe /
// backend D = DataRow; etc.) — we surface the most common
// direction interpretation.
func messageTypeNameDir(t byte) (string, string) {
	switch t {
	case 'R':
		return "Authentication", "backend"
	case 'K':
		return "BackendKeyData", "backend"
	case '2':
		return "BindComplete", "backend"
	case '3':
		return "CloseComplete", "backend"
	case 'G':
		return "CopyInResponse", "backend"
	case 'W':
		return "CopyBothResponse", "backend"
	case 'I':
		return "EmptyQueryResponse", "backend"
	case 'V':
		return "FunctionCallResponse", "backend"
	case 'v':
		return "NegotiateProtocolVersion", "backend"
	case 'n':
		return "NoData", "backend"
	case 'N':
		return "NoticeResponse", "backend"
	case 'A':
		return "NotificationResponse", "backend"
	case 't':
		return "ParameterDescription", "backend"
	case '1':
		return "ParseComplete", "backend"
	case 's':
		return "PortalSuspended", "backend"
	case 'Z':
		return "ReadyForQuery", "backend"
	case 'T':
		return "RowDescription", "backend"
	case 'B':
		return "Bind", "frontend"
	case 'C':
		return "Close (frontend) / CommandComplete (backend)", "either"
	case 'D':
		return "Describe (frontend) / DataRow (backend)", "either"
	case 'd':
		return "CopyData", "either"
	case 'c':
		return "CopyDone", "either"
	case 'f':
		return "CopyFail", "frontend"
	case 'E':
		return "Execute (frontend) / ErrorResponse (backend)", "either"
	case 'F':
		return "FunctionCall", "frontend"
	case 'H':
		return "Flush (frontend) / CopyOutResponse (backend)", "either"
	case 'P':
		return "Parse", "frontend"
	case 'p':
		return "PasswordMessage", "frontend"
	case 'Q':
		return "Query", "frontend"
	case 'S':
		return "Sync (frontend) / ParameterStatus (backend)", "either"
	case 'X':
		return "Terminate", "frontend"
	}
	return fmt.Sprintf("uncatalogued type 0x%02X", t), ""
}

func authSubtypeName(s int) string {
	switch s {
	case 0:
		return "AuthenticationOk (trust — no password!)"
	case 2:
		return "KerberosV5"
	case 3:
		return "CleartextPassword (MITM-capturable!)"
	case 5:
		return "MD5Password (offline-crackable hashcat mode 12)"
	case 7:
		return "GSS"
	case 8:
		return "GSSContinue"
	case 9:
		return "SSPI"
	case 10:
		return "SASL (SCRAM-SHA-256 — modern hardened)"
	case 11:
		return "SASLContinue"
	case 12:
		return "SASLFinal"
	}
	return fmt.Sprintf("uncatalogued auth subtype %d", s)
}

func errorFieldName(t byte) string {
	switch t {
	case 'S':
		return "Severity"
	case 'V':
		return "SeverityNonLocalized"
	case 'C':
		return "SQLSTATE"
	case 'M':
		return "Message"
	case 'D':
		return "Detail"
	case 'H':
		return "Hint"
	case 'P':
		return "Position"
	case 'p':
		return "InternalPosition"
	case 'q':
		return "InternalQuery"
	case 'W':
		return "Where"
	case 's':
		return "Schema"
	case 't':
		return "Table"
	case 'c':
		return "Column"
	case 'd':
		return "DataType"
	case 'n':
		return "Constraint"
	case 'F':
		return "File"
	case 'L':
		return "Line"
	case 'R':
		return "Routine"
	}
	return fmt.Sprintf("uncatalogued field 0x%02X", t)
}

func sqlStateName(s string) string {
	switch s {
	case "00000":
		return "successful_completion"
	case "28P01":
		return "invalid_password (brute-force feedback!)"
	case "28000":
		return "invalid_authorization_specification"
	case "3D000":
		return "invalid_catalog_name (database doesn't exist)"
	case "42501":
		return "insufficient_privilege"
	case "42P01":
		return "undefined_table"
	case "53300":
		return "too_many_connections (DoS signal)"
	case "57P03":
		return "cannot_connect_now (server shutdown/recovery)"
	}
	return fmt.Sprintf("uncatalogued SQLSTATE %s", s)
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
