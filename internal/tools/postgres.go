// postgres.go — host-side PostgreSQL message decoder Spec.
// Wraps the internal/postgres walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/postgres"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(postgresDecodeSpec)
}

var postgresDecodeSpec = Spec{
	Name: "postgres_decode",
	Description: "Decode a PostgreSQL frontend/backend protocol v3 message per " +
		"the PostgreSQL documentation (Part VIII). TCP/5432 default; " +
		"alternate ports common in container deployments but wire format " +
		"identical. The second-largest open-source database pentest " +
		"target after MySQL; deployed everywhere from cloud-managed " +
		"Postgres (RDS / Aurora / Cloud SQL / Crunchy / Supabase / Neon " +
		"/ Timescale Cloud) to bare-metal installations to containerized " +
		"side-cars. Database-protocol pentest decoder sibling to " +
		"`tds_decode` (v0.334). The wire format leaks: **cleartext " +
		"username + database via StartupMessage** (no-type-byte first " +
		"message after TCP connect; `user` and `database` keys sent " +
		"cleartext UTF-8 — canonical PostgreSQL credential disclosure " +
		"on TCP/5432 without TLS); **authentication method enumeration " +
		"via AuthenticationRequest** (server's `R` response carries 4-" +
		"byte sub-type revealing auth policy: 0 AuthenticationOk = " +
		"trust/no password!, 3 CleartextPassword = MITM-capturable!, 5 " +
		"MD5Password = offline-crackable hashcat mode 12, 10 SASL = " +
		"SCRAM-SHA-256 modern hardened); **brute-force feedback via " +
		"ErrorResponse SQLSTATE** (28P01 invalid_password = canonical " +
		"wrong-password response consumed by password-spray tools; " +
		"3D000 invalid_catalog_name = database enumeration feedback; " +
		"42P01 undefined_table = post-auth enumeration); **PostgreSQL " +
		"version disclosure via ParameterStatus** (`server_version` GUC " +
		"= canonical version-fingerprint for CVE selection — 15.4, 16.1, " +
		"17.2 etc.); **SSL / GSS pre-handshake** (SSLRequest magic " +
		"0x04D2162F = 80877103 + GSSENCRequest magic 0x04D21630 = " +
		"80877104 sent before StartupMessage to probe TLS / GSSAPI " +
		"encryption support); **application_name** identifies client " +
		"tool (psql / pgAdmin 4 / DBeaver / pgcli / node-postgres / " +
		"sqlmap). Decodes:\n\n" +
		"- **Type+Length+Body frame parsing**: Type (1 byte) + Length " +
		"(4 BE, includes self) + Body. Startup messages have NO type " +
		"byte and are discriminated by Length + ProtocolVersion magic.\n" +
		"- **3-entry pre-startup magic name table**: 0x04D2162F " +
		"SSLRequest / 0x04D21630 GSSENCRequest / 0x04D21631 " +
		"CancelRequest. Surfaces `is_ssl_request` / `is_gss_request` / " +
		"`is_cancel_request` boolean classifications.\n" +
		"- **15-entry frontend message type name table**: B Bind / C " +
		"Close / d CopyData / c CopyDone / f CopyFail / D Describe / E " +
		"Execute / F FunctionCall / H Flush / P Parse / p " +
		"PasswordMessage / Q Query / S Sync / X Terminate.\n" +
		"- **24-entry backend message type name table**: R " +
		"Authentication / K BackendKeyData / 2 BindComplete / 3 " +
		"CloseComplete / C CommandComplete / G CopyInResponse / H " +
		"CopyOutResponse / W CopyBothResponse / D DataRow / I " +
		"EmptyQueryResponse / E ErrorResponse / V FunctionCallResponse " +
		"/ v NegotiateProtocolVersion / n NoData / N NoticeResponse / A " +
		"NotificationResponse / t ParameterDescription / S " +
		"ParameterStatus / 1 ParseComplete / s PortalSuspended / Z " +
		"ReadyForQuery / T RowDescription.\n" +
		"- **StartupMessage body walker**: ProtocolVersion (4 BE) + " +
		"sequence of null-terminated key/value strings terminated by " +
		"extra null byte. Surfaces all observed key/value pairs as " +
		"`startup_params` map plus canonical `user` / `database` / " +
		"`application_name` / `client_encoding` keys as top-level " +
		"fields.\n" +
		"- **AuthenticationRequest body walker**: first 4 BE bytes are " +
		"the sub-type. Surfaces `auth_subtype` + `auth_subtype_name`.\n" +
		"- **11-entry AuthenticationRequest sub-type name table**: 0 " +
		"AuthenticationOk (trust — no password!) / 2 KerberosV5 / 3 " +
		"CleartextPassword (MITM-capturable!) / 5 MD5Password (offline-" +
		"crackable hashcat mode 12) / 7 GSS / 8 GSSContinue / 9 SSPI / " +
		"10 SASL (SCRAM-SHA-256 — modern hardened) / 11 SASLContinue / " +
		"12 SASLFinal.\n" +
		"- **ErrorResponse / NoticeResponse body walker**: TLV-style " +
		"(1-byte field tag + null-terminated value, terminated by 0-byte " +
		"tag). Surfaces all observed field tags as `error_fields` map.\n" +
		"- **18-entry ErrorResponse field-tag name table** (PostgreSQL " +
		"§52.8): S Severity (localized) / V Severity (non-localized) / " +
		"C SQLSTATE / M Message / D Detail / H Hint / P Position / p " +
		"InternalPosition / q InternalQuery / W Where / s Schema / t " +
		"Table / c Column / d DataType / n Constraint / F File / L Line " +
		"/ R Routine.\n" +
		"- **8-entry canonical SQLSTATE name table**: 00000 " +
		"successful_completion / 28P01 invalid_password (brute-force " +
		"feedback!) / 28000 invalid_authorization_specification / 3D000 " +
		"invalid_catalog_name (database doesn't exist) / 42501 " +
		"insufficient_privilege / 42P01 undefined_table / 53300 " +
		"too_many_connections (DoS signal) / 57P03 cannot_connect_now " +
		"(server shutdown/recovery).\n" +
		"- **ParameterStatus body walker**: two null-terminated strings " +
		"(parameter name + value). Surfaces all observed parameters; " +
		"canonical pentest-interesting: `server_version` (CVE-selection " +
		"fingerprint), `is_superuser`, `session_authorization`.\n\n" +
		"Pure offline parser — operators paste PostgreSQL bytes (the " +
		"TCP-segment payload as hex; default TCP/5432) from a `tcpdump " +
		"-X port 5432` line or a Wireshark PGSQL dissector view and " +
		"get the documented per-message-type breakdown.\n\n" +
		"Out of scope (deferred): Bind / Parse parameter marshalling " +
		"(per-parameter format codes + length-prefixed binary blobs " +
		"typed via prior Parse message's type OID list); RowDescription " +
		"type-OID parsing (1700+ system catalogue OIDs); DataRow body " +
		"parsing (per-column NULL or length-prefixed binary); extended " +
		"query protocol multi-message flow (Parse/Bind/Describe/Execute" +
		"/Sync); COPY streaming (CopyInResponse + CopyData + CopyDone/" +
		"CopyFail carry raw COPY data — typically CSV or PG binary " +
		"format); TLS / GSSAPI encryption handshake (after SSLRequest + " +
		"`S` reply connection upgrades to TLS — handle TLS strip first); " +
		"SASL inner-mechanism decode (SCRAM-SHA-256 client-first / " +
		"server-first / client-final / server-final base64-blob " +
		"payloads); NOTIFY / LISTEN payload semantics (application-" +
		"defined channel namespace).\n\n" +
		"Source: docs/catalog/gap-analysis.md (database-protocol " +
		"foundational decoder — canonical PostgreSQL pentest dissector " +
		"for credential capture + TLS-downgrade audit + auth-method " +
		"enumeration + version fingerprint + database enumeration; pairs " +
		"with `tds_decode` for cross-database-protocol pentest surface; " +
		"common in DEF CON + Black Hat + HITB + OffSec engagements + " +
		"every sqlmap / nmap pgsql-* NSE / metasploit postgres_login-" +
		"driven PostgreSQL attack workflow). Wrap-vs-native: native — " +
		"PostgreSQL frontend/backend protocol is publicly documented " +
		"(Part VIII); the message format is a simple type+length+body " +
		"frame with a startup-message exception; key/value parameter " +
		"walks via null-terminated strings; no crypto at the parse " +
		"layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"PostgreSQL message bytes as hex (the TCP-segment payload; default TCP/5432). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   postgresDecodeHandler,
}

func postgresDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("postgres_decode: 'hex' is required")
	}
	res, err := postgres.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("postgres_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
