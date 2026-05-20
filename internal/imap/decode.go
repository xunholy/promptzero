// Package imap decodes IMAP4rev1 (Internet Message Access
// Protocol v4 revision 1) messages per RFC 3501, plus the RFC
// 2595 (STARTTLS), RFC 2087 (QUOTA), RFC 2342 (NAMESPACE), and
// RFC 4978 (COMPRESS) extensions. IMAP is the **dominant
// modern mail-access protocol** — TCP/143 (cleartext) or
// TCP/993 (implicit-TLS, "IMAPS"). It powers Exchange / Office
// 365 / Google Workspace IMAP / Dovecot / Cyrus IMAP / Courier
// IMAP / Zimbra / FastMail / SendGrid Inbound / Apple Mail /
// Thunderbird / iOS Mail / Outlook.
//
// Operationally, IMAP is the canonical mail-server pentest
// target alongside POP3 and SMTP — but with a richer surface:
//
//   - **Credential brute-force** — `LOGIN <user> <pass>` is
//     the canonical cleartext-credentials command (sent before
//     STARTTLS!); tagged responses are `OK` for success and
//     `NO` for failure. Different `NO` error wording per
//     implementation enables username enumeration (classic
//     against older Dovecot configurations).
//   - **STARTTLS downgrade audit** — `CAPABILITY` returns
//     `STARTTLS` when the server supports opportunistic TLS
//     upgrade; clients that don't enforce TLS can be
//     stripped down to cleartext via mitm.
//   - **SASL mechanism enumeration** — `CAPABILITY` lists
//     `AUTH=LOGIN` / `AUTH=PLAIN` / `AUTH=CRAM-MD5` /
//     `AUTH=DIGEST-MD5` / `AUTH=SCRAM-SHA-1` /
//     `AUTH=SCRAM-SHA-256` / `AUTH=XOAUTH2` / `AUTH=GSSAPI`;
//     the canonical pre-auth fingerprint.
//   - **Banner fingerprinting** — the `* OK` greeting leaks
//     IMAP server software + version (e.g.
//     `* OK Dovecot ready.` / `* OK Microsoft Exchange Server
//     2019 IMAP4 service is ready` / `* OK Gimap ready`).
//   - **CAPABILITY enumeration** — the per-server capability
//     list (`IMAP4rev1 STARTTLS AUTH=PLAIN AUTH=LOGIN
//     LOGINDISABLED IDLE NAMESPACE QUOTA UIDPLUS LITERAL+
//     COMPRESS=DEFLATE`) fingerprints the server's feature
//     set + can reveal misconfigurations (e.g.
//     `LOGINDISABLED` absent + `STARTTLS` absent = cleartext
//     LOGIN accepted).
//   - **FETCH-based content disclosure** — `1 UID FETCH 1:*
//     BODY[]` retrieves every message in the selected mailbox
//     in one round-trip (the canonical post-auth data-
//     exfiltration command).
//   - **IDLE / NOTIFY abuse** — `IDLE` keeps the connection
//     open for server push of new messages; long-running
//     IDLE sessions can be used to maintain persistent
//     observer access.
//
// Wrap-vs-native judgement
//
//	Native. RFC 3501 is publicly available; IMAP is a text-
//	based protocol with four message kinds — Client Command
//	(tagged), Untagged Response (`*`), Tagged Response
//	(matching the command's tag), and Continuation (`+`).
//	The wire format is richer than POP3 / SMTP because of
//	the tag-pairing mechanism, but the decoder discriminates
//	on the first character + the second whitespace-delimited
//	token. Literal strings (`{N}<CRLF>...<N bytes>`) and
//	multi-line FETCH bodies are surfaced as raw bytes for
//	caller-side processing — per-message-body MIME parsing
//	is a separate decoder. No crypto at the parse layer
//	(STARTTLS triggers a TLS upgrade — handle the post-
//	STARTTLS bytes through a TLS strip first).
//
// What this package covers
//
//   - **Four message kinds** discriminated by the first
//     character of the first line:
//
//   - **Continuation** — first character is `+`. Format:
//     `+ <prompt-text>`. Used by the server during
//     `AUTHENTICATE` SASL exchanges (server prompts the
//     client for the next SASL step) and during `APPEND`
//     literal uploads.
//
//   - **Untagged Response** — first character is `*`.
//     Format: `* <type> <data>`. The `<type>` is one of
//     the documented untagged response types — either a
//     status (`OK` / `NO` / `BAD` / `BYE` / `PREAUTH`) or
//     a data response (`CAPABILITY` / `LIST` / `LSUB` /
//     `STATUS` / `SEARCH` / `FLAGS` / `FETCH` / `EXISTS`
//     / `RECENT` / `EXPUNGE` / `NAMESPACE` / `QUOTA` /
//     `QUOTAROOT` / `ID`). The decoder surfaces the
//     untagged type as `untagged_type` and the rest of
//     the line as `untagged_data`.
//
//   - **Command + Tagged Response** — first character is
//     alphanumeric. Format: `<tag> <command> [args]`
//     (Command) or `<tag> <status> [args]` (Tagged
//     Response). To disambiguate, the decoder inspects
//     the second whitespace-delimited token: if it is
//     one of `OK` / `NO` / `BAD` / `BYE` / `PREAUTH` →
//     Tagged Response; otherwise → Command.
//
//   - **25+ entry Verb name table** (RFC 3501 §6 +
//     extensions): `LOGIN` (cleartext credentials!) /
//     `AUTHENTICATE` (SASL with continuation) / `SELECT`
//     (open mailbox r/w) / `EXAMINE` (open mailbox
//     read-only) / `CREATE` / `DELETE` / `RENAME` /
//     `SUBSCRIBE` / `UNSUBSCRIBE` / `LIST` (list
//     mailboxes — wildcard `*` / `%`) / `LSUB` (list
//     subscribed mailboxes) / `STATUS` (query mailbox
//     metadata without SELECT) / `APPEND` (push a message
//     to a mailbox — literal upload) / `CHECK` / `CLOSE`
//     (close mailbox without EXPUNGE) / `EXPUNGE` (permanently
//     delete \Deleted messages) / `SEARCH` (search by
//     criteria — `FROM` / `TO` / `SUBJECT` / `BEFORE` /
//     `SINCE` / `HEADER` / `BODY` / `TEXT` / etc.) /
//     `FETCH` (retrieve message data — the canonical
//     content-disclosure command) / `STORE` (set message
//     flags) / `COPY` / `UID` (UID variants of FETCH /
//     STORE / SEARCH / COPY) / `NOOP` (keep-alive) /
//     `LOGOUT` (close session) / `CAPABILITY` (list
//     server features — the canonical enumeration step)
//     / `STARTTLS` (TLS upgrade per RFC 2595) / `IDLE`
//     (server push mode per RFC 2177) / `NAMESPACE` (list
//     personal/shared/other namespaces per RFC 2342) /
//     `ID` (client/server identification per RFC 2971).
//
//   - **5-entry Status name table** (RFC 3501 §7.1):
//     `OK` (success) / `NO` (failure) / `BAD` (malformed)
//     / `BYE` (server closing connection) / `PREAUTH`
//     (server pre-authenticated the client via Kerberos /
//     IPsec / similar out-of-band trust).
//
//   - **15+ entry Untagged Type name table** (data
//     responses + the status responses above): `CAPABILITY`
//     / `LIST` / `LSUB` / `STATUS` / `SEARCH` / `FLAGS` /
//     `FETCH` / `EXISTS` / `RECENT` / `EXPUNGE` /
//     `NAMESPACE` / `QUOTA` / `QUOTAROOT` / `ID` /
//     `ESEARCH` (RFC 4731 extended SEARCH).
//
//   - **Continuation prompt extraction** — the text after
//     `+ ` on continuation responses is surfaced as
//     `continuation_prompt` for caller-side SASL exchange
//     analysis.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Network framing** — feed IMAP bytes after the TCP-
//     segment header strip (default TCP port 143 cleartext
//     / 993 implicit-TLS IMAPS).
//   - **STARTTLS / IMAPS transport** — after a successful
//     STARTTLS handshake the connection upgrades to TLS;
//     handle the TLS strip first before feeding the
//     decrypted bytes back.
//   - **Literal string body handling** — IMAP literals
//     (`{N}<CRLF>...<N bytes>`) carry binary data inline
//     (FETCH BODY[], APPEND uploads). The decoder surfaces
//     the literal-length marker as part of the line but
//     does not consume the following N bytes from a
//     separate buffer; multi-line FETCH bodies are
//     surfaced as the raw line content.
//   - **FETCH attribute parser** — `FETCH (UID 12 FLAGS
//     (\\Seen) BODY[HEADER] {142}\r\n...)` carries a
//     nested attribute list; the decoder surfaces it as
//     untagged_data for caller-side parsing.
//   - **MIME / RFC 5322 message body parsing** — the
//     bytes inside FETCH BODY[] / BODY[TEXT] / BODY.PEEK[]
//     responses are the RFC 5322 mail body with optional
//     MIME structure per RFC 2045; separate decoder.
//   - **SASL mechanism decoding** — `AUTHENTICATE
//     <mechanism>` is followed by a server `+` challenge
//     then base64 responses; per-mechanism decoding
//     (LOGIN, PLAIN, CRAM-MD5, SCRAM-SHA-256) is out of
//     scope.
//   - **IMAP4 commands beyond the IMAP4rev1 + common-
//     extension set** — RFC 5267 (CONTEXT extension), RFC
//     5256 (SORT/THREAD), RFC 4467 (URLAUTH), RFC 4731
//     (ESEARCH), RFC 5464 (METADATA), RFC 6855 (UTF8) —
//     verbs not in the name table surface as
//     "uncatalogued verb <name>".
package imap

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// MessageKind enumerates the four IMAP message kinds.
type MessageKind string

const (
	KindCommand      MessageKind = "Command"
	KindUntaggedResp MessageKind = "Untagged_Response"
	KindTaggedResp   MessageKind = "Tagged_Response"
	KindContinuation MessageKind = "Continuation"
	KindUnknown      MessageKind = "uncatalogued"
)

// Result is the structured decode of an IMAP message.
type Result struct {
	TotalBytes int         `json:"total_bytes"`
	Kind       MessageKind `json:"kind"`

	// Command + Tagged Response only.
	Tag string `json:"tag,omitempty"`

	// Command only.
	Verb     string `json:"verb,omitempty"`
	VerbName string `json:"verb_name,omitempty"`
	Argument string `json:"argument,omitempty"`

	// Tagged Response only.
	Status     string `json:"status,omitempty"`
	StatusText string `json:"status_text,omitempty"`

	// Untagged Response only.
	UntaggedType     string `json:"untagged_type,omitempty"`
	UntaggedTypeName string `json:"untagged_type_name,omitempty"`
	UntaggedData     string `json:"untagged_data,omitempty"`

	// Continuation only.
	ContinuationPrompt string `json:"continuation_prompt,omitempty"`
}

// Decode parses an IMAP message from a hex string. Separators
// (':' '-' '_' whitespace) tolerated; '0x' prefix tolerated.
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
	if len(b) == 0 {
		return nil, fmt.Errorf("empty payload")
	}

	r := &Result{TotalBytes: len(b)}
	text := strings.TrimRight(string(b), "\r\n")
	lines := strings.Split(text, "\n")
	if len(lines) == 0 {
		return r, fmt.Errorf("no start line")
	}
	first := strings.TrimRight(lines[0], "\r")
	r.Kind = classifyFirstLine(first)

	switch r.Kind {
	case KindContinuation:
		decodeContinuation(r, first)
	case KindUntaggedResp:
		decodeUntagged(r, first)
	case KindCommand:
		decodeCommand(r, first)
	case KindTaggedResp:
		decodeTaggedResponse(r, first)
	}
	return r, nil
}

func classifyFirstLine(line string) MessageKind {
	if line == "" {
		return KindUnknown
	}
	switch line[0] {
	case '+':
		return KindContinuation
	case '*':
		return KindUntaggedResp
	}
	// Alphanumeric → either Command or Tagged Response.
	// Look at the second whitespace-delimited token.
	if !isAlnum(line[0]) {
		return KindUnknown
	}
	tok := secondToken(line)
	if isStatusToken(tok) {
		return KindTaggedResp
	}
	return KindCommand
}

func isAlnum(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9')
}

func secondToken(line string) string {
	first := strings.IndexByte(line, ' ')
	if first < 0 || first == len(line)-1 {
		return ""
	}
	rest := line[first+1:]
	end := strings.IndexByte(rest, ' ')
	if end < 0 {
		return rest
	}
	return rest[:end]
}

func isStatusToken(s string) bool {
	switch strings.ToUpper(s) {
	case "OK", "NO", "BAD", "BYE", "PREAUTH":
		return true
	}
	return false
}

func decodeContinuation(r *Result, line string) {
	if len(line) < 2 {
		return
	}
	// Skip "+ " or "+\t".
	prompt := line[1:]
	r.ContinuationPrompt = trimLeadingSpace(prompt)
}

func decodeUntagged(r *Result, line string) {
	// Format: "* <type> [data]".
	if len(line) < 2 {
		return
	}
	rest := line[1:]
	rest = trimLeadingSpace(rest)
	idx := strings.IndexByte(rest, ' ')
	if idx < 0 {
		r.UntaggedType = strings.ToUpper(rest)
		r.UntaggedTypeName = untaggedTypeName(r.UntaggedType)
		return
	}
	r.UntaggedType = strings.ToUpper(rest[:idx])
	r.UntaggedTypeName = untaggedTypeName(r.UntaggedType)
	r.UntaggedData = trimLeadingSpace(rest[idx+1:])
}

func decodeCommand(r *Result, line string) {
	// Format: "<tag> <verb> [args]".
	idx := strings.IndexByte(line, ' ')
	if idx < 0 {
		r.Tag = line
		return
	}
	r.Tag = line[:idx]
	rest := trimLeadingSpace(line[idx+1:])
	vidx := strings.IndexByte(rest, ' ')
	if vidx < 0 {
		r.Verb = strings.ToUpper(rest)
		r.VerbName = verbName(r.Verb)
		return
	}
	r.Verb = strings.ToUpper(rest[:vidx])
	r.VerbName = verbName(r.Verb)
	r.Argument = trimLeadingSpace(rest[vidx+1:])
}

func decodeTaggedResponse(r *Result, line string) {
	// Format: "<tag> <status> [text]".
	idx := strings.IndexByte(line, ' ')
	if idx < 0 {
		r.Tag = line
		return
	}
	r.Tag = line[:idx]
	rest := trimLeadingSpace(line[idx+1:])
	sidx := strings.IndexByte(rest, ' ')
	if sidx < 0 {
		r.Status = strings.ToUpper(rest)
		return
	}
	r.Status = strings.ToUpper(rest[:sidx])
	r.StatusText = trimLeadingSpace(rest[sidx+1:])
}

func verbName(v string) string {
	switch v {
	case "LOGIN":
		return "LOGIN (cleartext credentials!)"
	case "AUTHENTICATE":
		return "AUTHENTICATE (SASL)"
	case "SELECT":
		return "SELECT (open mailbox r/w)"
	case "EXAMINE":
		return "EXAMINE (open mailbox read-only)"
	case "CREATE":
		return "CREATE"
	case "DELETE":
		return "DELETE"
	case "RENAME":
		return "RENAME"
	case "SUBSCRIBE":
		return "SUBSCRIBE"
	case "UNSUBSCRIBE":
		return "UNSUBSCRIBE"
	case "LIST":
		return "LIST"
	case "LSUB":
		return "LSUB"
	case "STATUS":
		return "STATUS"
	case "APPEND":
		return "APPEND (literal upload)"
	case "CHECK":
		return "CHECK"
	case "CLOSE":
		return "CLOSE"
	case "EXPUNGE":
		return "EXPUNGE"
	case "SEARCH":
		return "SEARCH"
	case "FETCH":
		return "FETCH (content disclosure)"
	case "STORE":
		return "STORE (set flags)"
	case "COPY":
		return "COPY"
	case "UID":
		return "UID (variant prefix)"
	case "NOOP":
		return "NOOP (keep-alive)"
	case "LOGOUT":
		return "LOGOUT"
	case "CAPABILITY":
		return "CAPABILITY (server feature list)"
	case "STARTTLS":
		return "STARTTLS (TLS upgrade)"
	case "IDLE":
		return "IDLE (server push)"
	case "NAMESPACE":
		return "NAMESPACE"
	case "ID":
		return "ID (client/server identification)"
	case "ENABLE":
		return "ENABLE"
	case "UNSELECT":
		return "UNSELECT"
	case "COMPRESS":
		return "COMPRESS"
	}
	return fmt.Sprintf("uncatalogued verb %q", v)
}

func untaggedTypeName(t string) string {
	switch t {
	case "OK":
		return "Status_OK"
	case "NO":
		return "Status_NO"
	case "BAD":
		return "Status_BAD"
	case "BYE":
		return "Status_BYE"
	case "PREAUTH":
		return "Status_PREAUTH"
	case "CAPABILITY":
		return "CAPABILITY"
	case "LIST":
		return "LIST"
	case "LSUB":
		return "LSUB"
	case "STATUS":
		return "STATUS"
	case "SEARCH":
		return "SEARCH"
	case "FLAGS":
		return "FLAGS"
	case "FETCH":
		return "FETCH"
	case "EXISTS":
		return "EXISTS"
	case "RECENT":
		return "RECENT"
	case "EXPUNGE":
		return "EXPUNGE"
	case "NAMESPACE":
		return "NAMESPACE"
	case "QUOTA":
		return "QUOTA"
	case "QUOTAROOT":
		return "QUOTAROOT"
	case "ID":
		return "ID"
	case "ESEARCH":
		return "ESEARCH"
	case "ENABLED":
		return "ENABLED"
	}
	// Numeric prefixes like "* 12 EXISTS" cause the type
	// token to be "12" — the actual data type is the third
	// token (EXISTS / RECENT / EXPUNGE / FETCH). Surface
	// the numeric token but flag it as numeric-prefixed.
	if isAllDigits(t) {
		return "numeric_prefix (see untagged_data for real type)"
	}
	return fmt.Sprintf("uncatalogued type %q", t)
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func trimLeadingSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	return s
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
