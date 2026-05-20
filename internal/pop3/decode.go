// Package pop3 decodes POP3 (Post Office Protocol v3) messages
// per RFC 1939, plus the RFC 2449 (CAPA), RFC 2595 (STLS), and
// RFC 5034 (AUTH SASL) extensions. POP3 is the **mail-retrieval
// counterpart to SMTP** — TCP/110 (cleartext) or TCP/995
// (implicit-TLS, "POP3S").
//
// Operationally, POP3 is interesting to a mail-server pentester
// for many of the same reasons as SMTP:
//
//   - **Credential brute-force** — `USER admin` / `PASS guess` is
//     the canonical brute-force pattern; servers reply `+OK`
//     for valid credentials and `-ERR` for invalid. A `-ERR`
//     on USER vs PASS leaks whether the username exists
//     (different error wording per implementation; classic
//     username-enumeration vector against older Dovecot /
//     Courier configurations).
//   - **STLS downgrade audit** — `CAPA` returns `STLS` when the
//     server supports opportunistic TLS upgrade; clients that
//     don't enforce TLS can be stripped down to cleartext.
//   - **SASL mechanism enumeration** — `AUTH` (with no args)
//     lists supported SASL mechanisms (`LOGIN` / `PLAIN` /
//     `CRAM-MD5` / `DIGEST-MD5` / `SCRAM-SHA-1` /
//     `SCRAM-SHA-256` / `XOAUTH2` / `GSSAPI`); the canonical
//     pre-auth fingerprint of the mail server's identity
//     stack.
//   - **Banner fingerprinting** — the `+OK` greeting leaks
//     MTA software + version (e.g. `+OK Dovecot ready.` or
//     `+OK POP3 mail.example.com v2024.07 server ready`).
//   - **APOP timestamp leakage** — the legacy `+OK <timestamp>`
//     banner (used by APOP MD5-challenge auth) leaks the
//     server's hostname + timestamp; combined with a known-
//     plaintext PASS, the APOP MD5 digest is trivially
//     crackable offline. Modern servers usually disable APOP.
//
// Wrap-vs-native judgement
//
//	Native. RFC 1939 is publicly available; POP3 is a tiny
//	text-based protocol — two message kinds (Client Command
//	and Server Response), CRLF-terminated lines, a 15-entry
//	verb registry, and a 2-state status indicator
//	(`+OK` / `-ERR`). Multi-line responses to `LIST` / `RETR`
//	/ `TOP` / `UIDL` / `CAPA` use the `<CRLF>.<CRLF>`
//	terminator (with byte-stuffing of leading dots in the
//	message body per §3); the decoder surfaces multi-line
//	data bytes alongside the `+OK` first line. No crypto at
//	the parse layer (STLS triggers a TLS upgrade — handle
//	the post-STLS bytes through a TLS strip first).
//
// What this package covers
//
//   - **Two message kinds** discriminated by the first
//     character of the first line:
//
//   - **Server Response** — first line starts with `+OK`
//     (positive) or `-ERR` (negative). Format:
//     `+OK <text>\r\n` or `-ERR <text>\r\n`. For
//     **multi-line responses** (when the response is to
//     `LIST` with no argument, `RETR <msg>`, `TOP <msg>
//     <n>`, `UIDL` with no argument, or `CAPA`), the
//     server emits the first `+OK <text>\r\n` line then
//     a sequence of data lines, terminating with a line
//     containing a single `.` per RFC 1939 §3 (with
//     byte-stuffing — any data line that starts with `.`
//     has an extra `.` prepended; the decoder removes
//     the byte-stuffing).
//
//   - **Client Command** — first line starts with an
//     ASCII letter. Format: `VERB [argument]\r\n`. The
//     decoder splits the first whitespace-delimited
//     token as the verb (uppercased) + the remainder as
//     the argument.
//
//   - **15+ entry Verb name table** (RFC 1939 + extensions):
//     `USER` (authentication username — first half of the
//     classic 2-step USER/PASS login) / `PASS`
//     (authentication password — second half; sent in
//     CLEARTEXT before STLS!) / `APOP` (legacy MD5-
//     challenge authentication — `APOP <user>
//     <md5-digest>`; the digest is `MD5(<banner-timestamp>
//
//   - <password>)`) / `STAT` (mailbox status — server
//     replies with `+OK <count> <octets>`) / `LIST`
//     (mailbox list — single-line per-message reply, or
//     multi-line with `.` terminator when no argument) /
//     `RETR` (retrieve message — multi-line) / `DELE`
//     (mark message for deletion — committed on QUIT in
//     TRANSACTION state) / `NOOP` (keep-alive) / `RSET`
//     (reset deletion marks) / `QUIT` (close session,
//     trigger UPDATE state, commit DELEs) / `TOP`
//     (retrieve message headers + N body lines — multi-
//     line) / `UIDL` (unique-id list — multi-line or
//     single-line per-message) / `STLS` (opportunistic
//     TLS upgrade per RFC 2595) / `CAPA` (capability list
//     per RFC 2449 — multi-line with `.` terminator) /
//     `AUTH` (SASL authentication per RFC 5034; with no
//     argument lists supported mechanisms multi-line).
//
//   - **Status indicator categorisation**: `+OK` → `Success`;
//     `-ERR` → `Error`; anything else → empty. Surfaced as
//     the `status` field on response messages.
//
//   - **Multi-line data aggregation** — when the response is
//     a `+OK` followed by additional data lines terminated
//     by a single `.` on a line, the decoder captures the
//     data lines (with byte-stuffing removed per RFC 1939
//     §3) into the `data_lines` slice for caller-side
//     processing.
//
//   - **CAPA / UIDL / LIST detection** — when the first-line
//     status is `+OK` and multi-line data is present, the
//     decoder surfaces the data lines as a generic list.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Network framing** — feed POP3 bytes after the TCP-
//     segment header strip (default TCP port 110 cleartext /
//     995 implicit-TLS POP3S).
//   - **STLS / POP3S transport** — after a successful STLS
//     handshake the connection upgrades to TLS; handle the
//     TLS strip first before feeding the decrypted bytes
//     back.
//   - **RFC 5322 message body parsing** — bytes between
//     `+OK ...\r\n` and `\r\n.\r\n` for `RETR` are the RFC
//     5322 mail body (with optional MIME structure per RFC
//     2045); separate decoder. The decoder surfaces them as
//     raw `data_lines`.
//   - **APOP digest verification** — the APOP MD5 digest is
//     surfaced as the second whitespace-delimited token of
//     the `APOP` command argument; verification against the
//     server-side password is out of scope.
//   - **SASL mechanism decoding** — `AUTH <mechanism>` is
//     followed by a server `+` challenge then base64
//     responses; per-mechanism decoding is out of scope.
package pop3

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// MessageKind enumerates the two POP3 message kinds.
type MessageKind string

const (
	KindCommand  MessageKind = "Command"
	KindResponse MessageKind = "Response"
	KindUnknown  MessageKind = "uncatalogued"
)

// Result is the structured decode of a POP3 message.
type Result struct {
	TotalBytes int         `json:"total_bytes"`
	Kind       MessageKind `json:"kind"`

	// Command only.
	Verb     string `json:"verb,omitempty"`
	Argument string `json:"argument,omitempty"`

	// Response only.
	Status     string   `json:"status,omitempty"`
	StatusText string   `json:"status_text,omitempty"`
	DataLines  []string `json:"data_lines,omitempty"`
}

// Decode parses a POP3 message from a hex string. Separators
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
	case KindCommand:
		decodeCommand(r, first)
	case KindResponse:
		decodeResponse(r, first, lines[1:])
	}
	return r, nil
}

func classifyFirstLine(line string) MessageKind {
	if line == "" {
		return KindUnknown
	}
	first := line[0]
	if first == '+' || first == '-' {
		return KindResponse
	}
	if (first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') {
		return KindCommand
	}
	return KindUnknown
}

func decodeCommand(r *Result, line string) {
	idx := strings.IndexByte(line, ' ')
	if idx < 0 {
		r.Verb = strings.ToUpper(line)
		return
	}
	r.Verb = strings.ToUpper(line[:idx])
	r.Argument = line[idx+1:]
}

func decodeResponse(r *Result, first string, rest []string) {
	switch {
	case strings.HasPrefix(first, "+OK"):
		r.Status = "+OK"
		r.StatusText = trimLeadingSpace(first[3:])
	case strings.HasPrefix(first, "-ERR"):
		r.Status = "-ERR"
		r.StatusText = trimLeadingSpace(first[4:])
	default:
		return
	}
	// Multi-line bodies are only valid after +OK. Walk the
	// rest of the lines until we hit a "." line.
	if r.Status != "+OK" {
		return
	}
	for _, raw := range rest {
		line := strings.TrimRight(raw, "\r")
		if line == "." {
			break
		}
		// Byte-stuffing removal per RFC 1939 §3: a leading
		// "." in body data is doubled on the wire.
		if strings.HasPrefix(line, "..") {
			line = line[1:]
		}
		r.DataLines = append(r.DataLines, line)
	}
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
