// Package smtp decodes SMTP (Simple Mail Transfer Protocol)
// messages per RFC 5321 — the 40-year-old text-based protocol
// every mail server speaks. Default ports: TCP/25 (mail
// exchange between MTAs), TCP/587 (mail submission with
// STARTTLS), TCP/465 (implicit-TLS submission, "SMTPS").
//
// Operationally, SMTP is the canonical text protocol on the
// boundary between MTAs (Exim, Postfix, Sendmail, Exchange,
// Office 365 Exchange Online, Google Workspace, Mailcow,
// Mailgun, SendGrid). It is interesting to a mail-server
// pentester for:
//
//   - **Open-relay testing** — the classic `MAIL FROM:
//     <attacker@evil.com>` + `RCPT TO:<victim@target.com>`
//     sequence detects whether a server accepts mail for
//     non-local recipients (open relay = spam abuse risk).
//   - **User enumeration** — `VRFY user` returns 250 if the
//     mailbox exists, 550 if not; `EXPN list` expands
//     mailing-list members; `RCPT TO:<user@target>` is a
//     fallback when VRFY is disabled. All three are commonly
//     used to enumerate valid usernames from a mail server.
//   - **STARTTLS downgrade audit** — a server's response to
//     `EHLO` lists `STARTTLS` if it supports opportunistic
//     TLS; clients that don't enforce TLS can be downgraded.
//   - **Authentication enumeration** — `AUTH` listing in EHLO
//     reveals supported SASL mechanisms (LOGIN / PLAIN /
//     CRAM-MD5 / DIGEST-MD5 / SCRAM-SHA-1 / SCRAM-SHA-256 /
//     XOAUTH2 / GSSAPI).
//   - **Banner fingerprinting** — the 220 banner on connect
//     leaks MTA software + version (e.g. `220 mail.example.com
//     ESMTP Postfix (Debian/GNU)`).
//   - **DEF CON / HITB / CTF challenges** — open-relay +
//     UCEPROTECT-list + DKIM/DMARC alignment puzzles
//     frequently use SMTP captures.
//
// Wrap-vs-native judgement
//
//	Native. RFC 5321 is publicly available; SMTP is a tiny
//	text-based protocol — two message kinds (Client Command
//	and Server Response), CRLF-terminated lines, a fixed
//	verb registry, and a 3-digit status code scheme. The
//	multi-line response format (RFC 5321 §4.2.1) uses
//	`<code>-<text>` for intermediate lines and `<code>
//	<text>` for the final line of a multi-line reply; the
//	decoder aggregates these. No crypto at the parse layer
//	(STARTTLS triggers a TLS upgrade — handle the post-
//	STARTTLS bytes through a TLS strip first).
//
// What this package covers
//
//   - **Two message kinds** discriminated by the first
//     character of the first line:
//
//   - **Server Response** — first line starts with a 3-
//     digit ASCII status code (`220 mail.example.com
//     ESMTP Postfix\r\n`). Multi-line responses use
//     `<code>-<text>` for intermediate lines and `<code>
//     <text>` (space, not hyphen) for the final line —
//     the decoder aggregates all lines into a single
//     `lines` slice + a `final_line_text` field.
//
//   - **Client Command** — first line starts with an
//     ASCII letter (`HELO mail.example.com\r\n`). The
//     decoder splits the first whitespace-delimited
//     token as the verb + the remainder as the argument.
//
//   - **14+ entry Verb name table** (RFC 5321 §4.1.1 +
//     RFC 1869 EHLO + RFC 1652 8BITMIME + RFC 3030 BDAT +
//     RFC 4954 AUTH + RFC 3207 STARTTLS): `HELO` (legacy
//     greeting — single-line response) / `EHLO` (extended
//     greeting — multi-line response listing supported
//     extensions) / `AUTH` (SASL authentication —
//     followed by mechanism + base64 initial response) /
//     `MAIL` (from-address, prefix `MAIL FROM:`) / `RCPT`
//     (to-address, prefix `RCPT TO:`) / `DATA` (begin
//     message body; server replies 354 then expects
//     CRLF.CRLF terminator) / `RSET` (abort current
//     transaction) / `VRFY` (verify mailbox exists —
//     user enumeration target) / `EXPN` (expand mailing
//     list — user enumeration target) / `QUIT` (close
//     session) / `STARTTLS` (upgrade to TLS — RFC 3207)
//     / `HELP` / `NOOP` / `BDAT` (binary data chunking
//     per RFC 3030).
//
//   - **HTTP-style status code categorisation**: 2xx
//     `Success` (220 banner / 221 closing / 250 OK / 251
//     forward) / 3xx `Intermediate` (354 start mail
//     input — only DATA gets this) / 4xx `Transient_Error`
//     (421 service unavailable / 450 mailbox busy / 451
//     local processing error / 452 insufficient storage)
//     / 5xx `Permanent_Error` (500 syntax / 501
//     parameters / 502 not implemented / 503 bad
//     sequence / 504 unrecognised parameter / 535
//     authentication failed / 550 mailbox unavailable /
//     553 mailbox name not allowed / 554 transaction
//     failed). The decoder surfaces this as
//     `status_category` on the response.
//
//   - **Multi-line response aggregation** — server replies
//     to EHLO frequently span 5+ lines (one per extension).
//     The decoder walks the entire input collecting every
//     line that shares the same status code, exposes the
//     full list as `lines`, and identifies the final line
//     (space-after-code) as `final_line_text` for caller
//     convenience.
//
//   - **EHLO extension list** — when the server responds to
//     EHLO with a multi-line reply, every line after the
//     first contains a supported extension keyword
//     (`SIZE 35882577` / `8BITMIME` / `STARTTLS` /
//     `AUTH LOGIN PLAIN` / `ENHANCEDSTATUSCODES` / etc.).
//     The decoder surfaces these as `ehlo_extensions` on
//     response messages where the code is 250 + line count
//     > 1.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Network framing** — feed SMTP bytes after the TCP-
//     segment header strip (default TCP port 25 / 587 / 465).
//   - **STARTTLS / SMTPS transport** — after a successful
//     STARTTLS handshake the connection upgrades to TLS;
//     handle the TLS strip first before feeding the
//     decrypted bytes back.
//   - **MIME / mail body parsing** — the bytes between `354`
//     server reply and the `\r\n.\r\n` terminator are the
//     RFC 5322 mail body (with optional MIME structure per
//     RFC 2045); separate decoder.
//   - **SASL mechanism decoding** — AUTH command arguments
//     are SASL mechanism + optional initial response
//     (base64-encoded); the decoder surfaces them as raw
//     strings; per-mechanism decoding (PLAIN → username +
//     password; CRAM-MD5 → challenge + HMAC response;
//     SCRAM-SHA-1 → 5-message exchange) is out of scope.
//   - **DKIM / DMARC / SPF** — DNS-side anti-spam machinery;
//     SMTP carries DKIM-Signature in the body header, but
//     parsing the signature + validating against the DNS
//     TXT record is a separate concern.
//   - **Submission queue + bounce handling** — Postfix /
//     Sendmail queue semantics, bounce-message generation,
//     forwarding loop detection are all higher-level.
package smtp

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// MessageKind enumerates the two SMTP message kinds.
type MessageKind string

const (
	KindCommand  MessageKind = "Command"
	KindResponse MessageKind = "Response"
	KindUnknown  MessageKind = "uncatalogued"
)

// Result is the structured decode of an SMTP message.
type Result struct {
	TotalBytes int         `json:"total_bytes"`
	Kind       MessageKind `json:"kind"`

	// Command only.
	Verb     string `json:"verb,omitempty"`
	Argument string `json:"argument,omitempty"`

	// Response only.
	StatusCode     int      `json:"status_code,omitempty"`
	StatusCategory string   `json:"status_category,omitempty"`
	Lines          []string `json:"lines,omitempty"`
	FinalLineText  string   `json:"final_line_text,omitempty"`
	EHLOExtensions []string `json:"ehlo_extensions,omitempty"`
}

// Decode parses an SMTP message from a hex string. Separators
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
	// Strip trailing CRLF so the final empty element of the
	// split doesn't pollute the line walker, then split on
	// '\n' (CRs are trimmed per-line below).
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
	if first >= '0' && first <= '9' {
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
	r.Lines = append(r.Lines, first)
	code, finalReached, _ := parseResponseLine(first)
	r.StatusCode = code
	r.StatusCategory = statusCategory(code)
	if finalReached {
		r.FinalLineText = textAfterDelimiter(first)
	} else {
		// Walk remaining lines until we hit the final-line
		// space-after-code or end of input.
		for _, raw := range rest {
			line := strings.TrimRight(raw, "\r")
			if line == "" {
				break
			}
			r.Lines = append(r.Lines, line)
			_, final, _ := parseResponseLine(line)
			if final {
				r.FinalLineText = textAfterDelimiter(line)
				break
			}
		}
	}
	// EHLO-style multi-line 250-X aggregation.
	if r.StatusCode == 250 && len(r.Lines) > 1 {
		for _, ln := range r.Lines[1:] {
			txt := textAfterDelimiter(ln)
			if txt != "" {
				r.EHLOExtensions = append(r.EHLOExtensions, txt)
			}
		}
	}
}

// parseResponseLine returns (code, hasFinalDelimiter, ok).
// hasFinalDelimiter is true when the 4th char is a space —
// indicating the last line of a multi-line reply.
func parseResponseLine(line string) (int, bool, bool) {
	if len(line) < 4 {
		return 0, false, false
	}
	codeStr := line[:3]
	c, err := strconv.Atoi(codeStr)
	if err != nil {
		return 0, false, false
	}
	final := line[3] == ' '
	return c, final, true
}

// textAfterDelimiter returns the text after the 4th character
// (the space or hyphen following the 3-digit code).
func textAfterDelimiter(line string) string {
	if len(line) < 5 {
		return ""
	}
	return line[4:]
}

func statusCategory(c int) string {
	switch {
	case c >= 200 && c < 300:
		return "Success"
	case c >= 300 && c < 400:
		return "Intermediate"
	case c >= 400 && c < 500:
		return "Transient_Error"
	case c >= 500 && c < 600:
		return "Permanent_Error"
	}
	return ""
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
