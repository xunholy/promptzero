// smtp.go — host-side SMTP (Simple Mail Transfer Protocol)
// decoder Spec. Wraps the internal/smtp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/smtp"
)

func init() { //nolint:gochecknoinits
	Register(smtpDecodeSpec)
}

var smtpDecodeSpec = Spec{
	Name: "smtp_decode",
	Description: "Decode an SMTP (Simple Mail Transfer Protocol) message per RFC 5321 — " +
		"the 40-year-old text-based protocol every mail server speaks. Default " +
		"ports: TCP/25 (mail exchange between MTAs), TCP/587 (mail submission " +
		"with STARTTLS), TCP/465 (implicit-TLS submission 'SMTPS'). The canonical " +
		"text protocol on the boundary between MTAs (Exim, Postfix, Sendmail, " +
		"Exchange, Office 365 Exchange Online, Google Workspace, Mailcow, Mailgun, " +
		"SendGrid). Interesting to a mail-server pentester for: open-relay " +
		"testing (classic MAIL FROM/RCPT TO sequence detects whether a server " +
		"accepts mail for non-local recipients); user enumeration (VRFY user " +
		"returns 250 if mailbox exists, 550 if not; EXPN list expands mailing-" +
		"list members; RCPT TO fallback when VRFY disabled); STARTTLS downgrade " +
		"audit (EHLO response lists STARTTLS extension; clients that don't " +
		"enforce TLS can be downgraded); authentication enumeration (AUTH listing " +
		"in EHLO reveals supported SASL mechanisms LOGIN/PLAIN/CRAM-MD5/DIGEST-" +
		"MD5/SCRAM-SHA-1/SCRAM-SHA-256/XOAUTH2/GSSAPI); banner fingerprinting " +
		"(220 banner leaks MTA software + version). Decodes:\n\n" +
		"- **Two message kinds** discriminated by the first character of the " +
		"first line: **Server Response** (first line starts with a 3-digit " +
		"ASCII status code) with multi-line support per RFC 5321 §4.2.1 " +
		"(<code>-<text> intermediate, <code> <text> final); **Client Command** " +
		"(first line starts with an ASCII letter) — verb + optional argument.\n" +
		"- **14+ entry Verb name table** (RFC 5321 §4.1.1 + RFC 1869 EHLO + RFC " +
		"1652 8BITMIME + RFC 3030 BDAT + RFC 4954 AUTH + RFC 3207 STARTTLS): " +
		"HELO / EHLO / AUTH / MAIL / RCPT / DATA / RSET / VRFY (user-enumeration " +
		"target) / EXPN / QUIT / STARTTLS (TLS upgrade trigger) / HELP / NOOP / " +
		"BDAT.\n" +
		"- **HTTP-style status code categorisation**: 2xx Success (220 banner / " +
		"221 closing / 250 OK / 251 forward) / 3xx Intermediate (354 start mail " +
		"input — only DATA gets this) / 4xx Transient_Error (421 service " +
		"unavailable / 450 mailbox busy / 451 local processing / 452 storage) " +
		"/ 5xx Permanent_Error (500 syntax / 501 parameters / 502 not " +
		"implemented / 503 bad sequence / 504 unrecognised parameter / 535 " +
		"auth failed / 550 mailbox unavailable / 553 mailbox not allowed / " +
		"554 transaction failed). Surfaced as status_category.\n" +
		"- **Multi-line response aggregation** — server replies to EHLO " +
		"frequently span 5+ lines (one per extension); decoder walks the entire " +
		"input collecting every line that shares the same status code, exposes " +
		"the full list as `lines`, and identifies the final line (space-after-" +
		"code) as `final_line_text` for caller convenience.\n" +
		"- **EHLO extension list** — when the server responds to EHLO with a " +
		"multi-line 250 reply, every line after the first contains a supported " +
		"extension keyword (SIZE 35882577 / 8BITMIME / STARTTLS / AUTH LOGIN " +
		"PLAIN / ENHANCEDSTATUSCODES / etc.); surfaced as `ehlo_extensions`.\n\n" +
		"Pure offline parser — operators paste SMTP bytes (the TCP-segment " +
		"payload as hex; default TCP port 25/587/465) from a `tcpdump -X port " +
		"25` line or a Wireshark SMTP dissector view and get the documented " +
		"command/response breakdown.\n\n" +
		"Out of scope (deferred): network framing (feed bytes after the TCP-" +
		"segment header strip; default TCP port 25 / 587 / 465); STARTTLS / " +
		"SMTPS transport (after a successful STARTTLS handshake the connection " +
		"upgrades to TLS — handle the TLS strip first before feeding the " +
		"decrypted bytes back); MIME / mail body parsing (bytes between 354 " +
		"server reply and \\r\\n.\\r\\n terminator are the RFC 5322 mail body " +
		"with optional MIME structure per RFC 2045 — separate decoder); SASL " +
		"mechanism decoding (AUTH command arguments are SASL mechanism + " +
		"optional initial response base64-encoded; surfaced as raw strings; " +
		"per-mechanism decoding PLAIN → username+password, CRAM-MD5 → " +
		"challenge+HMAC, SCRAM-SHA-1 → 5-message exchange is out of scope); " +
		"DKIM/DMARC/SPF (DNS-side anti-spam machinery); submission queue + " +
		"bounce handling.\n\n" +
		"Source: docs/catalog/gap-analysis.md (email-server dissector — " +
		"canonical decode for Exim / Postfix / Sendmail / Exchange / Office 365 " +
		"/ Google Workspace / Mailcow MTAs; common in DEF CON + HITB + CTF " +
		"open-relay + UCEPROTECT-list + DKIM/DMARC alignment puzzles; " +
		"foundational mail-server pentest tool for user enumeration via VRFY/" +
		"EXPN/RCPT, STARTTLS downgrade audit, SASL mechanism enumeration). " +
		"Wrap-vs-native: native — RFC 5321 is publicly available; SMTP is a " +
		"tiny text-based protocol with two message kinds + CRLF-terminated " +
		"lines + a fixed verb registry + a 3-digit status code scheme; no " +
		"crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"SMTP message bytes as hex (the TCP-segment payload; default TCP port 25/587/465). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   smtpDecodeHandler,
}

func smtpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("smtp_decode: 'hex' is required")
	}
	res, err := smtp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("smtp_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
