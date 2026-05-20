// pop3.go — host-side POP3 (Post Office Protocol v3) decoder
// Spec. Wraps the internal/pop3 walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/pop3"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(pop3DecodeSpec)
}

var pop3DecodeSpec = Spec{
	Name: "pop3_decode",
	Description: "Decode a POP3 (Post Office Protocol v3) message per RFC 1939, plus the " +
		"RFC 2449 (CAPA), RFC 2595 (STLS), and RFC 5034 (AUTH SASL) extensions. " +
		"POP3 is the mail-retrieval counterpart to SMTP — TCP/110 (cleartext) " +
		"or TCP/995 (implicit-TLS, 'POP3S'). Operationally interesting to a " +
		"mail-server pentester for credential brute-force (USER/PASS canonical " +
		"pattern; -ERR feedback differs between unknown user and bad password " +
		"on older Dovecot/Courier configurations — classic username-enumeration " +
		"vector); STLS downgrade audit (CAPA returns STLS when the server " +
		"supports opportunistic TLS upgrade; clients that don't enforce TLS can " +
		"be stripped to cleartext); SASL mechanism enumeration (AUTH with no " +
		"args lists supported mechanisms LOGIN/PLAIN/CRAM-MD5/DIGEST-MD5/SCRAM-" +
		"SHA-1/SCRAM-SHA-256/XOAUTH2/GSSAPI); banner fingerprinting (+OK greeting " +
		"leaks MTA software + version); APOP timestamp leakage (legacy +OK " +
		"<timestamp> banner used by MD5-challenge auth leaks server hostname + " +
		"timestamp; combined with known plaintext PASS, the APOP MD5 digest is " +
		"trivially crackable offline). Decodes:\n\n" +
		"- **Two message kinds** discriminated by the first character of the " +
		"first line: **Server Response** (first line starts with +OK positive " +
		"or -ERR negative; for multi-line responses to LIST/RETR/TOP/UIDL/CAPA " +
		"the server emits the first +OK <text>\\r\\n line then a sequence of " +
		"data lines terminating with a line containing a single '.' per RFC " +
		"1939 §3 with byte-stuffing — any data line starting with '.' has an " +
		"extra '.' prepended on the wire; the decoder removes the byte-" +
		"stuffing); **Client Command** (first line starts with an ASCII letter; " +
		"verb + optional argument).\n" +
		"- **15+ entry Verb name table** (RFC 1939 + extensions): USER " +
		"(authentication username — first half of 2-step USER/PASS login) / " +
		"PASS (authentication password — second half; sent in CLEARTEXT before " +
		"STLS!) / APOP (legacy MD5-challenge authentication — APOP <user> " +
		"<md5-digest>; the digest is MD5(<banner-timestamp> + <password>)) / " +
		"STAT (mailbox status — +OK <count> <octets>) / LIST (mailbox list — " +
		"single-line per-message reply, or multi-line with '.' terminator when " +
		"no argument) / RETR (retrieve message — multi-line) / DELE (mark for " +
		"deletion, committed on QUIT in TRANSACTION state) / NOOP (keep-alive) " +
		"/ RSET (reset deletion marks) / QUIT (close session, trigger UPDATE " +
		"state, commit DELEs) / TOP (retrieve headers + N body lines — multi-" +
		"line) / UIDL (unique-id list — multi-line or single-line per-message) " +
		"/ STLS (opportunistic TLS upgrade per RFC 2595) / CAPA (capability " +
		"list per RFC 2449 — multi-line) / AUTH (SASL authentication per RFC " +
		"5034).\n" +
		"- **Status indicator categorisation**: +OK → Success; -ERR → Error.\n" +
		"- **Multi-line data aggregation** — when the response is a +OK " +
		"followed by additional data lines terminated by a single '.' on a " +
		"line, the decoder captures the data lines (with byte-stuffing removed " +
		"per RFC 1939 §3) into the data_lines slice for caller-side " +
		"processing.\n\n" +
		"Pure offline parser — operators paste POP3 bytes (the TCP-segment " +
		"payload as hex; default TCP port 110/995) from a `tcpdump -X port " +
		"110` line or a Wireshark POP3 dissector view and get the documented " +
		"command/response breakdown.\n\n" +
		"Out of scope (deferred): network framing (feed bytes after the TCP-" +
		"segment header strip; default TCP port 110/995); STLS / POP3S " +
		"transport (after STLS the connection upgrades to TLS — handle the TLS " +
		"strip first); RFC 5322 message body parsing (bytes between +OK ...\\r\\n " +
		"and \\r\\n.\\r\\n for RETR are the RFC 5322 mail body with optional MIME " +
		"per RFC 2045 — separate decoder; surfaced as raw data_lines); APOP " +
		"digest verification (MD5 digest is the second whitespace-delimited " +
		"token of the APOP command argument; verification against the server-" +
		"side password is out of scope); SASL mechanism decoding (AUTH " +
		"<mechanism> is followed by server + challenge then base64 responses; " +
		"per-mechanism decoding is out of scope).\n\n" +
		"Source: docs/catalog/gap-analysis.md (mail-retrieval dissector — " +
		"pairs with smtp_decode for the email-protocol pair; canonical decode " +
		"for Dovecot / Courier / qmail-pop3d / Exchange POP3 / Office 365 POP3 " +
		"/ Google Workspace POP3 servers; common in DEF CON + HITB + CTF " +
		"credential-spray + APOP timestamp-leakage puzzles; foundational mail-" +
		"server pentest tool for username enumeration via USER/PASS error " +
		"divergence, STLS downgrade audit, SASL mechanism enumeration). Wrap-" +
		"vs-native: native — RFC 1939 is publicly available; POP3 is a tiny " +
		"text-based protocol with two message kinds + CRLF-terminated lines + " +
		"a 15-entry verb registry + a 2-state status indicator (+OK / -ERR); " +
		"multi-line response framing per §3 with `.` terminator + byte-" +
		"stuffing; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"POP3 message bytes as hex (the TCP-segment payload; default TCP port 110/995). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   pop3DecodeHandler,
}

func pop3DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("pop3_decode: 'hex' is required")
	}
	res, err := pop3.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("pop3_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
