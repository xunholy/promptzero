// imap.go — host-side IMAP4rev1 (Internet Message Access
// Protocol v4) decoder Spec. Wraps the internal/imap walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/imap"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(imapDecodeSpec)
}

var imapDecodeSpec = Spec{
	Name: "imap4_decode",
	Description: "Decode an IMAP4rev1 (Internet Message Access Protocol v4 revision 1) " +
		"message per RFC 3501, plus the RFC 2595 (STARTTLS), RFC 2087 (QUOTA), " +
		"RFC 2342 (NAMESPACE), RFC 2177 (IDLE), and RFC 2971 (ID) extensions. " +
		"IMAP is the dominant modern mail-access protocol — TCP/143 (cleartext) " +
		"or TCP/993 (implicit-TLS, 'IMAPS'). It powers Exchange / Office 365 / " +
		"Google Workspace IMAP / Dovecot / Cyrus IMAP / Courier IMAP / Zimbra / " +
		"FastMail / Apple Mail / Thunderbird / iOS Mail / Outlook. Canonical " +
		"mail-server pentest target alongside POP3 and SMTP: credential brute-" +
		"force (LOGIN <user> <pass> cleartext command sent before STARTTLS!); " +
		"STARTTLS downgrade audit (CAPABILITY returns STARTTLS when supported); " +
		"SASL mechanism enumeration (CAPABILITY lists AUTH=PLAIN/LOGIN/CRAM-" +
		"MD5/DIGEST-MD5/SCRAM-SHA-1/SCRAM-SHA-256/XOAUTH2/GSSAPI); banner " +
		"fingerprinting (* OK greeting leaks server software + version); FETCH-" +
		"based content disclosure (1 UID FETCH 1:* BODY[] retrieves every " +
		"message in selected mailbox in one round-trip); IDLE abuse (server " +
		"push mode for persistent observer access). Decodes:\n\n" +
		"- **Four message kinds** discriminated by the first character of the " +
		"first line: **Continuation** (first char `+`; SASL multi-step server " +
		"prompt or APPEND literal upload); **Untagged Response** (first char " +
		"`*`; data response or status); **Command + Tagged Response** (first " +
		"char alphanumeric; disambiguated by second token — if it's OK/NO/BAD/" +
		"BYE/PREAUTH → Tagged Response, otherwise → Command).\n" +
		"- **25+ entry Verb name table** (RFC 3501 §6 + extensions): LOGIN " +
		"(cleartext credentials!) / AUTHENTICATE (SASL with continuation) / " +
		"SELECT (open mailbox r/w) / EXAMINE (read-only) / CREATE / DELETE / " +
		"RENAME / SUBSCRIBE / UNSUBSCRIBE / LIST (wildcards) / LSUB / STATUS " +
		"(query without SELECT) / APPEND (literal upload) / CHECK / CLOSE / " +
		"EXPUNGE / SEARCH / FETCH (content disclosure) / STORE (set flags) / " +
		"COPY / UID (variant prefix) / NOOP / LOGOUT / CAPABILITY / STARTTLS / " +
		"IDLE (server push per RFC 2177) / NAMESPACE / ID.\n" +
		"- **5-entry Status name table** (§7.1): OK (success) / NO (failure) " +
		"/ BAD (malformed) / BYE (server closing) / PREAUTH (server pre-" +
		"authenticated via Kerberos / IPsec / similar).\n" +
		"- **15+ entry Untagged Type name table** (data responses + status): " +
		"CAPABILITY / LIST / LSUB / STATUS / SEARCH / FLAGS / FETCH / EXISTS / " +
		"RECENT / EXPUNGE / NAMESPACE / QUOTA / QUOTAROOT / ID / ESEARCH " +
		"(RFC 4731) / ENABLED.\n" +
		"- **Numeric-prefix detection** — IMAP uses '* 12 EXISTS' format for " +
		"some untagged responses; the decoder surfaces the numeric prefix as " +
		"untagged_type and flags it via untagged_type_name 'numeric_prefix " +
		"(see untagged_data for real type)'.\n" +
		"- **Continuation prompt extraction** — text after '+ ' surfaced as " +
		"continuation_prompt for caller-side SASL exchange analysis.\n\n" +
		"Pure offline parser — operators paste IMAP bytes (the TCP-segment " +
		"payload as hex; default TCP port 143/993) from a `tcpdump -X port " +
		"143` line or a Wireshark IMAP dissector view and get the documented " +
		"per-kind breakdown.\n\n" +
		"Out of scope (deferred): network framing (feed bytes after the TCP-" +
		"segment header strip; default TCP port 143/993); STARTTLS / IMAPS " +
		"transport (after STARTTLS the connection upgrades to TLS — handle " +
		"TLS strip first); literal string body handling (IMAP {N}<CRLF>...<N " +
		"bytes> carries binary data inline for FETCH BODY[] + APPEND uploads; " +
		"surfaces literal-length marker but doesn't consume the following N " +
		"bytes); FETCH attribute parser (`FETCH (UID 12 FLAGS (\\Seen) " +
		"BODY[HEADER] {142}\\r\\n...)` nested attribute list surfaced as " +
		"untagged_data for caller-side parsing); MIME / RFC 5322 message body " +
		"parsing (FETCH BODY[] content is the mail body — separate decoder); " +
		"SASL mechanism decoding (AUTHENTICATE <mechanism> followed by server " +
		"+ challenge then base64 responses; per-mechanism PLAIN/CRAM-MD5/" +
		"SCRAM-SHA-256 decode is out of scope); RFC 5267 CONTEXT / RFC 5256 " +
		"SORT/THREAD / RFC 4467 URLAUTH / RFC 5464 METADATA / RFC 6855 UTF8 " +
		"extensions (verbs not in the name table surface as uncatalogued).\n\n" +
		"Source: docs/catalog/gap-analysis.md (mail-access dissector — " +
		"completes the email-protocol triad with smtp_decode + pop3_decode + " +
		"imap4_decode; canonical decode for Exchange / Office 365 / Google " +
		"Workspace / Dovecot / Cyrus IMAP / Courier IMAP servers; common in " +
		"DEF CON + HITB + CTF credential-spray + STARTTLS-downgrade + LOGIN " +
		"cleartext capture pentests). Wrap-vs-native: native — RFC 3501 is " +
		"publicly available; IMAP is a text-based protocol with four message " +
		"kinds + tag-pairing for request/response correlation + a fixed " +
		"verb registry + a 5-entry status name table; literal handling + " +
		"per-attribute FETCH parsing + per-mechanism SASL decoding are out " +
		"of scope; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"IMAP message bytes as hex (the TCP-segment payload; default TCP port 143/993). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   imapDecodeHandler,
}

func imapDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("imap4_decode: 'hex' is required")
	}
	res, err := imap.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("imap4_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
