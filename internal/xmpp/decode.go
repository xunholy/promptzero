// Package xmpp decodes XMPP (Extensible Messaging and Presence Protocol)
// wire-protocol stanzas per RFC 6120 (core) and RFC 6121 (IM). Runs on
// TCP/5222 (client-to-server), TCP/5269 (server-to-server), TCP/5280
// (BOSH/WebSocket). Used by Jabber, ejabberd, Prosody, Openfire,
// Google Talk (legacy), WhatsApp (modified wire format), Facebook
// Messenger (legacy), and IoT systems (XEP-0323 sensor data, XEP-0325
// control).
//
// XMPP is a TEXT/XML streaming protocol, not binary. Each TCP connection
// carries an XML stream: the client opens <stream:stream …>, the server
// responds with its own <stream:stream …> followed by <stream:features>,
// then authentication (SASL), resource binding (<iq> bind), and finally
// normal stanza exchange (<message>, <presence>, <iq>).
//
// Operationally, XMPP is a **high-value enterprise and IoT messaging
// target** — many deployments still offer STARTTLS-optional (XMPP
// servers present both STARTTLS and non-TLS paths and the client
// decides), and SASL PLAIN over a non-TLS session transmits base64(
// \0username\0password) in cleartext on the wire. IoT deployments
// frequently skip TLS entirely. Roster queries (XEP-0237 / RFC 6121
// §2) expose full contact-list JIDs; MUC room names (XEP-0045) expose
// organisational structure.
//
// The wire format leaks:
//
//   - **Stream negotiation** — <stream:stream to='domain' ...> discloses
//     the target server domain and XMPP version; <stream:features> lists
//     supported SASL mechanisms, STARTTLS availability + requirement,
//     resource-bind support, and XEP capabilities.
//
//   - **SASL PLAIN cleartext credentials** — <auth mechanism='PLAIN'>
//     carries base64(\0username\0password); on a non-TLS session this is
//     a passive-capture credential disclosure. The decoder surfaces
//     auth_data_length (base64 string length) but NOT the decoded content.
//
//   - **JID disclosure** — every stanza's from/to attributes carry
//     user@domain/resource JIDs, disclosing user identity and client
//     resource names.
//
//   - **Roster (contact-list) queries** — IQ stanzas with xmlns=
//     'jabber:iq:roster' expose the user's full contact list.
//
//   - **Service discovery** — IQ stanzas with xmlns=
//     'http://jabber.org/protocol/disco#info' or '#items' enumerate
//     server capabilities and hosted services.
//
//   - **MUC room names** — <presence> to='room@conference.domain/nick'
//     and <message> to='room@conference.domain' disclose organisation
//     room structure.
//
// Wrap-vs-native judgement
//
//	Native. XMPP is XML over TCP; the wire payload is UTF-8 text.
//	The decoder uses lightweight string scanning rather than a full
//	XML parser because captured fragments may not be well-formed XML
//	(stream opening tags are never closed in a single segment, TLS
//	upgrade splices the stream, etc.). Simple substring + regex
//	attribute extraction gives robust partial-fragment handling.
//	No crypto at the parse layer.
//
// What this package covers
//
//   - **stanza_type detection**: stream_open, stream_features, auth,
//     message, presence, iq, starttls, success, failure, stream_close.
//   - **stream_open**: to_domain, version, xmlns extraction.
//   - **stream_features**: mechanisms list, has_starttls, starttls_required.
//   - **auth**: mechanism, auth_data_length (base64 length only).
//   - **message / presence / iq**: from_jid, to_jid, stanza_id,
//     stanza_subtype (type attribute).
//   - **message**: has_body (bool — presence of <body> tag, not content).
//   - **iq**: iq_namespace (xmlns of first child element).
//   - **is_cleartext_auth**: true when mechanism is PLAIN.
//   - **is_stream_negotiation**: true for stream_open and stream_features.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Message body content extraction** — <body> text is never surfaced.
//   - **SASL credential decoding** — auth_data_length only; NEVER decodes
//     the base64 auth data.
//   - **TLS handshake** — handle at the transport layer.
//   - **Full XML parsing** — fragments are handled by substring scan.
//   - **XEP stanza bodies** — payload elements beyond namespace detection.
//   - **BOSH / WebSocket framing** — handle HTTP/WS layer separately.
package xmpp

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// Result is the structured decode of an XMPP stanza or stream fragment.
type Result struct {
	TotalBytes int    `json:"total_bytes"`
	RawText    string `json:"raw_text,omitempty"`

	// StanzaType is the top-level XMPP element type detected.
	// Values: "stream_open", "stream_features", "auth", "message",
	// "presence", "iq", "starttls", "success", "failure",
	// "stream_close", "unknown".
	StanzaType string `json:"stanza_type"`

	// Stream open fields (stanza_type == "stream_open")
	ToDomain string `json:"to_domain,omitempty"`
	Version  string `json:"version,omitempty"`
	Xmlns    string `json:"xmlns,omitempty"`

	// Stream features fields (stanza_type == "stream_features")
	Mechanisms       []string `json:"mechanisms,omitempty"`
	HasStartTLS      bool     `json:"has_starttls,omitempty"`
	StartTLSRequired bool     `json:"starttls_required,omitempty"`

	// Auth fields (stanza_type == "auth")
	Mechanism      string `json:"mechanism,omitempty"`
	AuthDataLength int    `json:"auth_data_length,omitempty"`

	// Common stanza fields (message / presence / iq)
	FromJID       string `json:"from_jid,omitempty"`
	ToJID         string `json:"to_jid,omitempty"`
	StanzaID      string `json:"stanza_id,omitempty"`
	StanzaSubtype string `json:"stanza_subtype,omitempty"`

	// Message-specific
	HasBody bool `json:"has_body,omitempty"`

	// IQ-specific
	IQNamespace string `json:"iq_namespace,omitempty"`

	// Security flags
	IsCleartextAuth     bool   `json:"is_cleartext_auth,omitempty"`
	CleartextAuthFlag   string `json:"cleartext_auth_flag,omitempty"`
	IsStreamNegotiation bool   `json:"is_stream_negotiation,omitempty"`
}

// attrRe builds a regexp that extracts the value of an XML attribute by
// exact name match. It matches both single and double quoted values.
func attrRe(name string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)` + regexp.QuoteMeta(name) + `\s*=\s*(?:"([^"]*)"|'([^']*)')`)
}

var (
	reAttrTo        = attrRe("to")
	reAttrVersion   = attrRe("version")
	reAttrMechanism = attrRe("mechanism")
	reAttrFrom      = attrRe("from")
	reAttrType      = attrRe("type")
	reAttrID        = attrRe("id")

	// reDefaultXmlns matches a bare xmlns='...' or xmlns="..." attribute —
	// i.e. xmlns not followed by ':' (which would be a namespace prefix
	// declaration like xmlns:stream='...'). Used to extract jabber:client /
	// jabber:server from the stream opening tag.
	reDefaultXmlns = regexp.MustCompile(`(?i)\bxmlns\s*=\s*(?:"([^"]*)"|'([^']*)')`)

	// reMechanism matches <mechanism>VALUE</mechanism> inside stream features.
	reMechanism = regexp.MustCompile(`(?i)<mechanism[^>]*>([^<]+)</mechanism>`)

	// reIQChildXmlns matches the xmlns attribute of the first child element
	// inside an <iq> stanza to reveal the query namespace.
	reIQChildXmlns = regexp.MustCompile(`(?i)<[a-zA-Z:_][a-zA-Z0-9:._-]*[^>]+xmlns\s*=\s*(?:"([^"]*)"|'([^']*)')`)
)

// extractAttr extracts the value of a named XML attribute from s using
// a pre-compiled regexp. Returns "" if not found.
func extractAttr(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	// m[1] is the double-quoted value, m[2] is the single-quoted value.
	if m[1] != "" {
		return m[1]
	}
	return m[2]
}

// Decode parses an XMPP stream fragment from a hex string.
// The input is expected to be the TCP-segment payload hex of an XMPP
// connection on TCP/5222, TCP/5269, or TCP/5280.
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

	text := string(b)
	r := &Result{
		TotalBytes: len(b),
		RawText:    text,
	}

	detect(r, text)
	return r, nil
}

// detect classifies the stanza type and fills in the Result fields.
func detect(r *Result, text string) {
	switch {
	case strings.Contains(text, "</stream:stream>") || text == "</stream:stream>":
		r.StanzaType = "stream_close"

	case strings.Contains(text, "<stream:stream") || strings.Contains(text, "<?xml"):
		r.StanzaType = "stream_open"
		r.IsStreamNegotiation = true
		r.ToDomain = extractAttr(reAttrTo, text)
		r.Version = extractAttr(reAttrVersion, text)
		// Extract the default namespace (xmlns without a prefix).
		// We want xmlns='jabber:client' or xmlns="jabber:server", not
		// xmlns:stream or xmlns:something.
		r.Xmlns = extractDefaultXmlns(text)

	case strings.Contains(text, "<stream:features"):
		r.StanzaType = "stream_features"
		r.IsStreamNegotiation = true
		r.HasStartTLS = strings.Contains(text, "starttls")
		r.StartTLSRequired = strings.Contains(text, "<required")
		mechs := reMechanism.FindAllStringSubmatch(text, -1)
		for _, m := range mechs {
			if len(m) >= 2 {
				r.Mechanisms = append(r.Mechanisms, strings.TrimSpace(m[1]))
			}
		}

	case strings.Contains(text, "<auth ") || strings.Contains(text, "<auth>"):
		r.StanzaType = "auth"
		r.Mechanism = extractAttr(reAttrMechanism, text)
		// Extract the base64 auth data (content between <auth ...> and </auth>)
		// but only record its length, never the content.
		r.AuthDataLength = extractAuthDataLength(text)
		if strings.EqualFold(r.Mechanism, "PLAIN") {
			r.IsCleartextAuth = true
			r.CleartextAuthFlag = "SASL PLAIN — auth data is base64(\\0username\\0password); " +
				"cleartext credentials on non-TLS XMPP session (TCP/5222); " +
				"passive-capture yields immediate credential access"
		}

	case strings.Contains(text, "<starttls"):
		r.StanzaType = "starttls"

	case strings.Contains(text, "<proceed") || strings.Contains(text, "<success"):
		r.StanzaType = "success"

	case strings.Contains(text, "<failure"):
		r.StanzaType = "failure"

	case strings.Contains(text, "<message ") || strings.Contains(text, "<message>"):
		r.StanzaType = "message"
		r.FromJID = extractAttr(reAttrFrom, text)
		r.ToJID = extractAttr(reAttrTo, text)
		r.StanzaID = extractAttr(reAttrID, text)
		r.StanzaSubtype = extractAttr(reAttrType, text)
		r.HasBody = strings.Contains(text, "<body") || strings.Contains(text, "<body>")

	case strings.Contains(text, "<presence ") || strings.Contains(text, "<presence>") ||
		strings.Contains(text, "<presence/>"):
		r.StanzaType = "presence"
		r.FromJID = extractAttr(reAttrFrom, text)
		r.ToJID = extractAttr(reAttrTo, text)
		r.StanzaID = extractAttr(reAttrID, text)
		r.StanzaSubtype = extractAttr(reAttrType, text)

	case strings.Contains(text, "<iq ") || strings.Contains(text, "<iq>"):
		r.StanzaType = "iq"
		r.FromJID = extractAttr(reAttrFrom, text)
		r.ToJID = extractAttr(reAttrTo, text)
		r.StanzaID = extractAttr(reAttrID, text)
		r.StanzaSubtype = extractAttr(reAttrType, text)
		r.IQNamespace = extractIQNamespace(text)

	default:
		r.StanzaType = "unknown"
	}
}

// extractDefaultXmlns finds the bare xmlns attribute (not xmlns:prefix)
// in an XML start tag. This is used to find xmlns='jabber:client' in
// the stream:stream opening tag without accidentally matching
// xmlns:stream='http://etherx.jabber.org/streams'.
func extractDefaultXmlns(text string) string {
	matches := reDefaultXmlns.FindAllStringSubmatch(text, -1)
	for _, m := range matches {
		val := m[1]
		if val == "" {
			val = m[2]
		}
		// Skip namespace prefix declarations like xmlns:stream=...
		// Check the character just before the match position is not ':'.
		idx := strings.Index(text, m[0])
		if idx > 0 && text[idx-1] == ':' {
			continue
		}
		// Skip http://etherx.jabber.org/streams (that's the stream namespace).
		if strings.Contains(val, "etherx.jabber.org") {
			continue
		}
		return val
	}
	return ""
}

// extractAuthDataLength finds the base64 content between <auth ...> and
// </auth> and returns its length (NOT the decoded content).
func extractAuthDataLength(text string) int {
	// Find content between > and </auth>
	start := strings.Index(text, ">")
	end := strings.Index(text, "</auth>")
	if start < 0 || end < 0 || end <= start {
		return 0
	}
	content := strings.TrimSpace(text[start+1 : end])
	return len(content)
}

// extractIQNamespace finds the xmlns attribute of the first non-trivial
// child element inside an <iq> stanza. This reveals the query namespace
// (e.g. jabber:iq:roster, urn:ietf:params:xml:ns:xmpp-bind, etc.).
func extractIQNamespace(text string) string {
	// Find the opening of the iq element, then look past it for child tags.
	iqStart := strings.Index(text, "<iq")
	if iqStart < 0 {
		return ""
	}
	// Find the end of the <iq ...> opening tag.
	tagEnd := strings.Index(text[iqStart:], ">")
	if tagEnd < 0 {
		return ""
	}
	rest := text[iqStart+tagEnd+1:]

	// Find first child element's xmlns.
	m := reIQChildXmlns.FindStringSubmatch(rest)
	if m == nil {
		return ""
	}
	if m[1] != "" {
		return m[1]
	}
	return m[2]
}

// stripSeparators removes common hex formatting characters and the
// optional 0x prefix. Identical to the implementation in internal/kafka.
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
