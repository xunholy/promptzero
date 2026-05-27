// xmpp.go — host-side XMPP wire-protocol decoder Spec.
// Wraps the internal/xmpp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/xmpp"
)

func init() { //nolint:gochecknoinits
	Register(xmppDecodeSpec)
}

var xmppDecodeSpec = Spec{
	Name: "xmpp_decode",
	Description: "Decode an XMPP (Extensible Messaging and Presence Protocol) " +
		"stream fragment per RFC 6120 (core) and RFC 6121 (IM). TCP/5222 " +
		"client-to-server, TCP/5269 server-to-server, TCP/5280 BOSH/" +
		"WebSocket. Used by Jabber, ejabberd, Prosody, Openfire, Google " +
		"Talk (legacy), WhatsApp (modified wire format), Facebook Messenger " +
		"(legacy), and IoT systems (XEP-0323 sensor data, XEP-0325 " +
		"control). XMPP is a TEXT/XML streaming protocol — wire payloads " +
		"are UTF-8 encoded XML fragments.\n\n" +
		"The wire format leaks: **stream negotiation via <stream:stream>** " +
		"— to='domain' discloses the target server; <stream:features> " +
		"lists supported SASL mechanisms, STARTTLS availability + " +
		"requirement, and XEP capabilities; **SASL PLAIN cleartext " +
		"credentials** — <auth mechanism='PLAIN'> carries " +
		"base64(\\0username\\0password); on a non-TLS session this is a " +
		"passive-capture credential disclosure — many XMPP servers " +
		"present STARTTLS-optional, and IoT deployments often skip TLS " +
		"entirely; the decoder surfaces auth_data_length (base64 string " +
		"length) but NEVER decodes the credential bytes; **JID disclosure** " +
		"— every stanza's from/to attributes carry user@domain/resource " +
		"JIDs, disclosing user identity and client resource names; **roster " +
		"(contact-list) queries** — IQ stanzas with xmlns='jabber:iq:roster' " +
		"expose the user's full contact list; **service discovery** — IQ " +
		"stanzas with xmlns='http://jabber.org/protocol/disco#info' or " +
		"'#items' enumerate server capabilities; **MUC room names** — " +
		"<presence> or <message> to='room@conference.domain' disclose " +
		"organisation structure.\n\n" +
		"Detects and decodes:\n\n" +
		"- **stream_open** — `<?xml` or `<stream:stream` opening fragment; " +
		"extracts to_domain, version, xmlns (jabber:client / jabber:server).\n" +
		"- **stream_features** — `<stream:features>` block; extracts " +
		"mechanisms[] list, has_starttls, starttls_required.\n" +
		"- **auth** — `<auth mechanism='…'>` SASL initiation; extracts " +
		"mechanism name + auth_data_length (base64 length, NOT decoded " +
		"content); flags PLAIN as is_cleartext_auth.\n" +
		"- **message** — `<message>` stanza; extracts from_jid, to_jid, " +
		"stanza_id, stanza_subtype (chat / groupchat / headline / normal / " +
		"error); detects has_body (presence of <body> tag — content NOT " +
		"extracted).\n" +
		"- **presence** — `<presence>` stanza; extracts from_jid, to_jid, " +
		"stanza_id, stanza_subtype (unavailable / subscribe / subscribed / " +
		"unsubscribe / unsubscribed / probe / error).\n" +
		"- **iq** — `<iq>` info/query stanza; extracts from_jid, to_jid, " +
		"stanza_id, stanza_subtype (get / set / result / error); extracts " +
		"iq_namespace (xmlns of first child element — reveals roster / bind " +
		"/ session / disco#info / disco#items / pubsub / ping etc.).\n" +
		"- **starttls** — `<starttls>` client TLS-upgrade request.\n" +
		"- **success / failure** — SASL exchange result.\n" +
		"- **stream_close** — `</stream:stream>` session terminator.\n" +
		"- **is_cleartext_auth** — true when mechanism is PLAIN (base64 " +
		"cleartext credential on wire).\n" +
		"- **is_stream_negotiation** — true for stream_open + " +
		"stream_features.\n\n" +
		"Pure offline parser — paste XMPP bytes (the TCP-segment payload " +
		"hex; default TCP/5222) from tcpdump / Wireshark XMPP dissector " +
		"and get the per-stanza breakdown. The decoder uses lightweight " +
		"string scanning rather than a full XML parser so partial or " +
		"fragmented XML (e.g. a stream opening that spans segments) is " +
		"handled gracefully.\n\n" +
		"Out of scope: message body content extraction (has_body bool " +
		"only — content NEVER surfaced); SASL credential decoding " +
		"(auth_data_length only — base64 bytes NEVER decoded); TLS " +
		"handshake (handle at transport layer before passing to this tool); " +
		"full XML parsing or XEP stanza payload bodies beyond namespace " +
		"detection; BOSH / WebSocket framing (handle HTTP/WS layer first); " +
		"Multi-User Chat (MUC) internal protocol (XEP-0045) beyond room " +
		"JID extraction via to/from attributes; PubSub (XEP-0060) body " +
		"parsing; vCard / avatar / file-transfer extension bodies.\n\n" +
		"Source: gap analysis (enterprise IM + IoT messaging backbone — " +
		"canonical XMPP pentest dissector for stream-negotiation " +
		"fingerprinting + SASL mechanism enumeration + PLAIN cleartext " +
		"credential detection + JID disclosure + roster query detection; " +
		"pairs with ldap_decode + kerberos_decode for the complete " +
		"enterprise-directory attack surface; common in DEF CON + corporate " +
		"IM-server pentests + IoT XEP-0323/0325 deployments + ejabberd / " +
		"Prosody / Openfire reconnaissance). Wrap-vs-native: native — " +
		"XMPP is XML-over-TCP with a publicly documented stream grammar " +
		"(RFC 6120); lightweight string scanning handles partial fragments " +
		"that a strict XML parser would reject; no crypto at the parse " +
		"layer; credential bytes NEVER decoded.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"XMPP stream fragment bytes as hex (the TCP-segment payload; default TCP/5222 client-to-server, TCP/5269 server-to-server, TCP/5280 BOSH/WebSocket). Feed one stanza or stream fragment at a time. Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   xmppDecodeHandler,
}

func xmppDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("xmpp_decode: 'hex' is required")
	}
	res, err := xmpp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("xmpp_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
