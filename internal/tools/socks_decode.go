// socks_decode.go — host-side SOCKS proxy (SOCKS4 / 4a / 5) decoder Spec,
// delegating to internal/socks.
//
// Wrap-vs-native: native — a tiny fixed wire format (version + command/atyp
// + address + port); byte-field reads, stdlib only. The proxy / pivot /
// exfil-channel decoder: surfaces the proxied destination host:port from a
// captured SOCKS exchange. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/socks"
)

func init() { //nolint:gochecknoinits
	Register(socksDecodeSpec)
}

var socksDecodeSpec = Spec{
	Name: "socks_decode",
	Description: "Decode the **SOCKS proxy protocol** (SOCKS4 / SOCKS4a / SOCKS5, RFC 1928) — the proxy / pivot / " +
		"**exfiltration channel**. A captured SOCKS exchange is a network-reconnaissance source: the " +
		"**request reveals the proxied destination** (host or IP + port) a client is reaching *through* the " +
		"proxy — exactly what matters when analysing a capture for **data-exfiltration channels**, **malware " +
		"command-and-control** over a SOCKS proxy, or an attacker **pivoting** through a compromised host's " +
		"proxy. An application-layer complement to the project's other capture decoders.\n\n" +
		"Decodes: the SOCKS5 **greeting** (offered auth methods) and **method selection**; the SOCKS5 " +
		"**request / reply** — command (CONNECT / BIND / UDP-ASSOCIATE) or reply code, address type and the " +
		"**destination / bound address + port** (IPv4, IPv6 or domain name); and SOCKS4 / SOCKS4a requests " +
		"(command, destination, user-id, and the 4a domain) and the 8-byte SOCKS4 reply (status code).\n\n" +
		"No confidently-wrong output: implemented to RFC 1928 (the SOCKS5 domain is a 1-octet length + name " +
		"per §5, not DNS labels; a SOCKS4 reply is 8 bytes). Because a lone SOCKS5 message does not always " +
		"distinguish a request from a reply (both share cmd/rep + rsv + atyp + addr + port, and 1-3 are " +
		"valid as either), the unambiguous **destination address + port** is always surfaced and the leading " +
		"byte is reported as a command when it can only be one, a reply when it can only be that, and with " +
		"both readings noted when genuinely ambiguous. No network, no device, transmits nothing, so it is " +
		"Low risk. ':' / '-' / '_' / whitespace separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (SOCKS proxy / exfil-channel recon). Wrap-vs-native: native — " +
		"a byte-field read, stdlib only, no new go.mod dep. The IPv4 / IPv6 / SOCKS4 cases were cross-checked " +
		"against scapy; the SOCKS5 domain + SOCKS4 reply were hand-verified against RFC 1928 (scapy's layer " +
		"is non-standard for both).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"A single SOCKS message (the TCP payload) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   socksDecodeHandler,
}

func socksDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("socks_decode: 'hex' is required")
	}
	res, err := socks.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("socks_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
