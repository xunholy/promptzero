// ssdp.go — host-side SSDP (Simple Service Discovery Protocol)
// message decoder Spec. Wraps the internal/ssdp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/ssdp"
)

func init() { //nolint:gochecknoinits
	Register(ssdpDecodeSpec)
}

var ssdpDecodeSpec = Spec{
	Name: "ssdp_decode",
	Description: "Decode an SSDP (Simple Service Discovery Protocol) message per the " +
		"UPnP Device Architecture 1.1 (UPnP Forum, 2008). SSDP is the foundational " +
		"discovery layer for UPnP + DLNA + a broad swath of consumer IoT devices " +
		"— smart TVs, streaming receivers, media servers, NAS units, network " +
		"printers, routers (UPnP-IGD), smart-home hubs, and any device that wants " +
		"to advertise its presence on a LAN without prior configuration. Runs " +
		"over multicast UDP to 239.255.255.250:1900 (IPv4) or [FF02::C]:1900 " +
		"(IPv6 link-local). HTTP-over-UDP: every SSDP packet is a complete " +
		"HTTP/1.1 request or response line followed by Key: Value headers and a " +
		"blank line; no body. Operationally interesting to an attacker tapping " +
		"into a consumer / SMB network because (i) every UPnP device sends NOTIFY " +
		"announcements at ~30-minute intervals plus on every reboot; (ii) the " +
		"USN/LOCATION/SERVER/ST/NT headers leak device UUID + vendor description " +
		"URL + OS + UPnP version + product name + device type URN; (iii) UPnP-" +
		"IGD reachability has historically been the entry point for " +
		"unauthenticated NAT-traversal attacks (CVE-2020-12695 CallStranger); " +
		"(iv) smart-TV / Chromecast / Sonos enumeration yields enough metadata " +
		"to identify model + firmware version for downstream CVE lookup. " +
		"Decodes:\n\n" +
		"- **Three message kinds** discriminated by the first whitespace-" +
		"delimited token of the first line: M-SEARCH (search request with ST + " +
		"MAN + MX + HOST), NOTIFY (periodic device advertisement with NT + NTS " +
		"= ssdp:alive/byebye/update + USN + LOCATION + SERVER + CACHE-CONTROL), " +
		"HTTP/1.1 200 OK (unicast search response with ST + USN + LOCATION + " +
		"SERVER + CACHE-CONTROL).\n" +
		"- **Header parser** with case-insensitive key matching (RFC 7230). " +
		"Surfaces canonical UPnP fields as dedicated typed fields: Host, " +
		"Cache-Control (with max-age extraction as cache_max_age_seconds), " +
		"Location, Server, ST (Search Target), USN (Unique Service Name — with " +
		"deconstruction into usn_uuid + usn_nt when of form uuid:<UUID>::<NT>), " +
		"NT (Notification Type), NTS (Notification Subtype), MAN, MX, " +
		"BOOTID.UPNP.ORG, CONFIGID.UPNP.ORG, SEARCHPORT.UPNP.ORG.\n" +
		"- **Vendor / non-standard headers** surfaced as a generic " +
		"`other_headers` map for caller-side inspection (vendor-specific " +
		"headers like 01-NLS: for AXIS IP cameras or X-RINCON-HOUSEHOLD: for " +
		"Sonos groups are common).\n\n" +
		"Pure offline parser — operators paste SSDP bytes (the UDP payload as " +
		"hex; default UDP port 1900) from a `tcpdump -X port 1900` line or a " +
		"Wireshark SSDP dissector view and get the documented start-line + " +
		"header breakdown + canonical UPnP fields.\n\n" +
		"Out of scope (deferred): network framing (feed bytes after the UDP-" +
		"datagram header strip; UDP port 1900 multicast + occasional UDP/1900 " +
		"unicast for search responses); UPnP Description XML fetch (the " +
		"`LOCATION` header points at a per-device `rootDesc.xml` enumerating " +
		"services + control URLs — fetching + parsing that XML is a follow-on " +
		"step); UPnP Control / Eventing SOAP (the `controlURL` + `eventSubURL` " +
		"from the description XML are SOAP endpoints with per-action shapes); " +
		"SSDP-over-IPv6 (same wire format runs to [FF02::C]:1900 link-local, " +
		"[FF05::C]:1900 site-local, [FF08::C]:1900 organisation-local — this " +
		"decoder treats the bytes identically regardless of transport); DLNA / " +
		"OCF (Open Connectivity Foundation) extensions (additional headers " +
		"surfaced via the generic other_headers map); mDNS / DNS-SD discovery " +
		"(parallel discovery protocol on UDP/5353 with a different DNS-style " +
		"wire format — separate decoder).\n\n" +
		"Source: docs/catalog/gap-analysis.md (UPnP / consumer-IoT discovery " +
		"dissector — foundational IoT/consumer-network reconnaissance protocol; " +
		"common in DEF CON Wireless / Recon Village CTFs + home-network pentests " +
		"+ UPnP-IGD WAN-port-forwarding attack chains). Wrap-vs-native: native " +
		"— SSDP is a tiny text-based protocol — three message kinds (M-SEARCH " +
		"request, NOTIFY announcement, HTTP/1.1 response), CRLF-terminated " +
		"lines, and a flat header set; the UPnP Device Architecture 1.1 spec " +
		"is publicly available; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"SSDP message bytes as hex (the UDP payload; default UDP port 1900 multicast 239.255.255.250). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ssdpDecodeHandler,
}

func ssdpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ssdp_decode: 'hex' is required")
	}
	res, err := ssdp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("ssdp_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
