// Package ssdp decodes SSDP (Simple Service Discovery Protocol)
// messages per the UPnP Device Architecture 1.1 (UPnP Forum,
// 2008). SSDP is the foundational discovery layer for UPnP +
// DLNA + a broad swath of consumer IoT devices — smart TVs,
// streaming receivers, media servers, NAS units, network
// printers, routers (UPnP-IGD), smart-home hubs, and any device
// that wants to advertise its presence on a LAN without prior
// configuration.
//
// SSDP runs over **multicast UDP** to 239.255.255.250:1900 (IPv4)
// or `[FF02::C]:1900` (IPv6 link-local). The protocol is
// HTTP-over-UDP — every SSDP packet is a complete HTTP/1.1
// request or response line followed by `Key: Value` headers and
// a blank line. There is no body.
//
// Operationally, an attacker tapping into a consumer / SMB
// network sees SSDP first because:
//
//   - **It's chatty by design.** Every UPnP device sends NOTIFY
//     announcements at ~30-minute intervals (per the
//     CACHE-CONTROL max-age semantics) plus on every reboot.
//   - **It leaks every device's identity.** The USN header
//     carries a UUID; LOCATION points at a vendor-specific
//     `rootDesc.xml`; SERVER carries OS + UPnP version + product
//     name; ST/NT carries the device type (e.g.
//     `urn:schemas-upnp-org:device:MediaServer:1`).
//   - **UPnP-IGD reachability** — routers that respond to
//     `M-SEARCH ST: urn:schemas-upnp-org:device:InternetGateway
//     Device:1` expose their WAN-port-forwarding control URL,
//     which has historically been the entry point for
//     unauthenticated NAT-traversal attacks (CVE-2020-12695
//     CallStranger, the BlackHat 2008 "Hacking the UPnP" talk,
//     the Conficker self-propagation primitive).
//   - **Smart-TV / Chromecast / Sonos enumeration** — every
//     consumer media device sends NOTIFY announcements with
//     enough metadata to identify model + firmware version, a
//     starting point for downstream CVE lookup.
//
// Wrap-vs-native judgement
//
//	Native. SSDP is a tiny text-based protocol — three message
//	kinds (M-SEARCH request, NOTIFY announcement, HTTP/1.1
//	response), CRLF-terminated lines, and a flat header set.
//	The UPnP Device Architecture 1.1 spec is publicly available;
//	canonical header names are documented in §1.3 (Discovery)
//	and §2.3 (Description). No crypto at the parse layer.
//
// What this package covers
//
//   - **Three message kinds** discriminated by the first
//     whitespace-delimited token of the first line:
//
//   - **`M-SEARCH * HTTP/1.1`** — search request sent by a
//     client looking for devices. Carries `ST` (Search
//     Target), `MAN` (= `"ssdp:discover"`), `MX`
//     (Maximum response delay seconds — receivers spread
//     responses over this many seconds to avoid storm),
//     and `HOST` (always `239.255.255.250:1900`).
//
//   - **`NOTIFY * HTTP/1.1`** — periodic advertisement
//     sent by a device. Carries `NT` (Notification Type
//     — device type URN), `NTS` (Notification Subtype:
//     `ssdp:alive` for advertisement, `ssdp:byebye` for
//     planned shutdown, `ssdp:update` for boot-id
//     change), `USN` (Unique Service Name —
//     `uuid:<deviceUUID>::<nt>`), `LOCATION` (URL of the
//     XML description document), `SERVER` (UA-style OS
//
//   - UPnP version + product string), `CACHE-CONTROL`
//     (`max-age=<seconds>` — refresh interval).
//
//   - **`HTTP/1.1 200 OK`** — unicast search response a
//     device sends in reply to an M-SEARCH. Carries
//     `ST` (echoes the request's Search Target), `USN`,
//     `LOCATION`, `SERVER`, `CACHE-CONTROL`.
//
//   - **Header parser** — case-insensitive key matching
//     (per RFC 7230, all HTTP-style protocols are case-
//     insensitive on header field names). Surfaces:
//
//   - `Host`, `Cache-Control`, `Location`, `Server`,
//     `ST` (Search Target), `USN` (Unique Service Name),
//     `NT` (Notification Type), `NTS` (Notification
//     Subtype), `MAN`, `MX`, `BOOTID.UPNP.ORG`,
//     `CONFIGID.UPNP.ORG`, `SEARCHPORT.UPNP.ORG` —
//     each as a dedicated typed field.
//
//   - All other headers — surfaced as a generic
//     `other_headers` map for caller-side inspection
//     (vendor-specific headers like `01-NLS:` for AXIS
//     IP cameras or `X-RINCON-HOUSEHOLD:` for Sonos
//     groups are common).
//
//   - **`max-age` extraction** — when `Cache-Control`
//     starts with `max-age=`, the integer seconds value
//     is surfaced as `cache_max_age_seconds`.
//
//   - **`USN` deconstruction** — when the USN starts
//     with `uuid:<UUID>`, the UUID portion is surfaced
//     as `usn_uuid` and the trailing `::<NT>` (if
//     present) as `usn_nt`.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Network framing** — feed SSDP bytes after the UDP-
//     datagram header strip (UDP port 1900 multicast +
//     occasional UDP/1900 unicast for search responses).
//   - **UPnP Description XML fetch** — the `LOCATION` header
//     points at a per-device `rootDesc.xml` that enumerates
//     services + control URLs; fetching + parsing that XML
//     is a follow-on step (the `mcpfed:upnp_describe` style
//     Spec).
//   - **UPnP Control / Eventing SOAP** — the `controlURL` +
//     `eventSubURL` from the description XML are SOAP
//     endpoints with their own per-action shapes; out of
//     scope.
//   - **SSDP-over-IPv6** — the same wire format runs to
//     `[FF02::C]:1900` (link-local), `[FF05::C]:1900` (site-
//     local), and `[FF08::C]:1900` (organisation-local); this
//     decoder treats the bytes identically regardless of
//     transport.
//   - **DLNA / OCF (Open Connectivity Foundation) extensions**
//     — DLNA + OCF layer additional headers on top of base
//     SSDP; surfaced via the generic `other_headers` map.
//   - **mDNS / DNS-SD discovery** — a parallel discovery
//     protocol on UDP/5353 with a different (DNS-style) wire
//     format. Separate decoder.
package ssdp

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// MessageKind enumerates the three SSDP message kinds.
type MessageKind string

const (
	KindSearch       MessageKind = "M-SEARCH"
	KindNotify       MessageKind = "NOTIFY"
	KindResponse     MessageKind = "RESPONSE"
	KindUncatalogued MessageKind = "uncatalogued"
)

// Result is the structured decode of an SSDP message.
type Result struct {
	TotalBytes int         `json:"total_bytes"`
	Kind       MessageKind `json:"kind"`
	StartLine  string      `json:"start_line"`

	// HTTP/1.1 response only.
	StatusCode   int    `json:"status_code,omitempty"`
	StatusPhrase string `json:"status_phrase,omitempty"`

	// Headers documented in UPnP Device Architecture 1.1.
	Host            string `json:"host,omitempty"`
	CacheControl    string `json:"cache_control,omitempty"`
	CacheMaxAgeSecs int    `json:"cache_max_age_seconds,omitempty"`
	Location        string `json:"location,omitempty"`
	Server          string `json:"server,omitempty"`
	ST              string `json:"st_search_target,omitempty"`
	USN             string `json:"usn,omitempty"`
	USNUUID         string `json:"usn_uuid,omitempty"`
	USNNT           string `json:"usn_nt,omitempty"`
	NT              string `json:"nt_notification_type,omitempty"`
	NTS             string `json:"nts_notification_subtype,omitempty"`
	MAN             string `json:"man,omitempty"`
	MX              int    `json:"mx_max_seconds,omitempty"`
	BootID          string `json:"bootid_upnp_org,omitempty"`
	ConfigID        string `json:"configid_upnp_org,omitempty"`
	SearchPort      string `json:"searchport_upnp_org,omitempty"`

	// Vendor / non-standard headers.
	OtherHeaders map[string]string `json:"other_headers,omitempty"`
}

// Decode parses an SSDP message from a hex string. Separators
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
	if len(b) < 4 {
		return nil, fmt.Errorf("SSDP message truncated (%d bytes; need ≥4)", len(b))
	}

	r := &Result{TotalBytes: len(b)}
	scanner := bufio.NewScanner(strings.NewReader(string(b)))
	scanner.Buffer(make([]byte, 0, 64*1024), 64*1024)
	if !scanner.Scan() {
		return nil, fmt.Errorf("no start line")
	}
	r.StartLine = strings.TrimRight(scanner.Text(), "\r")
	r.Kind = classifyStartLine(r.StartLine)
	if r.Kind == KindResponse {
		r.StatusCode, r.StatusPhrase = parseStatusLine(r.StartLine)
	}

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" {
			continue
		}
		key, val, ok := splitHeader(line)
		if !ok {
			continue
		}
		r.applyHeader(key, val)
	}
	return r, nil
}

func classifyStartLine(line string) MessageKind {
	upper := strings.ToUpper(line)
	switch {
	case strings.HasPrefix(upper, "M-SEARCH "):
		return KindSearch
	case strings.HasPrefix(upper, "NOTIFY "):
		return KindNotify
	case strings.HasPrefix(upper, "HTTP/1.1 ") || strings.HasPrefix(upper, "HTTP/1.0 "):
		return KindResponse
	}
	return KindUncatalogued
}

func parseStatusLine(line string) (int, string) {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return 0, ""
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, ""
	}
	phrase := ""
	if len(parts) == 3 {
		phrase = parts[2]
	}
	return code, phrase
}

func splitHeader(line string) (string, string, bool) {
	idx := strings.Index(line, ":")
	if idx <= 0 {
		return "", "", false
	}
	key := strings.TrimSpace(line[:idx])
	val := strings.TrimSpace(line[idx+1:])
	return key, val, true
}

func (r *Result) applyHeader(key, val string) {
	switch strings.ToUpper(key) {
	case "HOST":
		r.Host = val
	case "CACHE-CONTROL":
		r.CacheControl = val
		r.CacheMaxAgeSecs = extractMaxAge(val)
	case "LOCATION":
		r.Location = val
	case "SERVER":
		r.Server = val
	case "ST":
		r.ST = val
	case "USN":
		r.USN = val
		r.USNUUID, r.USNNT = splitUSN(val)
	case "NT":
		r.NT = val
	case "NTS":
		r.NTS = val
	case "MAN":
		r.MAN = val
	case "MX":
		if n, err := strconv.Atoi(val); err == nil {
			r.MX = n
		}
	case "BOOTID.UPNP.ORG":
		r.BootID = val
	case "CONFIGID.UPNP.ORG":
		r.ConfigID = val
	case "SEARCHPORT.UPNP.ORG":
		r.SearchPort = val
	default:
		if r.OtherHeaders == nil {
			r.OtherHeaders = map[string]string{}
		}
		r.OtherHeaders[key] = val
	}
}

// extractMaxAge pulls the integer seconds out of a Cache-Control
// `max-age=N` directive (case-insensitive; comma-separated list
// permitted). Returns 0 if no max-age directive is present.
func extractMaxAge(cc string) int {
	for _, part := range strings.Split(cc, ",") {
		p := strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(p), "max-age=") {
			if n, err := strconv.Atoi(p[8:]); err == nil {
				return n
			}
		}
	}
	return 0
}

// splitUSN deconstructs a USN of the form `uuid:<uuid>::<nt>`.
// Returns (uuid, nt). Missing parts return empty strings.
func splitUSN(usn string) (string, string) {
	if !strings.HasPrefix(strings.ToLower(usn), "uuid:") {
		return "", ""
	}
	rest := usn[5:]
	if idx := strings.Index(rest, "::"); idx > 0 {
		return rest[:idx], rest[idx+2:]
	}
	return rest, ""
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
