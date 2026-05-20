// rtsp.go — host-side RTSP (Real-Time Streaming Protocol)
// decoder Spec. Wraps the internal/rtsp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/rtsp"
)

func init() { //nolint:gochecknoinits
	Register(rtspDecodeSpec)
}

var rtspDecodeSpec = Spec{
	Name: "rtsp_decode",
	Description: "Decode an RTSP (Real-Time Streaming Protocol) message per RFC 7826 " +
		"(RTSP 2.0) + RFC 2326 (RTSP 1.0). RTSP is the canonical streaming-" +
		"session control protocol for IP cameras + streaming-server fronts — " +
		"the wire format an operator sees when interrogating Hikvision / Axis / " +
		"Dahua / Bosch / Vivotek / Pelco IP cameras (which all expose an RTSP " +
		"server on TCP/554) or talking to a streaming-server product (Wowza, " +
		"RTSP Simple Server, GStreamer rtspserver, Live555 " +
		"testOnDemandRTSPServer, VLC). The first protocol an IP-camera pentester " +
		"touches: default-credential brute force (`DESCRIBE rtsp://admin:" +
		"admin@target/Streaming/Channels/101` enumerates whether a camera is " +
		"online + which auth scheme it speaks); path enumeration (vendor-" +
		"specific URL paths /Streaming/Channels/<n> Hikvision / /axis-media/" +
		"media.amp Axis / /cam/realmonitor Dahua / /live/ch00_0 Bosch reveal " +
		"vendor + model); authentication harvesting (WWW-Authenticate Digest " +
		"realm + nonce leak for offline crack); CVE-2017-7921 / -7923 Hikvision " +
		"backdoor recon. Decodes:\n\n" +
		"- **Three message kinds** discriminated by the first byte: **Request** " +
		"(first whitespace-delimited token is one of 11 methods) format " +
		"`<METHOD> <URL> RTSP/<version>\\r\\n`; **Response** (first token is " +
		"`RTSP/<version>`) format `RTSP/<version> <status-code> <reason-" +
		"phrase>\\r\\n`; **Interleaved RTP** (first byte = `$` / 0x24 per RFC " +
		"7826 §14.4) followed by 1-byte channel + 2-byte BE length + length-many " +
		"bytes of RTP/RTCP payload.\n" +
		"- **11-entry Method name table** (RFC 7826 §13): OPTIONS (discover " +
		"server capabilities — canonical first probe) / DESCRIBE (request SDP " +
		"description of stream — canonical enumeration step revealing stream " +
		"tracks + codec parameters) / ANNOUNCE (push SDP to server — used in " +
		"record-mode ffmpeg upload) / SETUP (negotiate transport parameters per " +
		"track — RTP/AVP or RTP/AVP/TCP Interleaved tunnel mode) / PLAY (start " +
		"media delivery) / PAUSE / TEARDOWN (close session) / GET_PARAMETER " +
		"(keep-alive + per-server parameter query) / SET_PARAMETER / REDIRECT " +
		"(server informs client of new location) / RECORD.\n" +
		"- **HTTP-style status code categories**: 1xx Informational / 2xx " +
		"Success (200 OK overwhelmingly common; 451 Parameter Not Understood + " +
		"454 Session Not Found + 455 Method Not Valid in This State are RTSP-" +
		"specific) / 3xx Redirection / 4xx Client_Error (401 Unauthorized " +
		"triggers Digest auth; 461 Unsupported Transport on SETUP) / 5xx " +
		"Server_Error / 6xx Vendor_Error (some Hikvision firmwares). Surfaced " +
		"as derived status_category field.\n" +
		"- **Case-insensitive header parser**. Surfaces canonical RTSP fields " +
		"as dedicated typed fields: CSeq (per-session monotonic sequence number " +
		"pairing requests to responses) / Session (opaque session id server " +
		"assigns on SETUP) / Transport (RTP/AVP transport spec; " +
		"`RTP/AVP/UDP;unicast;client_port=8000-8001` or `RTP/AVP/TCP;unicast;" +
		"interleaved=0-1` for the tunnel mode) / Range (playback range: " +
		"`npt=0-`, `npt=10.0-20.5`, `clock=...`) / Scale + Speed (playback " +
		"rate) / Public + Allow (server-advertised method lists on OPTIONS / " +
		"405) / RTP-Info (per-track RTP sync info: sequence + RTP timestamp at " +
		"PLAY start) / Content-Type (usually application/sdp on DESCRIBE) / " +
		"Content-Length / User-Agent + Server (canonical fingerprinting fields) " +
		"/ Date / WWW-Authenticate (Basic realm or Digest realm + nonce — the " +
		"Digest realm + nonce are what an attacker cracks offline) / " +
		"Authorization (Basic <base64> or Digest username/realm/nonce/uri/" +
		"response).\n" +
		"- **Other headers** — surfaced as a generic other_headers map for " +
		"caller-side inspection (vendor-specific headers like X-Stream-Codec " +
		"for some Hikvision streams are common).\n" +
		"- **Body bytes** — when Content-Length: N is set and N bytes follow " +
		"the blank line, the body is surfaced as body_string (if UTF-8) or " +
		"body_hex (otherwise).\n\n" +
		"Pure offline parser — operators paste RTSP bytes (the TCP-segment " +
		"payload as hex; default TCP port 554) from a `tcpdump -X port 554` " +
		"line or a Wireshark RTSP dissector view and get the documented start-" +
		"line + header breakdown + canonical RTSP fields + optional body.\n\n" +
		"Out of scope (deferred): network framing (feed bytes after the TCP-" +
		"segment header strip; default TCP port 554; RTSPS over TLS on TCP/322 " +
		"wraps the same bytes in TLS records — handle TLS strip first); SDP " +
		"body decoding (DESCRIBE responses carry an SDP body covered by the " +
		"existing sdp_decode Spec — surfaces body for SDP decoder to handle); " +
		"encapsulated RTP / RTCP (Interleaved RTP frames carry RTP/RTCP packets " +
		"covered by the existing rtp_decode Spec); authentication evaluation " +
		"(Digest nonce validation, Basic credential extraction, MD5/SHA-256 " +
		"response verification — higher-level); RTSP-over-HTTP tunnelling " +
		"(application/x-rtsp-tunnelled — out of scope); WebRTC / WHIP / WHEP " +
		"(modern streaming signalling alternatives that replace RTSP in some " +
		"deployments — separate decoders).\n\n" +
		"Source: docs/catalog/gap-analysis.md (IP camera + streaming-server " +
		"dissector — pairs with the existing sdp_decode + rtp_decode Specs for " +
		"full streaming-stack coverage; canonical decode for Hikvision / Axis / " +
		"Dahua / Bosch / Vivotek / Pelco IP camera enumeration + Wowza / " +
		"GStreamer / Live555 server fingerprinting; common in DEF CON IoT " +
		"Village CTFs + home-network surveillance pentests + corporate IP-" +
		"camera audit engagements). Wrap-vs-native: native — RTSP is a tiny " +
		"text-based protocol with three message kinds, CRLF-terminated lines, " +
		"and a flat header set borrowed largely from HTTP/1.1; the RFCs are " +
		"publicly available; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"RTSP message bytes as hex (the TCP-segment payload; default TCP port 554). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   rtspDecodeHandler,
}

func rtspDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("rtsp_decode: 'hex' is required")
	}
	res, err := rtsp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("rtsp_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
