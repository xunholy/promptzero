// rtmp.go — host-side RTMP (Real-Time Messaging Protocol) wire-
// protocol decoder Spec. Wraps the internal/rtmp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/rtmp"
)

func init() { //nolint:gochecknoinits
	Register(rtmpDecodeSpec)
}

var rtmpDecodeSpec = Spec{
	Name: "rtmp_decode",
	Description: "Decode an RTMP (Real-Time Messaging Protocol) wire-protocol " +
		"frame per the Adobe RTMP Specification 1.0. TCP/1935 default. " +
		"Originally developed by Macromedia/Adobe for Flash; still the " +
		"dominant live-streaming ingest protocol used by OBS Studio, " +
		"Twitch, YouTube Live, Facebook Live, Nginx-RTMP, Wowza, SRS " +
		"(Simple Realtime Server). High-value live-streaming ingest " +
		"target — stream keys are transmitted in cleartext and are " +
		"effectively authentication tokens for live-streaming platforms.\n\n" +
		"The wire format leaks: **handshake version via C0/S0 byte** — " +
		"0x03 = plaintext RTMP; 0x06 = RTMPE (encrypted RTMP via " +
		"Diffie-Hellman; has known implementation weaknesses); " +
		"**application name and server URL via AMF0 'connect' command " +
		"(message type 20)** — first AMF0 command sent by any RTMP " +
		"client; argument object contains 'app' (application name e.g. " +
		"\"live\"), 'tcUrl' (full RTMP URL e.g. \"rtmp://server/live\" " +
		"which often contains auth tokens or stream keys embedded as " +
		"query parameters), 'flashVer' (client version string); " +
		"**stream keys via 'publish' command** — second string argument " +
		"is the stream name / stream key transmitted in cleartext; stream " +
		"keys are auth tokens for Twitch / YouTube Live / Facebook Live / " +
		"Wowza / Nginx-RTMP; **stream name via 'play' command** — " +
		"consumer clients send 'play' with the stream name as cleartext " +
		"second argument; **protocol control messages (types 1-6)** — " +
		"Set Chunk Size / Abort / Acknowledgement / User Control / " +
		"Window Acknowledgement Size / Set Peer Bandwidth; **audio (8) " +
		"and video (9) message streams** — identified by type.\n\n" +
		"Decodes:\n\n" +
		"- **C0+C1 / S0+S1 handshake detection** — leading byte is RTMP " +
		"version (0x03 or 0x06). Surfaces `is_handshake` + " +
		"`handshake_version` + `is_encrypted`.\n" +
		"- **RTMP chunk header walker** — basic_header (1-3 bytes): " +
		"fmt (2 bits) + cs_id (6 bits, or 1-byte/2-byte LE extended). " +
		"Message header per fmt: fmt 0 (11 bytes: timestamp 3 BE + " +
		"message_length 3 BE + message_type_id 1 + message_stream_id " +
		"4 LE); fmt 1 (7 bytes: timestamp_delta 3 + message_length 3 + " +
		"message_type_id 1); fmt 2 (3 bytes: timestamp_delta 3); fmt 3 " +
		"(0 bytes). Extended timestamp (4 BE) if timestamp == 0xFFFFFF.\n" +
		"- **14-entry message type name table**: Set Chunk Size (1) / " +
		"Abort (2) / Acknowledgement (3) / User Control (4) / Window " +
		"Acknowledgement Size (5) / Set Peer Bandwidth (6) / Audio (8) " +
		"/ Video (9) / Data AMF3 (15) / Shared Object AMF3 (17) / Data " +
		"AMF0 (18) / Shared Object AMF0 (19) / Command AMF0 (20) / " +
		"Aggregate (22).\n" +
		"- **AMF0 Command Message walker (type 20)** — extracts command " +
		"name from the first AMF0 string marker (0x02 + 2-byte BE length " +
		"+ data). Key commands: connect / createStream / play / publish / " +
		"deleteStream / FCPublish / releaseStream / onStatus / _result / " +
		"_error.\n" +
		"- **'connect' command argument extraction** — best-effort scan " +
		"for AMF0 object keys 'app', 'tcUrl', 'flashVer' following the " +
		"command name. Surfaces `app_name`, `tc_url`, `flash_ver`.\n" +
		"- **Classification booleans**: `is_connect`, `is_play`, " +
		"`is_publish`, `is_audio`, `is_video`, `is_control_message`.\n" +
		"- **User Control Message event decoder (type 4)** — 7-entry " +
		"event type name table: StreamBegin (0) / StreamEOF (1) / " +
		"StreamDry (2) / SetBufferLength (3) / StreamIsRecorded (4) / " +
		"PingRequest (6) / PingResponse (7).\n\n" +
		"Pure offline parser — paste RTMP bytes (the TCP-segment payload " +
		"hex; default TCP/1935) from tcpdump / Wireshark RTMP dissector " +
		"and get per-frame breakdown. Feed one frame / chunk at a time.\n\n" +
		"Out of scope: RTMPE decryption (Diffie-Hellman key exchange — " +
		"detected but not decrypted); full AMF0/AMF3 value parsing (only " +
		"command name string + best-effort 'app'/'tcUrl'/'flashVer' " +
		"extraction); multi-chunk message reassembly (first chunk only); " +
		"RTMPS (TLS-wrapped RTMP, TCP/443 — handle TLS strip first); " +
		"RTMPT (HTTP-tunneled RTMP — handle HTTP layer separately); " +
		"audio/video payload decoding (H.264/AAC/FLV codec payloads).\n\n" +
		"Source: gap analysis (live-streaming ingest backbone — canonical " +
		"RTMP pentest dissector for stream-key cleartext capture + " +
		"application-name / tcUrl leakage + connect command client " +
		"fingerprinting + RTMPE encrypted-stream detection; pairs with " +
		"rtsp_decode for the complete streaming pentest surface). " +
		"Wrap-vs-native: native — Adobe RTMP Specification 1.0 is " +
		"publicly available; chunk header is a deterministic binary " +
		"layout; no crypto at the parse layer for standard RTMP 0x03; " +
		"AMF0 command parsing limited to first string element + best-" +
		"effort object-key extraction; RTMPE deliberately not decrypted.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"RTMP wire-protocol frame bytes as hex (the TCP-segment payload; default TCP/1935). Feed one frame or chunk at a time. Handshake blocks (C0+C1 / S0+S1 = 1537 bytes) and post-handshake chunk headers are both accepted. Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   rtmpDecodeHandler,
}

func rtmpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("rtmp_decode: 'hex' is required")
	}
	res, err := rtmp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("rtmp_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
