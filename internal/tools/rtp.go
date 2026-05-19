// rtp.go — host-side RTP / RTCP packet decoder Spec.
// Wraps the internal/rtp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/rtp"
)

func init() { //nolint:gochecknoinits
	Register(rtpPacketDecodeSpec)
}

var rtpPacketDecodeSpec = Spec{
	Name: "rtp_packet_decode",
	Description: "Decode an RTP or RTCP datagram per RFC 3550 (Real-time Transport " +
		"Protocol) + RFC 3551 (static payload type assignments) + RFC 4585 (RTPFB / " +
		"PSFB feedback) + RFC 3611 (Extended Reports). RTP is the media layer of every " +
		"VoIP call, every WebRTC connection, every SIP-signalled multimedia stream — " +
		"natural completion of the VoIP/WebRTC decode stack alongside " +
		"`sip_message_decode` (signaling) and `stun_packet_decode` (NAT traversal). " +
		"Decodes:\n\n" +
		"- **Auto-detect**: RTP vs RTCP. Both share V=2; the disambiguator is the " +
		"payload-type byte — RTCP standard PTs are 200-207 (SR / RR / SDES / BYE / APP " +
		"/ RTPFB / PSFB / XR), which doesn't overlap practical RTP PTs (7-bit 0-127). " +
		"RTP PTs 72-76 are RTCP-conflict reserved per RFC 3551 §6 to make multiplexing " +
		"safe and are rejected.\n" +
		"- **RTP header** (12 fixed bytes + optional CSRC list + optional X-extension): " +
		"V / P / X / CC / M / PT / Sequence / Timestamp / SSRC / CSRC[CC] / optional " +
		"Extension (4-byte profile + length header + N×4 bytes data) / payload / " +
		"optional padding (last byte = pad count).\n" +
		"- **Static payload-type table** (RFC 3551 §6): audio (PCMU / GSM / G723 / DVI4 " +
		"/ LPC / PCMA / G722 / L16 / QCELP / CN / MPA / G728 / G729) and video (CelB / " +
		"JPEG / nv / H261 / MPV / MP2T / H263). PTs 35-71 + 77-95 are reserved/unassigned; " +
		"72-76 are RTCP-conflict; 96-127 are dynamic (negotiated in SDP).\n" +
		"- **RTCP composite packets**: one UDP datagram may carry multiple RTCP packets " +
		"concatenated. The walker follows the (length+1)*4 bytes rule until the buffer " +
		"is consumed. Each sub-packet is decoded by PT:\n" +
		"  - **SR (200)**: sender SSRC + NTP timestamp + RTP timestamp + sender " +
		"packet/byte count + RC × reception report block (source SSRC + fraction lost " +
		"+ cumulative lost + extended highest seq + interarrival jitter + LSR + DLSR).\n" +
		"  - **RR (201)**: reporter SSRC + RC × reception report block.\n" +
		"  - **SDES (202)**: SC × chunk (SSRC + items keyed by SDES type — 1 CNAME / " +
		"2 NAME / 3 EMAIL / 4 PHONE / 5 LOC / 6 TOOL / 7 NOTE / 8 PRIV).\n" +
		"  - **BYE (203)**: SC × SSRC + optional reason string.\n" +
		"  - **APP (204)**: SSRC + 4-byte name + opaque application data.\n" +
		"  - **RTPFB (205)** / **PSFB (206)**: feedback envelope per RFC 4585 — sender " +
		"SSRC + media SSRC + FCI blob. FMT field decoded: RTPFB FMT 1 NACK / 3 TMMBR " +
		"/ 4 TMMBN / 15 TWCC; PSFB FMT 1 PLI / 2 SLI / 3 RPSI / 4 FIR / 5 TSTR / 6 TSTN " +
		"/ 7 VBCM / 15 AFB (REMB-style).\n" +
		"  - **XR (207)**: extended-reports envelope per RFC 3611 — sender SSRC + " +
		"per-block (BT + type-specific + length + body bytes).\n\n" +
		"Pure offline parser — operators paste UDP payload bytes from a Wireshark RTP " +
		"stream, a SIPp test capture, a Janus / FreeSWITCH / Asterisk log replay, a " +
		"WebRTC chrome://webrtc-internals export, or any media-server diagnostic and " +
		"inspect every documented field. Pairs with sip_message_decode + " +
		"stun_packet_decode for the complete VoIP / WebRTC stack.\n\n" +
		"Out of scope (deferred): DTLS-SRTP key negotiation (RFC 5764) and SRTP payload " +
		"decryption (encrypted payload bytes are surfaced raw, cleartext header is " +
		"still parsed); SDP body parsing (already handled by sip_message_decode); " +
		"RFC 5285 one-byte / two-byte header extension dissection (raw blob only); " +
		"codec-level RTP payload framing (Opus / H.264 / VP8 / VP9 per RFC 6184 / 7741 " +
		"/ 7798 / 9628); RTCP-XR block-type-specific body decoding (BT + length surfaced, " +
		"body as hex).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational VoIP / WebRTC media-decode " +
		"completion alongside SIP and STUN). Wrap-vs-native: native — RFC 3550 + 3551 " +
		"are fully public, the wire format is a small fixed-layout binary header, " +
		"RTCP composite walking is a tight length-prefixed binary walker (no varints, " +
		"no compression).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"RTP or RTCP datagram hex bytes. Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   rtpPacketDecodeHandler,
}

func rtpPacketDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("rtp_packet_decode: 'hex' is required")
	}
	res, err := rtp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("rtp_packet_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
