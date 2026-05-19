// Package rtp decodes RTP and RTCP packets per RFC 3550
// (Real-time Transport Protocol) and the static payload type
// assignments of RFC 3551, plus the standard RTCP feedback
// extensions of RFC 4585 (RTPFB / PSFB) and RFC 3611 (XR).
//
// Wrap-vs-native judgement
//
//	Native. RFC 3550 and 3551 are fully public; the wire
//	format is a small fixed-layout binary header with a
//	well-defined set of optional sections and a finite, small
//	table of payload types. RTCP composite-packet walking is
//	also a tight binary walker: per-packet length field is
//	measured in 32-bit words, no varints, no compression.
//	Operators paste UDP payload bytes from a Wireshark RTP
//	stream, a SIPp test capture, or any media-server log and
//	get a documented view of every field. Pure offline parser
//	— no transport, no hardware, no state.
//
// What this package covers
//
//   - Auto-detect: RTP vs RTCP. Both share V=2 in the high two
//     bits of byte 0. The disambiguator is the payload-type
//     byte: RTCP standard PTs are 200-207 (SR / RR / SDES /
//     BYE / APP / RTPFB / PSFB / XR), which doesn't overlap
//     any practical RTP PT (RTP PT is 7-bit 0-127). A
//     non-zero high bit on byte 1 of an RTCP candidate (which
//     would be the RTP Marker bit) and a low-half value in
//     [72,76] are flagged as RTCP-collision-reserved per RFC
//     3551 §6 to make multiplexing safe.
//
//   - RTP header (12 fixed bytes + optional CSRC list +
//     optional X-extension): V, P, X, CC, M, PT, Sequence,
//     Timestamp, SSRC, CSRC[CC], optional Extension (4-byte
//     profile/length header + N×4 bytes), then payload, then
//     optional padding (last byte is pad count when P=1).
//
//   - Static payload-type table (RFC 3551 §6): PT 0-34 + the
//     gaps; includes audio (PCMU / GSM / G723 / DVI4 / LPC /
//     PCMA / G722 / L16 / QCELP / CN / MPA / G728 / G729) and
//     video (CelB / JPEG / nv / H261 / MPV / MP2T / H263). PTs
//     35-71 + 77-95 are reserved/unassigned (rendered as
//     "unassigned"); 72-76 are RTCP-conflict-reserved; 96-127
//     are dynamic (rendered as "dynamic" — actual codec is
//     negotiated in SDP).
//
//   - RTCP composite packets: one UDP datagram may carry
//     multiple RTCP packets concatenated. We walk the chain by
//     the (length+1)*4 bytes rule until the buffer is
//     consumed. Each chunk is decoded by PT:
//
//   - SR (200): SSRC + NTP timestamp + RTP timestamp +
//     sender packet/byte count + RC × reception report
//     block (SSRC + fraction lost + cumulative lost +
//     extended highest seq + interarrival jitter + LSR +
//     DLSR).
//
//   - RR (201): SSRC + RC × reception report block.
//
//   - SDES (202): SC × chunk (SSRC + items keyed by SDES
//     type: 1 CNAME / 2 NAME / 3 EMAIL / 4 PHONE / 5 LOC /
//     6 TOOL / 7 NOTE / 8 PRIV).
//
//   - BYE (203): SC × SSRC + optional reason string.
//
//   - APP (204): SSRC + 4-byte name + opaque app data.
//
//   - RTPFB (205) / PSFB (206): generic feedback envelope
//     per RFC 4585 — sender SSRC + media SSRC + FCI blob.
//
//   - XR (207): extended-reports envelope per RFC 3611 —
//     sender SSRC + per-block (BT + type-specific + length).
//
// What this package does NOT cover (deliberately out of scope)
//
//   - DTLS-SRTP key negotiation (RFC 5764) and SRTP keying
//     material — payload-level encryption is opaque to this
//     decoder; encrypted RTP shows the cleartext header (which
//     is what intermediaries see) but the payload is rendered
//     as hex bytes.
//
//   - SDP body parsing (RFC 4566) — that's already handled
//     by internal/sip's body section.
//
//   - RTP header extensions beyond the generic profile-defined
//     length walker — RFC 5285 one-byte and two-byte
//     extensions are surfaced as a raw blob; specific
//     extensions (audio-level, abs-send-time, video-orientation)
//     would belong in a sibling helper.
//
//   - Codec-level dissection (Opus / H.264 / VP8 RTP payload
//     framing per RFC 6184 / RFC 7741 / etc.) — payload bytes
//     are surfaced raw.
//
//   - RTCP-XR block-specific decoding for every block type
//     (RFC 3611 defines 8 block types — we surface BT + length
//     and leave the body as hex).
package rtp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Result is the top-level decoded view.
type Result struct {
	Kind        string       `json:"kind"` // "rtp" | "rtcp"
	TotalBytes  int          `json:"total_bytes"`
	RTP         *RTPPacket   `json:"rtp,omitempty"`
	RTCP        []RTCPPacket `json:"rtcp,omitempty"`
	RTCPSummary string       `json:"rtcp_summary,omitempty"`
}

// RTPPacket is one decoded RTP packet.
type RTPPacket struct {
	Version             int      `json:"version"`
	Padding             bool     `json:"padding"`
	Extension           bool     `json:"extension"`
	CSRCCount           int      `json:"csrc_count"`
	Marker              bool     `json:"marker"`
	PayloadType         int      `json:"payload_type"`
	PayloadTypeName     string   `json:"payload_type_name"`
	SequenceNumber      int      `json:"sequence_number"`
	Timestamp           uint32   `json:"timestamp"`
	SSRC                uint32   `json:"ssrc"`
	SSRCHex             string   `json:"ssrc_hex"`
	CSRC                []uint32 `json:"csrc,omitempty"`
	ExtensionProfile    *uint16  `json:"extension_profile,omitempty"`
	ExtensionLengthW    *uint16  `json:"extension_length_words,omitempty"`
	ExtensionDataHex    string   `json:"extension_data_hex,omitempty"`
	PaddingLength       int      `json:"padding_length,omitempty"`
	PayloadLength       int      `json:"payload_length"`
	PayloadHex          string   `json:"payload_hex,omitempty"`
	PayloadHexTruncated bool     `json:"payload_hex_truncated,omitempty"`
}

// RTCPPacket is one decoded RTCP sub-packet inside a composite
// datagram. Body shape depends on PT.
type RTCPPacket struct {
	Version    int    `json:"version"`
	Padding    bool   `json:"padding"`
	ReportCnt  int    `json:"report_count"`
	Type       int    `json:"type"`
	TypeName   string `json:"type_name"`
	LengthW    int    `json:"length_words"`
	TotalBytes int    `json:"total_bytes"`

	SR   *SRPacket   `json:"sr,omitempty"`
	RR   *RRPacket   `json:"rr,omitempty"`
	SDES *SDESPacket `json:"sdes,omitempty"`
	BYE  *BYEPacket  `json:"bye,omitempty"`
	APP  *APPPacket  `json:"app,omitempty"`
	FB   *FBPacket   `json:"feedback,omitempty"`
	XR   *XRPacket   `json:"xr,omitempty"`
	Raw  string      `json:"raw_hex,omitempty"`
}

// ReceptionReport is a per-source reception block used by SR
// and RR.
type ReceptionReport struct {
	SourceSSRC       uint32 `json:"source_ssrc"`
	SourceSSRCHex    string `json:"source_ssrc_hex"`
	FractionLost     int    `json:"fraction_lost"`
	CumulativeLost   int    `json:"cumulative_lost"`
	ExtendedHighSeq  uint32 `json:"extended_highest_seq"`
	InterarrivalJit  uint32 `json:"interarrival_jitter"`
	LastSRTimestamp  uint32 `json:"last_sr_ntp_middle"`
	DelaySinceLastSR uint32 `json:"delay_since_last_sr"`
}

// SRPacket is RTCP Sender Report (PT 200).
type SRPacket struct {
	SenderSSRC        uint32            `json:"sender_ssrc"`
	SenderSSRCHex     string            `json:"sender_ssrc_hex"`
	NTPTimestampHigh  uint32            `json:"ntp_timestamp_high"`
	NTPTimestampLow   uint32            `json:"ntp_timestamp_low"`
	RTPTimestamp      uint32            `json:"rtp_timestamp"`
	SenderPacketCount uint32            `json:"sender_packet_count"`
	SenderOctetCount  uint32            `json:"sender_octet_count"`
	Reports           []ReceptionReport `json:"reports,omitempty"`
}

// RRPacket is RTCP Receiver Report (PT 201).
type RRPacket struct {
	ReporterSSRC    uint32            `json:"reporter_ssrc"`
	ReporterSSRCHex string            `json:"reporter_ssrc_hex"`
	Reports         []ReceptionReport `json:"reports,omitempty"`
}

// SDESChunk is one source-description chunk.
type SDESChunk struct {
	SSRC    uint32     `json:"ssrc"`
	SSRCHex string     `json:"ssrc_hex"`
	Items   []SDESItem `json:"items,omitempty"`
}

// SDESItem is one (type, text) pair.
type SDESItem struct {
	Type     int    `json:"type"`
	TypeName string `json:"type_name"`
	Text     string `json:"text"`
}

// SDESPacket is RTCP Source Description (PT 202).
type SDESPacket struct {
	Chunks []SDESChunk `json:"chunks,omitempty"`
}

// BYEPacket is RTCP Goodbye (PT 203).
type BYEPacket struct {
	Sources    []uint32 `json:"sources,omitempty"`
	SourcesHex []string `json:"sources_hex,omitempty"`
	Reason     string   `json:"reason,omitempty"`
}

// APPPacket is RTCP Application-Defined (PT 204).
type APPPacket struct {
	SSRC    uint32 `json:"ssrc"`
	SSRCHex string `json:"ssrc_hex"`
	Name    string `json:"name"`
	DataHex string `json:"data_hex,omitempty"`
}

// FBPacket is RTCP feedback (PT 205 RTPFB / PT 206 PSFB) per
// RFC 4585.
type FBPacket struct {
	FormatCode    int    `json:"format_code"` // RC field reused as FMT
	FormatName    string `json:"format_name"`
	SenderSSRC    uint32 `json:"sender_ssrc"`
	SenderSSRCHex string `json:"sender_ssrc_hex"`
	MediaSSRC     uint32 `json:"media_ssrc"`
	MediaSSRCHex  string `json:"media_ssrc_hex"`
	FCIHex        string `json:"fci_hex,omitempty"`
}

// XRBlock is one RTCP-XR report block.
type XRBlock struct {
	BlockType    int    `json:"block_type"`
	TypeSpecific int    `json:"type_specific"`
	BlockLengthW int    `json:"block_length_words"`
	BlockBytes   int    `json:"block_bytes"`
	BodyHex      string `json:"body_hex,omitempty"`
}

// XRPacket is RTCP Extended Report (PT 207) per RFC 3611.
type XRPacket struct {
	SenderSSRC    uint32    `json:"sender_ssrc"`
	SenderSSRCHex string    `json:"sender_ssrc_hex"`
	Blocks        []XRBlock `json:"blocks,omitempty"`
}

// Decode parses an RTP or RTCP datagram from hex.
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if clean == "" {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("hex must have even length, got %d", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("datagram too short (%d bytes; need ≥4)", len(b))
	}
	ver := int(b[0] >> 6)
	if ver != 2 {
		return nil, fmt.Errorf("RTP/RTCP version must be 2, got %d", ver)
	}
	pt := int(b[1] & 0x7F)
	ptByteRaw := int(b[1])
	if ptByteRaw >= 200 && ptByteRaw <= 207 {
		return decodeRTCPComposite(b)
	}
	if pt >= 72 && pt <= 76 {
		return nil, fmt.Errorf("payload type %d is RTCP-conflict reserved (RFC 3551 §6)", pt)
	}
	return decodeRTP(b)
}

func decodeRTP(b []byte) (*Result, error) {
	if len(b) < 12 {
		return nil, fmt.Errorf("RTP header truncated (%d bytes; need ≥12)", len(b))
	}
	pkt := &RTPPacket{
		Version:        int(b[0] >> 6),
		Padding:        (b[0]>>5)&1 == 1,
		Extension:      (b[0]>>4)&1 == 1,
		CSRCCount:      int(b[0] & 0x0F),
		Marker:         (b[1]>>7)&1 == 1,
		PayloadType:    int(b[1] & 0x7F),
		SequenceNumber: int(binary.BigEndian.Uint16(b[2:4])),
		Timestamp:      binary.BigEndian.Uint32(b[4:8]),
		SSRC:           binary.BigEndian.Uint32(b[8:12]),
	}
	pkt.PayloadTypeName = rtpPayloadTypeName(pkt.PayloadType)
	pkt.SSRCHex = fmt.Sprintf("0x%08X", pkt.SSRC)

	off := 12
	for i := 0; i < pkt.CSRCCount; i++ {
		if off+4 > len(b) {
			return nil, fmt.Errorf("CSRC list truncated at index %d", i)
		}
		pkt.CSRC = append(pkt.CSRC, binary.BigEndian.Uint32(b[off:off+4]))
		off += 4
	}

	if pkt.Extension {
		if off+4 > len(b) {
			return nil, fmt.Errorf("extension header truncated")
		}
		prof := binary.BigEndian.Uint16(b[off : off+2])
		lenW := binary.BigEndian.Uint16(b[off+2 : off+4])
		pkt.ExtensionProfile = &prof
		pkt.ExtensionLengthW = &lenW
		off += 4
		extBytes := int(lenW) * 4
		if off+extBytes > len(b) {
			return nil, fmt.Errorf("extension payload truncated (declared %d bytes, %d left)",
				extBytes, len(b)-off)
		}
		pkt.ExtensionDataHex = strings.ToUpper(hex.EncodeToString(b[off : off+extBytes]))
		off += extBytes
	}

	end := len(b)
	if pkt.Padding {
		padLen := int(b[end-1])
		if padLen == 0 || padLen > end-off {
			return nil, fmt.Errorf("declared padding %d invalid (%d payload bytes left)",
				padLen, end-off)
		}
		pkt.PaddingLength = padLen
		end -= padLen
	}

	payload := b[off:end]
	pkt.PayloadLength = len(payload)
	if len(payload) > 256 {
		pkt.PayloadHex = strings.ToUpper(hex.EncodeToString(payload[:256]))
		pkt.PayloadHexTruncated = true
	} else if len(payload) > 0 {
		pkt.PayloadHex = strings.ToUpper(hex.EncodeToString(payload))
	}

	return &Result{
		Kind:       "rtp",
		TotalBytes: len(b),
		RTP:        pkt,
	}, nil
}

func decodeRTCPComposite(b []byte) (*Result, error) {
	var packets []RTCPPacket
	off := 0
	for off < len(b) {
		if off+4 > len(b) {
			return nil, fmt.Errorf("RTCP composite truncated at offset %d", off)
		}
		ver := int(b[off] >> 6)
		if ver != 2 {
			return nil, fmt.Errorf("RTCP sub-packet at offset %d has version %d (want 2)",
				off, ver)
		}
		lenW := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		pktBytes := (lenW + 1) * 4
		if off+pktBytes > len(b) {
			return nil, fmt.Errorf("RTCP sub-packet at offset %d declares %d bytes; %d left",
				off, pktBytes, len(b)-off)
		}
		sub := b[off : off+pktBytes]
		p := RTCPPacket{
			Version:    int(sub[0] >> 6),
			Padding:    (sub[0]>>5)&1 == 1,
			ReportCnt:  int(sub[0] & 0x1F),
			Type:       int(sub[1]),
			LengthW:    lenW,
			TotalBytes: pktBytes,
		}
		p.TypeName = rtcpTypeName(p.Type)
		body := sub[4:]
		switch p.Type {
		case 200:
			sr, err := decodeSR(body, p.ReportCnt)
			if err != nil {
				return nil, fmt.Errorf("RTCP SR at offset %d: %w", off, err)
			}
			p.SR = sr
		case 201:
			rr, err := decodeRR(body, p.ReportCnt)
			if err != nil {
				return nil, fmt.Errorf("RTCP RR at offset %d: %w", off, err)
			}
			p.RR = rr
		case 202:
			sdes, err := decodeSDES(body, p.ReportCnt)
			if err != nil {
				return nil, fmt.Errorf("RTCP SDES at offset %d: %w", off, err)
			}
			p.SDES = sdes
		case 203:
			bye, err := decodeBYE(body, p.ReportCnt)
			if err != nil {
				return nil, fmt.Errorf("RTCP BYE at offset %d: %w", off, err)
			}
			p.BYE = bye
		case 204:
			app, err := decodeAPP(body)
			if err != nil {
				return nil, fmt.Errorf("RTCP APP at offset %d: %w", off, err)
			}
			p.APP = app
		case 205, 206:
			fb, err := decodeFB(body, p.Type, p.ReportCnt)
			if err != nil {
				return nil, fmt.Errorf("RTCP feedback at offset %d: %w", off, err)
			}
			p.FB = fb
		case 207:
			xr, err := decodeXR(body)
			if err != nil {
				return nil, fmt.Errorf("RTCP XR at offset %d: %w", off, err)
			}
			p.XR = xr
		default:
			p.Raw = strings.ToUpper(hex.EncodeToString(body))
		}
		packets = append(packets, p)
		off += pktBytes
	}
	summary := make([]string, 0, len(packets))
	for _, p := range packets {
		summary = append(summary, p.TypeName)
	}
	return &Result{
		Kind:        "rtcp",
		TotalBytes:  len(b),
		RTCP:        packets,
		RTCPSummary: strings.Join(summary, " + "),
	}, nil
}

func decodeSR(body []byte, rc int) (*SRPacket, error) {
	if len(body) < 24 {
		return nil, fmt.Errorf("body too short (%d; need ≥24)", len(body))
	}
	sr := &SRPacket{
		SenderSSRC:        binary.BigEndian.Uint32(body[0:4]),
		NTPTimestampHigh:  binary.BigEndian.Uint32(body[4:8]),
		NTPTimestampLow:   binary.BigEndian.Uint32(body[8:12]),
		RTPTimestamp:      binary.BigEndian.Uint32(body[12:16]),
		SenderPacketCount: binary.BigEndian.Uint32(body[16:20]),
		SenderOctetCount:  binary.BigEndian.Uint32(body[20:24]),
	}
	sr.SenderSSRCHex = fmt.Sprintf("0x%08X", sr.SenderSSRC)
	off := 24
	for i := 0; i < rc; i++ {
		if off+24 > len(body) {
			return nil, fmt.Errorf("reception report %d truncated", i)
		}
		sr.Reports = append(sr.Reports, parseReceptionReport(body[off:off+24]))
		off += 24
	}
	return sr, nil
}

func decodeRR(body []byte, rc int) (*RRPacket, error) {
	if len(body) < 4 {
		return nil, fmt.Errorf("body too short (%d; need ≥4)", len(body))
	}
	rr := &RRPacket{
		ReporterSSRC: binary.BigEndian.Uint32(body[0:4]),
	}
	rr.ReporterSSRCHex = fmt.Sprintf("0x%08X", rr.ReporterSSRC)
	off := 4
	for i := 0; i < rc; i++ {
		if off+24 > len(body) {
			return nil, fmt.Errorf("reception report %d truncated", i)
		}
		rr.Reports = append(rr.Reports, parseReceptionReport(body[off:off+24]))
		off += 24
	}
	return rr, nil
}

func parseReceptionReport(b []byte) ReceptionReport {
	cumLost := int(b[5])<<16 | int(b[6])<<8 | int(b[7])
	if cumLost&0x800000 != 0 {
		cumLost -= 0x1000000
	}
	rr := ReceptionReport{
		SourceSSRC:       binary.BigEndian.Uint32(b[0:4]),
		FractionLost:     int(b[4]),
		CumulativeLost:   cumLost,
		ExtendedHighSeq:  binary.BigEndian.Uint32(b[8:12]),
		InterarrivalJit:  binary.BigEndian.Uint32(b[12:16]),
		LastSRTimestamp:  binary.BigEndian.Uint32(b[16:20]),
		DelaySinceLastSR: binary.BigEndian.Uint32(b[20:24]),
	}
	rr.SourceSSRCHex = fmt.Sprintf("0x%08X", rr.SourceSSRC)
	return rr
}

func decodeSDES(body []byte, sc int) (*SDESPacket, error) {
	sdes := &SDESPacket{}
	off := 0
	for i := 0; i < sc; i++ {
		if off+4 > len(body) {
			return nil, fmt.Errorf("SDES chunk %d header truncated", i)
		}
		chunk := SDESChunk{SSRC: binary.BigEndian.Uint32(body[off : off+4])}
		chunk.SSRCHex = fmt.Sprintf("0x%08X", chunk.SSRC)
		off += 4
		for {
			if off >= len(body) {
				return nil, fmt.Errorf("SDES chunk %d items truncated", i)
			}
			it := int(body[off])
			off++
			if it == 0 {
				// Pad up to 4-byte boundary; off is now after END.
				pad := (4 - (off % 4)) % 4
				if off+pad > len(body) {
					return nil, fmt.Errorf("SDES chunk %d padding overruns", i)
				}
				off += pad
				break
			}
			if off >= len(body) {
				return nil, fmt.Errorf("SDES item type %d length truncated", it)
			}
			ln := int(body[off])
			off++
			if off+ln > len(body) {
				return nil, fmt.Errorf("SDES item type %d text truncated", it)
			}
			chunk.Items = append(chunk.Items, SDESItem{
				Type:     it,
				TypeName: sdesItemName(it),
				Text:     safeText(body[off : off+ln]),
			})
			off += ln
		}
		sdes.Chunks = append(sdes.Chunks, chunk)
	}
	return sdes, nil
}

func decodeBYE(body []byte, sc int) (*BYEPacket, error) {
	bye := &BYEPacket{}
	off := 0
	for i := 0; i < sc; i++ {
		if off+4 > len(body) {
			return nil, fmt.Errorf("BYE source %d truncated", i)
		}
		s := binary.BigEndian.Uint32(body[off : off+4])
		bye.Sources = append(bye.Sources, s)
		bye.SourcesHex = append(bye.SourcesHex, fmt.Sprintf("0x%08X", s))
		off += 4
	}
	if off < len(body) {
		ln := int(body[off])
		off++
		if off+ln > len(body) {
			return nil, fmt.Errorf("BYE reason text truncated")
		}
		bye.Reason = safeText(body[off : off+ln])
	}
	return bye, nil
}

func decodeAPP(body []byte) (*APPPacket, error) {
	if len(body) < 8 {
		return nil, fmt.Errorf("APP body too short (%d; need ≥8)", len(body))
	}
	app := &APPPacket{
		SSRC: binary.BigEndian.Uint32(body[0:4]),
		Name: safeText(body[4:8]),
	}
	app.SSRCHex = fmt.Sprintf("0x%08X", app.SSRC)
	if len(body) > 8 {
		app.DataHex = strings.ToUpper(hex.EncodeToString(body[8:]))
	}
	return app, nil
}

func decodeFB(body []byte, ptype int, fmtCode int) (*FBPacket, error) {
	if len(body) < 8 {
		return nil, fmt.Errorf("feedback body too short (%d; need ≥8)", len(body))
	}
	fb := &FBPacket{
		FormatCode: fmtCode,
		FormatName: feedbackFormatName(ptype, fmtCode),
		SenderSSRC: binary.BigEndian.Uint32(body[0:4]),
		MediaSSRC:  binary.BigEndian.Uint32(body[4:8]),
	}
	fb.SenderSSRCHex = fmt.Sprintf("0x%08X", fb.SenderSSRC)
	fb.MediaSSRCHex = fmt.Sprintf("0x%08X", fb.MediaSSRC)
	if len(body) > 8 {
		fb.FCIHex = strings.ToUpper(hex.EncodeToString(body[8:]))
	}
	return fb, nil
}

func decodeXR(body []byte) (*XRPacket, error) {
	if len(body) < 4 {
		return nil, fmt.Errorf("XR body too short (%d; need ≥4)", len(body))
	}
	xr := &XRPacket{
		SenderSSRC: binary.BigEndian.Uint32(body[0:4]),
	}
	xr.SenderSSRCHex = fmt.Sprintf("0x%08X", xr.SenderSSRC)
	off := 4
	for off < len(body) {
		if off+4 > len(body) {
			return nil, fmt.Errorf("XR block header truncated at offset %d", off)
		}
		bt := int(body[off])
		ts := int(body[off+1])
		lenW := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		blockBytes := (lenW + 1) * 4
		if off+blockBytes > len(body) {
			return nil, fmt.Errorf("XR block at offset %d declares %d bytes; %d left",
				off, blockBytes, len(body)-off)
		}
		blk := XRBlock{
			BlockType:    bt,
			TypeSpecific: ts,
			BlockLengthW: lenW,
			BlockBytes:   blockBytes,
		}
		if blockBytes > 4 {
			blk.BodyHex = strings.ToUpper(hex.EncodeToString(body[off+4 : off+blockBytes]))
		}
		xr.Blocks = append(xr.Blocks, blk)
		off += blockBytes
	}
	return xr, nil
}

// rtpPayloadTypeName returns RFC 3551 §6 static assignments
// (PT 0-34, with gaps), plus reserved ranges.
func rtpPayloadTypeName(pt int) string {
	switch pt {
	case 0:
		return "PCMU/8000/1"
	case 3:
		return "GSM/8000/1"
	case 4:
		return "G723/8000/1"
	case 5:
		return "DVI4/8000/1"
	case 6:
		return "DVI4/16000/1"
	case 7:
		return "LPC/8000/1"
	case 8:
		return "PCMA/8000/1"
	case 9:
		return "G722/8000/1"
	case 10:
		return "L16/44100/2"
	case 11:
		return "L16/44100/1"
	case 12:
		return "QCELP/8000/1"
	case 13:
		return "CN/8000/1"
	case 14:
		return "MPA/90000"
	case 15:
		return "G728/8000/1"
	case 16:
		return "DVI4/11025/1"
	case 17:
		return "DVI4/22050/1"
	case 18:
		return "G729/8000/1"
	case 25:
		return "CelB/90000"
	case 26:
		return "JPEG/90000"
	case 28:
		return "nv/90000"
	case 31:
		return "H261/90000"
	case 32:
		return "MPV/90000"
	case 33:
		return "MP2T/90000"
	case 34:
		return "H263/90000"
	}
	switch {
	case pt >= 1 && pt <= 2:
		return "reserved (was 1016/G721)"
	case pt >= 19 && pt <= 24:
		return "unassigned"
	case pt == 27 || (pt >= 29 && pt <= 30):
		return "unassigned"
	case pt >= 35 && pt <= 71:
		return "unassigned"
	case pt >= 72 && pt <= 76:
		return "RTCP-conflict reserved (RFC 3551 §6)"
	case pt >= 77 && pt <= 95:
		return "unassigned"
	case pt >= 96 && pt <= 127:
		return "dynamic (negotiated in SDP)"
	}
	return "out-of-range"
}

func rtcpTypeName(pt int) string {
	switch pt {
	case 200:
		return "SR (Sender Report)"
	case 201:
		return "RR (Receiver Report)"
	case 202:
		return "SDES (Source Description)"
	case 203:
		return "BYE (Goodbye)"
	case 204:
		return "APP (Application-Defined)"
	case 205:
		return "RTPFB (Generic RTP Feedback)"
	case 206:
		return "PSFB (Payload-Specific Feedback)"
	case 207:
		return "XR (Extended Reports)"
	}
	return fmt.Sprintf("unknown RTCP type %d", pt)
}

func sdesItemName(it int) string {
	switch it {
	case 1:
		return "CNAME"
	case 2:
		return "NAME"
	case 3:
		return "EMAIL"
	case 4:
		return "PHONE"
	case 5:
		return "LOC"
	case 6:
		return "TOOL"
	case 7:
		return "NOTE"
	case 8:
		return "PRIV"
	}
	return fmt.Sprintf("SDES-item-%d", it)
}

func feedbackFormatName(ptype, fmtCode int) string {
	if ptype == 205 { // RTPFB
		switch fmtCode {
		case 1:
			return "Generic NACK (RFC 4585)"
		case 3:
			return "TMMBR (Temp Max Media Bitrate Request, RFC 5104)"
		case 4:
			return "TMMBN (Temp Max Media Bitrate Notification, RFC 5104)"
		case 15:
			return "TWCC (Transport-wide Congestion Control)"
		}
		return fmt.Sprintf("RTPFB FMT %d", fmtCode)
	}
	if ptype == 206 { // PSFB
		switch fmtCode {
		case 1:
			return "PLI (Picture Loss Indication, RFC 4585)"
		case 2:
			return "SLI (Slice Loss Indication, RFC 4585)"
		case 3:
			return "RPSI (Reference Picture Selection Indication, RFC 4585)"
		case 4:
			return "FIR (Full Intra Request, RFC 5104)"
		case 5:
			return "TSTR (Temporal-Spatial Trade-off Request, RFC 5104)"
		case 6:
			return "TSTN (Temporal-Spatial Trade-off Notification, RFC 5104)"
		case 7:
			return "VBCM (Video Back Channel Message, RFC 5104)"
		case 15:
			return "AFB (Application-layer Feedback, e.g. REMB)"
		}
		return fmt.Sprintf("PSFB FMT %d", fmtCode)
	}
	return ""
}

func safeText(b []byte) string {
	if utf8.Valid(b) {
		for _, c := range b {
			if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
				return strings.ToUpper(hex.EncodeToString(b))
			}
		}
		return string(b)
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
