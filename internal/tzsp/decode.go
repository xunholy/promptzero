// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tzsp decodes the TaZmen Sniffer Protocol (TZSP) — the UDP
// encapsulation (default port 0x9090 / 37008) that MikroTik RouterOS,
// Aruba and other gear use to **stream sniffed wireless frames to a
// remote analyser**. A captured TZSP stream is a remote packet-capture
// feed: each datagram wraps one sniffed frame (802.11 / Ethernet / Prism
// / AVS) together with the radio metadata the sensor observed — the RX
// **channel**, **RSSI**, SNR, link rate and FCS-error flag — so decoding
// it surfaces both the wireless-recon metadata (what channel / how strong
// / which sensor) and the encapsulated frame itself. It joins the
// project's wireless tooling (ieee80211, marauder) and the
// tunnel-decap decoders (gre, geneve, vxlan, mpls).
//
// # Wrap-vs-native judgement
//
//	Native. TZSP is a 4-byte header (version / type / encapsulated
//	protocol) followed by a list of type[/len/value] tags terminated by
//	an END tag, after which the raw encapsulated frame follows. A
//	byte-field read + a tag walk; stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The header, the tag layout and every standard tag (RAW_RSSI, SNR,
//	DATA_RATE, TIMESTAMP, CONTENTION_FREE, DECRYPTED, FCS_ERROR,
//	RX_CHANNEL, PACKET_COUNT, RX_FRAME_LENGTH, WLAN_RADIO_HDR_SERIAL)
//	were verified field-for-field against scapy's TZSP layer
//	(scapy.contrib.tzsp). The encapsulated frame is surfaced as raw hex
//	with its protocol named rather than partially decoded here — it is a
//	complete inner packet best handed to the matching decoder
//	(ieee80211 / an Ethernet/IP dissector). Unknown tags are surfaced as
//	raw hex.
package tzsp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Tag is one decoded TZSP tagged field.
type Tag struct {
	Type    int    `json:"type"`
	Name    string `json:"name"`
	Value   string `json:"value,omitempty"`
	HexData string `json:"hex_data,omitempty"`
}

// Result is the decoded view of a TZSP datagram.
type Result struct {
	Version           int    `json:"version"`
	PacketType        int    `json:"packet_type"`
	PacketTypeName    string `json:"packet_type_name"`
	EncapProtocol     int    `json:"encapsulated_protocol"`
	EncapProtocolName string `json:"encapsulated_protocol_name"`

	// Convenience copies of the most recon-relevant tags, when present.
	RawRSSI   *int   `json:"raw_rssi,omitempty"`
	SNR       *int   `json:"snr,omitempty"`
	DataRate  string `json:"data_rate,omitempty"`
	RXChannel *int   `json:"rx_channel,omitempty"`
	FCSError  *bool  `json:"fcs_error,omitempty"`

	Tags                 []Tag    `json:"tags"`
	EncapsulatedFrameHex string   `json:"encapsulated_frame_hex,omitempty"`
	Notes                []string `json:"notes,omitempty"`
}

// Decode parses a TZSP datagram (the UDP-37008 payload) from hex
// (whitespace / ':' / '-' / '_' separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("tzsp: %d bytes — too short for a TZSP header", len(b))
	}
	if b[0] != 0x01 {
		return nil, fmt.Errorf("tzsp: version 0x%02x is not 0x01 (not TZSP)", b[0])
	}
	r := &Result{
		Version:           int(b[0]),
		PacketType:        int(b[1]),
		PacketTypeName:    packetTypeName(b[1]),
		EncapProtocol:     int(binary.BigEndian.Uint16(b[2:4])),
		EncapProtocolName: encapName(binary.BigEndian.Uint16(b[2:4])),
	}
	off := 4
	for off < len(b) {
		tt := b[off]
		switch tt {
		case 0x00: // PADDING — no length, ignore
			r.Tags = append(r.Tags, Tag{Type: 0x00, Name: "PADDING"})
			off++
			continue
		case 0x01: // END — encapsulated frame follows
			r.Tags = append(r.Tags, Tag{Type: 0x01, Name: "END"})
			off++
			if off < len(b) {
				r.EncapsulatedFrameHex = strings.ToUpper(hex.EncodeToString(b[off:]))
			}
			off = len(b)
			continue
		}
		if off+2 > len(b) {
			r.Notes = append(r.Notes, fmt.Sprintf("tag 0x%02x truncated (no length byte)", tt))
			break
		}
		ln := int(b[off+1])
		if off+2+ln > len(b) {
			r.Notes = append(r.Notes, fmt.Sprintf("tag 0x%02x claims %d bytes but only %d remain", tt, ln, len(b)-off-2))
			break
		}
		data := b[off+2 : off+2+ln]
		r.Tags = append(r.Tags, decodeTag(r, int(tt), data))
		off += 2 + ln
	}
	if r.EncapsulatedFrameHex != "" {
		r.Notes = append(r.Notes, "the encapsulated "+r.EncapProtocolName+" frame is surfaced as raw hex — hand it to the matching decoder (e.g. ieee80211_decode for an 802.11 frame)")
	}
	return r, nil
}

func decodeTag(r *Result, tt int, data []byte) Tag {
	t := Tag{Type: tt, Name: tagName(tt)}
	switch tt {
	case 0x0a: // RAW_RSSI (signed)
		v := signedInt(data)
		r.RawRSSI = &v
		t.Value = fmt.Sprintf("%d", v)
	case 0x0b: // SNR (signed)
		v := signedInt(data)
		r.SNR = &v
		t.Value = fmt.Sprintf("%d", v)
	case 0x0c: // DATA_RATE
		if len(data) == 1 {
			r.DataRate = dataRateName(data[0])
			t.Value = r.DataRate
		}
	case 0x0d: // TIMESTAMP
		if len(data) == 4 {
			t.Value = fmt.Sprintf("%d", binary.BigEndian.Uint32(data))
		}
	case 0x0f, 0x10, 0x11: // CONTENTION_FREE / DECRYPTED / FCS_ERROR (bool)
		v := len(data) > 0 && data[0] != 0
		if tt == 0x11 {
			r.FCSError = &v
		}
		t.Value = fmt.Sprintf("%t", v)
	case 0x12: // RX_CHANNEL
		if len(data) >= 1 {
			c := int(data[0])
			r.RXChannel = &c
			t.Value = fmt.Sprintf("%d", c)
		}
	case 0x28: // PACKET_COUNT
		if len(data) == 4 {
			t.Value = fmt.Sprintf("%d", binary.BigEndian.Uint32(data))
		}
	case 0x29: // RX_FRAME_LENGTH
		if len(data) == 2 {
			t.Value = fmt.Sprintf("%d", binary.BigEndian.Uint16(data))
		}
	case 0x3c: // WLAN_RADIO_HDR_SERIAL (sensor id)
		t.Value = string(data)
	}
	if t.Value == "" {
		t.HexData = strings.ToUpper(hex.EncodeToString(data))
	}
	return t
}

// signedInt interprets a 1- or 2-byte big-endian value as signed (TZSP
// RSSI / SNR are relative, signed measures per the protocol appnote).
func signedInt(b []byte) int {
	switch len(b) {
	case 1:
		return int(int8(b[0]))
	case 2:
		return int(int16(binary.BigEndian.Uint16(b)))
	}
	return 0
}

func packetTypeName(t byte) string {
	switch t {
	case 0x00:
		return "RX_PACKET"
	case 0x01:
		return "TX_PACKET"
	case 0x03:
		return "CONFIG"
	case 0x04:
		return "KEEPALIVE/NULL"
	case 0x05:
		return "PORT"
	}
	return fmt.Sprintf("0x%02x", t)
}

func encapName(p uint16) string {
	switch p {
	case 0x01:
		return "ETHERNET"
	case 0x12:
		return "IEEE 802.11"
	case 0x77:
		return "PRISM HEADER"
	case 0x7f:
		return "WLAN AVS"
	}
	return fmt.Sprintf("0x%04x", p)
}

func tagName(t int) string {
	switch t {
	case 0x00:
		return "PADDING"
	case 0x01:
		return "END"
	case 0x0a:
		return "RAW_RSSI"
	case 0x0b:
		return "SNR"
	case 0x0c:
		return "DATA_RATE"
	case 0x0d:
		return "TIMESTAMP"
	case 0x0f:
		return "CONTENTION_FREE"
	case 0x10:
		return "DECRYPTED"
	case 0x11:
		return "FCS_ERROR"
	case 0x12:
		return "RX_CHANNEL"
	case 0x28:
		return "PACKET_COUNT"
	case 0x29:
		return "RX_FRAME_LENGTH"
	case 0x3c:
		return "WLAN_RADIO_HDR_SERIAL"
	}
	return fmt.Sprintf("UNKNOWN(0x%02x)", t)
}

func dataRateName(r byte) string {
	switch r {
	case 0x00:
		return "unknown"
	case 0x02, 0x0a:
		return "1 Mb/s"
	case 0x04, 0x14:
		return "2 Mb/s"
	case 0x0b, 0x37:
		return "5.5 Mb/s"
	case 0x0c:
		return "6 Mb/s"
	case 0x12:
		return "9 Mb/s"
	case 0x16, 0x6e:
		return "11 Mb/s"
	case 0x18:
		return "12 Mb/s"
	case 0x24:
		return "18 Mb/s"
	case 0x2c:
		return "22 Mb/s"
	case 0x30:
		return "24 Mb/s"
	case 0x42:
		return "33 Mb/s"
	case 0x48:
		return "36 Mb/s"
	case 0x60:
		return "48 Mb/s"
	case 0x6c:
		return "54 Mb/s"
	}
	return fmt.Sprintf("0x%02x", r)
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("tzsp: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("tzsp: input is not valid hex: %w", err)
	}
	return b, nil
}
