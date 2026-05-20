// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Michael Fornaro

// Inspect is the read-only metadata walker over a classic
// libpcap file. It complements the existing pcap.Reader (which
// is a streaming consumer for Writer-produced files) by
// returning a structured Summary that lists every record's
// header fields plus a hex preview of its payload — the right
// shape for a Spec that surfaces the file to an operator who
// pasted it in.
//
// Universal context. Every tcpdump capture (`tcpdump -w foo.pcap`),
// every Wireshark save, every aircrack-ng dump, every PMKID
// capture from a Marauder, every Sub-GHz RTL-SDR recording
// converted to pcap is in this format. Operators routinely get
// handed a .pcap and need to extract the link type + time
// window + record count *before* pulling individual frames out
// for one of the 80+ existing protocol decoders.
//
// Wrap-vs-native judgement: native. The libpcap classic format
// is fully public; the global header is 24 bytes (4-byte magic
// dispatching on endianness + timestamp resolution + 2-byte
// version major/minor + 4-byte timezone + 4-byte sigfigs +
// 4-byte snaplen + 4-byte network LINKTYPE), records are a
// 16-byte header (4-byte ts_sec + 4-byte ts_frac + 4-byte
// caplen + 4-byte origlen) followed by caplen bytes of payload.
// No crypto, no compression — the only subtlety is the four-
// magic dispatch and the per-record byte preview cap.

package pcap

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Summary is the top-level structured view of a libpcap file.
type Summary struct {
	MagicHex            string          `json:"magic_hex"`
	Endianness          string          `json:"endianness"`
	TimestampResolution string          `json:"timestamp_resolution"`
	VersionMajor        int             `json:"version_major"`
	VersionMinor        int             `json:"version_minor"`
	ThisZone            int32           `json:"this_zone"`
	SigFigs             uint32          `json:"sig_figs"`
	SnapLength          uint32          `json:"snap_length"`
	Network             uint32          `json:"network"`
	NetworkName         string          `json:"network_name"`
	RecordCount         int             `json:"record_count"`
	RecordsParsedHex    int             `json:"records_parsed_in_hex_preview"`
	TotalRecordBytes    uint64          `json:"total_record_bytes"`
	FirstTimestamp      string          `json:"first_timestamp,omitempty"`
	LastTimestamp       string          `json:"last_timestamp,omitempty"`
	DurationSeconds     float64         `json:"duration_seconds,omitempty"`
	Records             []RecordSummary `json:"records,omitempty"`
	Notes               []string        `json:"notes,omitempty"`
}

// RecordSummary is the structured view of one per-packet
// record inside a libpcap file.
type RecordSummary struct {
	Index             int    `json:"index"`
	TimestampSeconds  uint32 `json:"timestamp_seconds"`
	TimestampFraction uint32 `json:"timestamp_fraction"`
	TimestampISO      string `json:"timestamp_iso"`
	CapturedLength    uint32 `json:"captured_length"`
	OriginalLength    uint32 `json:"original_length"`
	Truncated         bool   `json:"truncated,omitempty"`
	PayloadHex        string `json:"payload_hex,omitempty"`
	PayloadBytesShown int    `json:"payload_bytes_shown,omitempty"`
}

// InspectOpts tunes the walker for output size.
type InspectOpts struct {
	// MaxRecords caps the number of per-record summaries
	// returned. RecordCount + TotalRecordBytes still reflect
	// the full file walk. Zero means no cap.
	MaxRecords int
	// MaxPayloadBytes caps the per-record PayloadHex preview.
	// Zero means no preview (just header fields).
	MaxPayloadBytes int
}

// DefaultInspectOpts returns sensible caps so that large pcaps
// produce bounded output: first 50 records, 32-byte hex preview
// per record.
func DefaultInspectOpts() InspectOpts {
	return InspectOpts{MaxRecords: 50, MaxPayloadBytes: 32}
}

// Inspect walks a libpcap file from its raw bytes and returns a
// Summary. Errors are returned only for unrecoverable framing
// issues (magic / version / truncated record header); partial
// payload tails are flagged via the Notes field rather than
// rejected, so that operators can still see what the capture
// claims to contain.
func Inspect(b []byte, opts InspectOpts) (*Summary, error) {
	if len(b) < globalHeaderLen {
		return nil, fmt.Errorf("pcap file truncated (%d bytes; need ≥24 for global header)",
			len(b))
	}
	s := &Summary{}

	magic := binary.LittleEndian.Uint32(b[0:4])
	var order binary.ByteOrder
	var nano bool
	switch magic {
	case 0xa1b2c3d4:
		order = binary.LittleEndian
		s.Endianness = "little"
		s.TimestampResolution = "microsecond"
	case 0xd4c3b2a1:
		order = binary.BigEndian
		s.Endianness = "big"
		s.TimestampResolution = "microsecond"
	case 0xa1b23c4d:
		order = binary.LittleEndian
		nano = true
		s.Endianness = "little"
		s.TimestampResolution = "nanosecond"
	case 0x4d3cb2a1:
		order = binary.BigEndian
		nano = true
		s.Endianness = "big"
		s.TimestampResolution = "nanosecond"
	default:
		return nil, fmt.Errorf("unrecognised magic 0x%08X (expected one of: 0xA1B2C3D4 LE-µs, 0xD4C3B2A1 BE-µs, 0xA1B23C4D LE-ns, 0x4D3CB2A1 BE-ns)",
			magic)
	}
	s.MagicHex = fmt.Sprintf("0x%08X", magic)

	s.VersionMajor = int(order.Uint16(b[4:6]))
	s.VersionMinor = int(order.Uint16(b[6:8]))
	if s.VersionMajor != int(pcapVersionMajor) || s.VersionMinor != int(pcapVersionMinor) {
		s.Notes = append(s.Notes, fmt.Sprintf(
			"version %d.%d (expected %d.%d for classic libpcap)",
			s.VersionMajor, s.VersionMinor, pcapVersionMajor, pcapVersionMinor))
	}
	s.ThisZone = int32(order.Uint32(b[8:12]))
	s.SigFigs = order.Uint32(b[12:16])
	s.SnapLength = order.Uint32(b[16:20])
	s.Network = order.Uint32(b[20:24])
	s.NetworkName = LinkTypeName(s.Network)

	off := globalHeaderLen
	idx := 0
	var firstTs, lastTs time.Time
	for off+perPacketHeaderLen <= len(b) {
		tsSec := order.Uint32(b[off : off+4])
		tsFrac := order.Uint32(b[off+4 : off+8])
		capLen := order.Uint32(b[off+8 : off+12])
		origLen := order.Uint32(b[off+12 : off+16])
		off += perPacketHeaderLen

		var ts time.Time
		if nano {
			ts = time.Unix(int64(tsSec), int64(tsFrac)).UTC()
		} else {
			ts = time.Unix(int64(tsSec), int64(tsFrac)*1000).UTC()
		}
		if idx == 0 {
			firstTs = ts
		}
		lastTs = ts

		truncated := false
		end := off + int(capLen)
		if end > len(b) {
			truncated = true
			end = len(b)
		}
		payload := b[off:end]
		off += int(capLen)
		if truncated {
			off = len(b)
		}

		s.RecordCount = idx + 1
		s.TotalRecordBytes += uint64(capLen)

		if opts.MaxRecords == 0 || idx < opts.MaxRecords {
			rec := RecordSummary{
				Index:             idx,
				TimestampSeconds:  tsSec,
				TimestampFraction: tsFrac,
				TimestampISO:      ts.Format(time.RFC3339Nano),
				CapturedLength:    capLen,
				OriginalLength:    origLen,
				Truncated:         truncated,
			}
			if opts.MaxPayloadBytes > 0 && len(payload) > 0 {
				show := len(payload)
				if show > opts.MaxPayloadBytes {
					show = opts.MaxPayloadBytes
				}
				rec.PayloadHex = strings.ToUpper(hex.EncodeToString(payload[:show]))
				rec.PayloadBytesShown = show
			}
			s.Records = append(s.Records, rec)
			s.RecordsParsedHex = len(s.Records)
		}
		idx++
		if truncated {
			s.Notes = append(s.Notes, fmt.Sprintf(
				"record %d truncated: header declared %d bytes, only %d remaining",
				idx-1, capLen, len(payload)))
			break
		}
	}

	if !firstTs.IsZero() {
		s.FirstTimestamp = firstTs.Format(time.RFC3339Nano)
	}
	if !lastTs.IsZero() {
		s.LastTimestamp = lastTs.Format(time.RFC3339Nano)
		if !firstTs.IsZero() {
			s.DurationSeconds = lastTs.Sub(firstTs).Seconds()
		}
	}
	if off < len(b) && off >= globalHeaderLen {
		s.Notes = append(s.Notes, fmt.Sprintf(
			"%d trailing bytes after last record header (file may be truncated mid-record)",
			len(b)-off))
	}
	return s, nil
}

// LinkTypeName returns the canonical libpcap LINKTYPE_* name
// for the given network field. Returns a generated placeholder
// for unknown values rather than erroring — the operator can
// still see the raw number.
func LinkTypeName(n uint32) string {
	if name, ok := linkTypeNames[n]; ok {
		return name
	}
	return fmt.Sprintf("LINKTYPE_%d (uncatalogued)", n)
}

// linkTypeNames is the ~35-entry catalog of canonical libpcap
// link-layer types operators most often encounter. Sourced
// from the IANA-administered tcpdump.org link-types registry.
var linkTypeNames = map[uint32]string{
	0:   "LINKTYPE_NULL (BSD loopback)",
	1:   "LINKTYPE_ETHERNET",
	6:   "LINKTYPE_IEEE802_5 (Token Ring)",
	7:   "LINKTYPE_ARCNET_BSD",
	8:   "LINKTYPE_SLIP",
	9:   "LINKTYPE_PPP",
	10:  "LINKTYPE_FDDI",
	50:  "LINKTYPE_PPP_HDLC",
	51:  "LINKTYPE_PPP_ETHER",
	100: "LINKTYPE_ATM_RFC1483",
	101: "LINKTYPE_RAW (raw IPv4/v6)",
	104: "LINKTYPE_C_HDLC",
	105: "LINKTYPE_IEEE802_11",
	107: "LINKTYPE_FRELAY",
	108: "LINKTYPE_LOOP (OpenBSD loopback)",
	113: "LINKTYPE_LINUX_SLL (Linux cooked v1)",
	114: "LINKTYPE_LTALK",
	119: "LINKTYPE_PRISM_HEADER",
	121: "LINKTYPE_HHDLC",
	127: "LINKTYPE_IEEE802_11_RADIOTAP",
	138: "LINKTYPE_APPLE_IP_OVER_IEEE1394",
	139: "LINKTYPE_MTP2_WITH_PHDR",
	140: "LINKTYPE_MTP2",
	141: "LINKTYPE_MTP3",
	142: "LINKTYPE_SCCP",
	143: "LINKTYPE_DOCSIS",
	147: "LINKTYPE_USER0",
	162: "LINKTYPE_IEEE802_15_4_WITHFCS",
	166: "LINKTYPE_PPP_PPPD",
	187: "LINKTYPE_BLUETOOTH_HCI_H4",
	189: "LINKTYPE_USB_LINUX",
	192: "LINKTYPE_PPI",
	195: "LINKTYPE_IEEE802_15_4_WITHFCS_NOFCS",
	196: "LINKTYPE_SITA",
	201: "LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR",
	209: "LINKTYPE_LAPD",
	215: "LINKTYPE_IEEE802_15_4_NOFCS",
	220: "LINKTYPE_USB_LINUX_MMAPPED",
	228: "LINKTYPE_IPV4",
	229: "LINKTYPE_IPV6",
	239: "LINKTYPE_NFLOG",
	240: "LINKTYPE_NETANALYZER",
	245: "LINKTYPE_DBUS",
	249: "LINKTYPE_USBPCAP",
	253: "LINKTYPE_INFINIBAND",
	256: "LINKTYPE_ZIGBEE_PSI",
	270: "LINKTYPE_IEEE802_15_4_TAP",
	276: "LINKTYPE_LINUX_SLL2 (Linux cooked v2)",
	291: "LINKTYPE_ZWAVE_TAP",
}
