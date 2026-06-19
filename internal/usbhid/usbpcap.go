// SPDX-License-Identifier: AGPL-3.0-or-later

package usbhid

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// dltUSBPcap is the pcap link-layer header type for USBPcap (Windows)
// captures (libpcap LINKTYPE_USBPCAP).
const dltUSBPcap = 249

// usbpcapHeaderLen is the size of the fixed USBPCAP_BUFFER_PACKET_HEADER.
// Control transfers prepend an extra 8-byte setup header, which the record's
// own headerLen field accounts for — so the payload always starts at
// headerLen, never at this constant.
const usbpcapHeaderLen = 27

// usbpcapTransferInterrupt is the USBPCAP_TRANSFER_INTERRUPT transfer-type
// value (0 isoc, 1 interrupt, 2 control, 3 bulk). A keyboard Boot Protocol
// report rides an Interrupt-IN endpoint.
const usbpcapTransferInterrupt = 1

// ExtractUSBPcapReports pulls the 8-byte USB HID Keyboard Boot Protocol
// reports out of a Windows USBPcap binary capture — a classic-format .pcap
// whose link type is DLT_USBPCAP (249), as written by USBPcapCMD and the
// USBPcap Wireshark extcap. It is the Windows counterpart to
// ExtractUsbmonReports (Linux usbmon text). Returns the concatenated report
// bytes as a lowercase hex string ready for Decode, plus the count found.
//
// # Format (desowin USBPcap, USBPcapBuffer.h)
//
// Classic pcap is a 24-byte global header (magic, version, snaplen, link
// type) then per-packet records of a 16-byte record header (ts_sec, ts_usec,
// incl_len, orig_len) followed by incl_len capture bytes. Record-header and
// global-header fields use the file's byte order, signalled by the magic
// (0xA1B2C3D4 native / 0xD4C3B2A1 byte-swapped, plus the 0xA1B23C4D
// nanosecond variants).
//
// Each USBPcap capture record begins with a USBPCAP_BUFFER_PACKET_HEADER
// (packed, always little-endian — USBPcap is Windows/x86-x64 only):
//
//	off size field
//	0   2    headerLen   (total header size; the data payload starts here)
//	2   8    irpId
//	10  4    status
//	14  2    function
//	16  1    info        (bit0 = PDO->FDO, i.e. IN direction)
//	17  2    bus
//	19  2    device
//	21  1    endpoint    (bit 0x80 = IN)
//	22  1    transfer    (0 isoc, 1 interrupt, 2 control, 3 bulk)
//	23  4    dataLength  (payload bytes following the header)
//
// # Heuristic
//
// Mirrors ExtractUsbmonReports exactly: keep records that are an Interrupt
// transfer (transfer==1), Interrupt-IN (endpoint&0x80), carrying exactly 8
// data bytes (dataLength==8) — the keyboard Boot report, separated from a
// co-resident 3-4 byte mouse by the length. The payload starts at the
// record's own headerLen offset (so a control transfer's extra setup header
// is skipped correctly); Decode then validates the Boot Protocol structure.
//
// Only classic pcap is parsed; pcapng (the newer Wireshark default) is
// rejected with an actionable error. Every length is bounds-checked, so a
// malformed or truncated capture returns an error — never a panic.
func ExtractUSBPcapReports(pcap []byte) (hexReports string, count int, err error) {
	if len(pcap) >= 4 && pcap[0] == 0x0a && pcap[1] == 0x0d && pcap[2] == 0x0d && pcap[3] == 0x0a {
		return "", 0, fmt.Errorf("pcapng format not supported — re-export as classic pcap " +
			"(Wireshark: File ▸ Export Specified Packets ▸ save as .pcap), then retry")
	}
	if len(pcap) < 24 {
		return "", 0, fmt.Errorf("not a pcap file: %d bytes is shorter than the 24-byte global header", len(pcap))
	}

	var bo binary.ByteOrder
	switch {
	case pcap[0] == 0xa1 && pcap[1] == 0xb2 && (pcap[2] == 0xc3 || pcap[2] == 0x3c) && (pcap[3] == 0xd4 || pcap[3] == 0x4d):
		bo = binary.BigEndian
	case (pcap[0] == 0xd4 || pcap[0] == 0x4d) && (pcap[1] == 0xc3 || pcap[1] == 0x3c) && pcap[2] == 0xb2 && pcap[3] == 0xa1:
		bo = binary.LittleEndian
	default:
		return "", 0, fmt.Errorf("not a pcap file: unrecognised magic %02x%02x%02x%02x",
			pcap[0], pcap[1], pcap[2], pcap[3])
	}

	if linktype := bo.Uint32(pcap[20:24]); linktype != dltUSBPcap {
		return "", 0, fmt.Errorf("pcap link type %d is not DLT_USBPCAP (%d) — this capture is not USBPcap (Windows). "+
			"On Linux capture with usbmon and use the 'usbmon' input instead", linktype, dltUSBPcap)
	}

	var sb strings.Builder
	off := 24
	for off+16 <= len(pcap) {
		inclLen := bo.Uint32(pcap[off+8 : off+12])
		off += 16
		// A hostile incl_len must not be trusted past the buffer end.
		if inclLen > uint32(len(pcap)-off) {
			break // truncated final record — stop cleanly
		}
		rec := pcap[off : off+int(inclLen)]
		off += int(inclLen)

		if data, ok := usbpcapReportFromRecord(rec); ok {
			sb.WriteString(data)
			count++
		}
	}

	if count == 0 {
		return "", 0, fmt.Errorf("no 8-byte Interrupt-IN HID keyboard reports found in USBPcap capture " +
			"(expected interrupt-IN records with dataLength 8); ensure the capture is USBPcap (DLT_USBPCAP) " +
			"and the keyboard endpoint was recorded")
	}
	return sb.String(), count, nil
}

// usbpcapReportFromRecord parses one capture record's
// USBPCAP_BUFFER_PACKET_HEADER and, when it is an 8-byte Interrupt-IN report,
// returns its 8 data bytes as a lowercase hex string. Every field read is
// bounds-checked so an arbitrary/truncated record can never panic.
func usbpcapReportFromRecord(rec []byte) (string, bool) {
	if len(rec) < usbpcapHeaderLen {
		return "", false
	}
	headerLen := int(binary.LittleEndian.Uint16(rec[0:2]))
	endpoint := rec[21]
	transfer := rec[22]
	dataLength := binary.LittleEndian.Uint32(rec[23:27])

	if transfer != usbpcapTransferInterrupt {
		return "", false
	}
	if endpoint&0x80 == 0 { // Interrupt-IN only (keyboard → host)
		return "", false
	}
	if dataLength != 8 { // boot keyboard report is exactly 8 bytes
		return "", false
	}
	if headerLen < usbpcapHeaderLen || headerLen+8 > len(rec) {
		return "", false // malformed or truncated payload
	}
	return hex.EncodeToString(rec[headerLen : headerLen+8]), true
}
