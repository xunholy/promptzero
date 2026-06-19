// SPDX-License-Identifier: AGPL-3.0-or-later

package usbhid

import (
	"encoding/binary"
	"strings"
	"testing"
)

// usbpcapRecord assembles one USBPCAP_BUFFER_PACKET_HEADER (always
// little-endian, per the format) followed by its payload. headerLen lets a
// test simulate a control transfer's extra setup header (payload starts at
// headerLen, not the fixed 27).
func usbpcapRecord(endpoint, transfer byte, headerLen uint16, dataLength uint32, payload []byte) []byte {
	hdr := make([]byte, usbpcapHeaderLen)
	binary.LittleEndian.PutUint16(hdr[0:2], headerLen)
	// irpId/status/function/info/bus/device left zero — not consulted.
	hdr[21] = endpoint
	hdr[22] = transfer
	binary.LittleEndian.PutUint32(hdr[23:27], dataLength)
	// Pad to headerLen if the test asked for a larger (e.g. control) header.
	if int(headerLen) > len(hdr) {
		hdr = append(hdr, make([]byte, int(headerLen)-len(hdr))...)
	}
	return append(hdr, payload...)
}

// interruptInReport is the common case: an 8-byte boot keyboard report on an
// Interrupt-IN endpoint (0x81), header length 27.
func interruptInReport(report []byte) []byte {
	return usbpcapRecord(0x81, usbpcapTransferInterrupt, usbpcapHeaderLen, uint32(len(report)), report)
}

// buildPcap assembles a classic pcap file: 24-byte global header + each record
// wrapped in a 16-byte record header. byteOrder controls the file endianness;
// the magic is written to match.
func buildPcap(bo binary.ByteOrder, linktype uint32, records [][]byte) []byte {
	gh := make([]byte, 24)
	if bo == binary.LittleEndian {
		copy(gh[0:4], []byte{0xd4, 0xc3, 0xb2, 0xa1})
	} else {
		copy(gh[0:4], []byte{0xa1, 0xb2, 0xc3, 0xd4})
	}
	bo.PutUint16(gh[4:6], 2)
	bo.PutUint16(gh[6:8], 4)
	bo.PutUint32(gh[16:20], 65535)
	bo.PutUint32(gh[20:24], linktype)

	out := gh
	for _, rec := range records {
		rh := make([]byte, 16)
		bo.PutUint32(rh[8:12], uint32(len(rec)))  // incl_len
		bo.PutUint32(rh[12:16], uint32(len(rec))) // orig_len
		out = append(out, rh...)
		out = append(out, rec...)
	}
	return out
}

// abReports is the report stream for typing "ab": key-down 'a' (0x04),
// release, key-down 'b' (0x05), release.
var abReports = [][]byte{
	{0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00},
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	{0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00},
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
}

// TestExtractUSBPcap_RoundTrip builds a USBPcap capture of "ab", extracts the
// reports, and confirms both the hex and a full Decode of the result.
func TestExtractUSBPcap_RoundTrip(t *testing.T) {
	var recs [][]byte
	for _, r := range abReports {
		recs = append(recs, interruptInReport(r))
	}
	pcap := buildPcap(binary.LittleEndian, dltUSBPcap, recs)

	hexReports, count, err := ExtractUSBPcapReports(pcap)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if count != 4 {
		t.Errorf("count: got %d want 4", count)
	}
	want := "0000040000000000" + "0000000000000000" + "0000050000000000" + "0000000000000000"
	if hexReports != want {
		t.Errorf("hex: got %q want %q", hexReports, want)
	}
	res, err := Decode(hexReports)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.ReconstructedText != "ab" {
		t.Errorf("reconstructedText: got %q want %q", res.ReconstructedText, "ab")
	}
}

// TestExtractUSBPcap_BigEndianFile confirms a byte-swapped (big-endian) pcap
// global/record header is handled — the USBPCAP payload header stays LE.
func TestExtractUSBPcap_BigEndianFile(t *testing.T) {
	pcap := buildPcap(binary.BigEndian, dltUSBPcap, [][]byte{interruptInReport(abReports[0])})
	hexReports, count, err := ExtractUSBPcapReports(pcap)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if count != 1 || hexReports != "0000040000000000" {
		t.Errorf("got count=%d hex=%q", count, hexReports)
	}
}

// TestExtractUSBPcap_Filtering verifies the heuristic skips everything that is
// not an 8-byte Interrupt-IN report: OUT (LED) reports, control transfers,
// short mouse reports, and bulk — keeping only the keyboard.
func TestExtractUSBPcap_Filtering(t *testing.T) {
	recs := [][]byte{
		usbpcapRecord(0x01, usbpcapTransferInterrupt, usbpcapHeaderLen, 1, []byte{0x00}),                   // Interrupt-OUT (LED) — skip
		usbpcapRecord(0x80, 2 /*control*/, usbpcapHeaderLen+8, 8, []byte{0, 0, 4, 0, 0, 0, 0, 0}),          // control, 35-byte header — skip
		usbpcapRecord(0x82, usbpcapTransferInterrupt, usbpcapHeaderLen, 4, []byte{0x01, 0x02, 0x03, 0x04}), // 4-byte mouse — skip
		usbpcapRecord(0x83, 3 /*bulk*/, usbpcapHeaderLen, 8, []byte{0, 0, 4, 0, 0, 0, 0, 0}),               // bulk — skip
		interruptInReport(abReports[0]), // the only keeper
	}
	hexReports, count, err := ExtractUSBPcapReports(buildPcap(binary.LittleEndian, dltUSBPcap, recs))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if count != 1 || hexReports != "0000040000000000" {
		t.Errorf("filtering wrong: got count=%d hex=%q want 1 / a-keydown", count, hexReports)
	}
}

// TestExtractUSBPcap_Rejects covers the error paths: wrong link type, pcapng,
// bad magic, too-short input, and a capture with no keyboard reports.
func TestExtractUSBPcap_Rejects(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		frag string
	}{
		{"wrong-linktype", buildPcap(binary.LittleEndian, 1 /*ethernet*/, [][]byte{interruptInReport(abReports[0])}), "not USBPcap"},
		{"pcapng", []byte{0x0a, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0}, "pcapng"},
		{"bad-magic", append([]byte{0x00, 0x11, 0x22, 0x33}, make([]byte, 20)...), "unrecognised magic"},
		{"too-short", []byte{0xd4, 0xc3}, "shorter than"},
		{"no-reports", buildPcap(binary.LittleEndian, dltUSBPcap, [][]byte{usbpcapRecord(0x01, usbpcapTransferInterrupt, usbpcapHeaderLen, 1, []byte{0})}), "no 8-byte"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := ExtractUSBPcapReports(c.in)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.frag)
			}
			if !strings.Contains(err.Error(), c.frag) {
				t.Errorf("error %q does not contain %q", err.Error(), c.frag)
			}
		})
	}
}

// TestExtractUSBPcap_TruncatedRecord ensures a record claiming more bytes than
// remain in the buffer is dropped cleanly (no panic, no over-read), and earlier
// valid records still extract.
func TestExtractUSBPcap_TruncatedRecord(t *testing.T) {
	good := interruptInReport(abReports[0])
	pcap := buildPcap(binary.LittleEndian, dltUSBPcap, [][]byte{good})
	// Append a record header claiming a huge incl_len with no body.
	rh := make([]byte, 16)
	binary.LittleEndian.PutUint32(rh[8:12], 0xffffff)
	pcap = append(pcap, rh...)

	_, count, err := ExtractUSBPcapReports(pcap)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if count != 1 {
		t.Errorf("count: got %d want 1 (truncated trailing record must be ignored)", count)
	}
}

// FuzzExtractUSBPcap feeds arbitrary bytes to the binary parser; it must never
// panic, only return (result,err). Seeded with a real capture and edge cases.
func FuzzExtractUSBPcap(f *testing.F) {
	f.Add(buildPcap(binary.LittleEndian, dltUSBPcap, [][]byte{interruptInReport(abReports[0])}))
	f.Add(buildPcap(binary.BigEndian, dltUSBPcap, [][]byte{interruptInReport(abReports[0])}))
	f.Add([]byte{0xd4, 0xc3, 0xb2, 0xa1})
	f.Add([]byte{0x0a, 0x0d, 0x0d, 0x0a})
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _, _ = ExtractUSBPcapReports(data) // must not panic
	})
}
