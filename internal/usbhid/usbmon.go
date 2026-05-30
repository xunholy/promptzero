// SPDX-License-Identifier: AGPL-3.0-or-later

package usbhid

import (
	"fmt"
	"strings"
)

// ExtractUsbmonReports pulls the 8-byte USB HID Keyboard Boot Protocol
// reports out of a Linux usbmon text capture (the format emitted by
// `cat /sys/kernel/debug/usb/usbmon/<N>u`, and what tshark/Wireshark show
// for usbmon-sourced captures). It returns the concatenated report bytes
// as a hex string ready for Decode, plus the number of reports found.
//
// # usbmon text line format
//
// Each line is, approximately:
//
//	<urb-tag> <timestamp> <type> <xfer><dir>:<bus>:<dev>:<ep> <status> <len> <marker> [<data-words>]
//
// e.g.
//
//		ffff8801ab33e3c0 1369381512 C Ii:1:003:1 0 8 = 00000400 00000000
//
//	  - type:   S (submit), C (callback/complete), E (submission error)
//	  - xfer:   C control, Z isoc, I interrupt, B bulk
//	  - dir:    i in, o out
//	  - marker: '=' data follows, '<' data not captured / none
//	  - data:   bytes in capture order, visually grouped into 4-byte words
//
// # What is extracted, and the heuristic
//
// A keyboard Boot Protocol report is exactly 8 bytes and arrives on an
// Interrupt-IN endpoint, surfaced to the host on the callback (C) line.
// ExtractUsbmonReports therefore keeps every line that is a callback (C),
// on an Interrupt-IN transfer (xfer/dir "Ii"), carries data (marker '='),
// and is exactly 8 bytes long. The 8-byte filter is what separates the
// keyboard from a co-resident mouse (3-4 byte boot reports) on the same
// bus; the per-report decode in Decode then validates the Boot Protocol
// structure. Submit (S) lines, Interrupt-OUT (Io, e.g. LED reports),
// control/bulk transfers, and non-8-byte interrupt data are skipped.
//
// Data bytes are printed in capture order (no endian swap), grouped into
// 4-byte words for readability; the words are simply concatenated.
func ExtractUsbmonReports(capture string) (hexReports string, count int, err error) {
	var sb strings.Builder
	for _, line := range strings.Split(capture, "\n") {
		fields := strings.Fields(line)
		// Need at least: tag ts type addr status len marker.
		if len(fields) < 7 {
			continue
		}
		if fields[2] != "C" { // callbacks carry the IN data
			continue
		}
		if !strings.HasPrefix(fields[3], "Ii") { // Interrupt-IN only
			continue
		}
		// Locate the data marker; the byte-length is the field before it.
		marker := -1
		for i := 4; i < len(fields); i++ {
			if fields[i] == "=" {
				marker = i
				break
			}
		}
		if marker < 0 || marker == 4 || marker+1 >= len(fields) {
			continue // no data captured ('<'), or malformed
		}
		if fields[marker-1] != "8" { // boot keyboard report is exactly 8 bytes
			continue
		}
		data := strings.ToLower(strings.Join(fields[marker+1:], ""))
		if len(data) != 16 || !isHexString(data) {
			continue
		}
		sb.WriteString(data)
		count++
	}
	if count == 0 {
		return "", 0, fmt.Errorf("no 8-byte Interrupt-IN HID keyboard reports found in usbmon capture " +
			"(expected callback lines like 'C Ii:<bus>:<dev>:<ep> 0 8 = ...'); ensure the capture is Linux " +
			"usbmon text format and the keyboard endpoint was recorded")
	}
	return sb.String(), count, nil
}

// isHexString reports whether s is non-empty and all hex digits.
func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}
