// SPDX-License-Identifier: AGPL-3.0-or-later

package isotp

import "fmt"

// MaxClassicFFLen is the largest message a classic-CAN First Frame can
// declare in its 12-bit FF_DL field. Larger messages need the CAN-FD 32-bit
// escape, which Segment does not emit (see the package doc).
const MaxClassicFFLen = 0xFFF

// Segment splits an application PDU into the ISO-TP (ISO 15765-2) CAN frame
// data fields needed to transmit it — the inverse of Reassemble. A PDU of
// up to 7 bytes becomes a single Single Frame; a longer PDU becomes a First
// Frame followed by Consecutive Frames with cycling sequence numbers
// (1,2,…,15,0,1,…). Every returned frame is padded to 8 bytes with pad
// (classic CAN's fixed frame size; the pad value is cosmetic — ISO-TP
// ignores bytes beyond the declared length). The output is exactly what you
// feed to a CAN injector to send a multi-frame UDS / OBD-II request, and it
// round-trips through Reassemble back to the original PDU.
func Segment(pdu []byte, pad byte) ([][]byte, error) {
	if len(pdu) == 0 {
		return nil, fmt.Errorf("isotp: empty PDU")
	}

	// Single Frame: PCI high nibble 0, low nibble = length.
	if len(pdu) <= 7 {
		f := make([]byte, 8)
		for i := range f {
			f[i] = pad
		}
		f[0] = byte(len(pdu)) // 0x0L
		copy(f[1:], pdu)
		return [][]byte{f}, nil
	}

	if len(pdu) > MaxClassicFFLen {
		return nil, fmt.Errorf("isotp: PDU %d bytes exceeds the 12-bit classic First Frame limit (%d); CAN-FD 32-bit escape not emitted", len(pdu), MaxClassicFFLen)
	}

	var frames [][]byte
	// First Frame: 0x1<len_hi> <len_lo> + first 6 bytes.
	ff := make([]byte, 8)
	ff[0] = 0x10 | byte(len(pdu)>>8)
	ff[1] = byte(len(pdu) & 0xFF)
	copy(ff[2:], pdu[:6])
	frames = append(frames, ff)

	// Consecutive Frames: 0x2<SN> + up to 7 bytes each.
	rest := pdu[6:]
	sn := 1
	for len(rest) > 0 {
		cf := make([]byte, 8)
		for i := range cf {
			cf[i] = pad
		}
		cf[0] = 0x20 | byte(sn&0x0F)
		n := copy(cf[1:], rest)
		rest = rest[n:]
		frames = append(frames, cf)
		sn++
	}
	return frames, nil
}
