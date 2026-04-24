// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Michael Fornaro

package pcap

import "encoding/binary"

// Radiotap present-bitmap bits used by this minimal implementation.
// Bit positions are defined by the radiotap.org specification.
//
//	Bit 1  → Flags
//	Bit 2  → Rate
//	Bit 3  → Channel (freq + channel flags, 4 bytes)
//	Bit 5  → DBM_AntSignal
//
// 0x0000_002E = bits 1|2|3|5 set.
const radiotapPresentBitmap uint32 = 0x0000002E

// radiotapHeaderLen is the fixed encoded length of a RadiotapHeader as
// returned by Bytes: 8 bytes fixed prefix + 1+1+4+1 = 15 → padded to 16
// for natural alignment of the Channel u16 field.
//
// Layout (all little-endian, offsets relative to start of radiotap):
//  0: u8  it_version = 0
//  1: u8  it_pad = 0
//  2: u16 it_len = 16  (total radiotap header length)
//  4: u32 it_present = 0x0000002E
//  8: u8  Flags
//  9: u8  Rate
// 10: u16 Channel freq (MHz)
// 12: u16 Channel flags
// 14: i8  DBM_AntSignal
// 15: u8  padding (alignment)
const radiotapHeaderLen = 16

// RadiotapHeader is a minimal radiotap prefix for 802.11 frames. Prepend
// the result of Bytes() before the raw 802.11 frame when writing with
// LinkTypeIEEE802_11Radiotap.
type RadiotapHeader struct {
	// Channel is the centre frequency in MHz (e.g. 2412 for channel 1,
	// 5180 for channel 36). Zero is treated as unknown / unset.
	Channel uint16

	// Flags is the radiotap Flags field (bit 1 in the present bitmap).
	// 0x10 signals that an FCS is appended to the frame payload.
	Flags uint8

	// SignalDBM is the receive signal strength in dBm (e.g. -65).
	// Zero means unknown.
	SignalDBM int8

	// Rate is the data rate in units of 500 kbps (e.g. 2 = 1 Mbit/s).
	// Zero means unknown.
	Rate uint8
}

// Bytes returns the 16-byte radiotap-encoded prefix to prepend to a
// bare 802.11 frame before handing it to Writer.WritePacket when the
// Writer was created with LinkTypeIEEE802_11Radiotap.
func (h RadiotapHeader) Bytes() []byte {
	buf := make([]byte, radiotapHeaderLen)
	le := binary.LittleEndian

	buf[0] = 0 // it_version
	buf[1] = 0 // it_pad
	le.PutUint16(buf[2:], uint16(radiotapHeaderLen)) // it_len
	le.PutUint32(buf[4:], radiotapPresentBitmap)      // it_present

	// Fields in present-bitmap order (bit 1 first):
	buf[8] = h.Flags  // Flags  (bit 1)
	buf[9] = h.Rate   // Rate   (bit 2)

	// Channel: 2 bytes freq + 2 bytes channel flags (bit 3).
	// Channel flags: 0x0080 = 2 GHz spectrum; 0x0100 = 5 GHz spectrum.
	// Use a simple heuristic: freq < 3000 → 2 GHz flag, else 5 GHz flag.
	le.PutUint16(buf[10:], h.Channel)
	var chFlags uint16
	if h.Channel > 0 && h.Channel < 3000 {
		chFlags = 0x0080
	} else if h.Channel >= 5000 {
		chFlags = 0x0100
	}
	le.PutUint16(buf[12:], chFlags)

	buf[14] = byte(h.SignalDBM) // DBM_AntSignal (bit 5), i8 cast to u8
	buf[15] = 0                 // padding

	return buf
}
