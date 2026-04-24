// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Michael Fornaro

// Package pcap implements a pure-Go libpcap classic-format writer and
// reader. It is deliberately minimal: no CGo, no gopacket, stdlib only.
// The output is compatible with Wireshark, aircrack-ng, and hashcat.
package pcap

import (
	"encoding/binary"
	"errors"
	"io"
	"time"
)

// LinkType identifies the data-link encapsulation of frames in the pcap.
type LinkType uint32

const (
	// LinkTypeEthernet is IEEE 802.3 Ethernet.
	LinkTypeEthernet LinkType = 1

	// LinkTypeIEEE802_11 is raw 802.11 without any prefix header.
	// This is what most Marauder packet dumps emit.
	LinkTypeIEEE802_11 LinkType = 105

	// LinkTypeIEEE802_11Radiotap is 802.11 preceded by a radiotap header.
	// Preferred for hashcat / aircrack-ng because it carries channel and RSSI.
	LinkTypeIEEE802_11Radiotap LinkType = 127
)

const (
	pcapMagicMicrosecond uint32 = 0xa1b2c3d4
	pcapVersionMajor     uint16 = 2
	pcapVersionMinor     uint16 = 4
	pcapSnaplen          uint32 = 65535

	globalHeaderLen    = 24
	perPacketHeaderLen = 16
)

var errNilData = errors.New("pcap: WritePacket called with nil data")

// Writer streams packets to an io.Writer in libpcap classic format.
//
// Concurrency: not safe for concurrent WritePacket; serialise externally.
//
// Usage:
//
//	w, err := pcap.NewWriter(file, pcap.LinkTypeIEEE802_11Radiotap)
//	if err != nil { ... }
//	w.WritePacket(time.Now(), frameBytes)
//	// closing the underlying file is the caller's responsibility
type Writer struct {
	w        io.Writer
	written  int64
	packets  int
	lastErr  error // sticky: if non-nil the next write is a no-op
}

// NewWriter writes the 24-byte global header to w and returns a Writer
// ready for WritePacket calls. Returns an error if the global header
// cannot be written.
func NewWriter(w io.Writer, linkType LinkType) (*Writer, error) {
	wr := &Writer{w: w}
	if err := wr.writeGlobalHeader(linkType); err != nil {
		return nil, err
	}
	return wr, nil
}

func (w *Writer) writeGlobalHeader(lt LinkType) error {
	// 24 bytes, all little-endian:
	//  u32 magic   u16 vmaj  u16 vmin
	//  i32 zone    u32 sigfigs
	//  u32 snaplen u32 network
	buf := make([]byte, globalHeaderLen)
	le := binary.LittleEndian
	le.PutUint32(buf[0:], pcapMagicMicrosecond)
	le.PutUint16(buf[4:], pcapVersionMajor)
	le.PutUint16(buf[6:], pcapVersionMinor)
	le.PutUint32(buf[8:], 0)  // thiszone = 0 (UTC)
	le.PutUint32(buf[12:], 0) // sigfigs = 0
	le.PutUint32(buf[16:], pcapSnaplen)
	le.PutUint32(buf[20:], uint32(lt))
	n, err := w.w.Write(buf)
	w.written += int64(n)
	return err
}

// WritePacket appends one packet record. ts is the capture timestamp;
// data is the raw frame bytes (already including any radiotap header
// when the Writer was created with LinkTypeIEEE802_11Radiotap).
//
// If data is nil an error is returned and no bytes are written.
// If a previous write already failed, WritePacket attempts the write
// anyway (no poison-pill behaviour).
func (w *Writer) WritePacket(ts time.Time, data []byte) error {
	if data == nil {
		return errNilData
	}

	inclLen := uint32(len(data))
	if inclLen > pcapSnaplen {
		inclLen = pcapSnaplen
	}
	origLen := uint32(len(data))

	tsSec := uint32(ts.Unix())
	tsUsec := uint32(ts.Nanosecond() / 1000)

	// 16-byte per-packet record header
	buf := make([]byte, perPacketHeaderLen)
	le := binary.LittleEndian
	le.PutUint32(buf[0:], tsSec)
	le.PutUint32(buf[4:], tsUsec)
	le.PutUint32(buf[8:], inclLen)
	le.PutUint32(buf[12:], origLen)

	n, err := w.w.Write(buf)
	w.written += int64(n)
	if err != nil {
		w.lastErr = err
		return err
	}

	n, err = w.w.Write(data[:inclLen])
	w.written += int64(n)
	if err != nil {
		w.lastErr = err
		return err
	}

	w.packets++
	return nil
}

// PacketsWritten returns the count of successful WritePacket calls.
func (w *Writer) PacketsWritten() int { return w.packets }

// BytesWritten returns the total bytes written, including the global
// header and all per-packet record headers.
func (w *Writer) BytesWritten() int64 { return w.written }
