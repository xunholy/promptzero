// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Michael Fornaro

package pcap

import (
	"encoding/binary"
	"errors"
	"io"
	"time"
)

var (
	errBadMagic    = errors.New("pcap: unrecognised magic number (not a classic pcap file)")
	errBadVersion  = errors.New("pcap: unexpected pcap version (expected 2.4)")
	errPacketTrunc = errors.New("pcap: packet data truncated")
)

// Reader reads a libpcap classic file emitted by Writer.
// It supports both little-endian (magic 0xa1b2c3d4) and big-endian
// (magic 0xd4c3b2a1) files, though Writer only produces little-endian.
type Reader struct {
	r        io.Reader
	order    binary.ByteOrder
	linkType LinkType
	nano     bool   // true if magic was the nanosecond variant
	maxPkt   uint32 // per-packet read cap (clamped snaplen)
}

// absoluteMaxPacket caps a single packet's captured length regardless
// of the file's declared snaplen. A garbage/malicious pcap can declare
// inclLen up to 0xFFFFFFFF (4 GiB), and make([]byte, inclLen) would
// OOM before io.ReadFull could fail. 16 MiB is far above any real
// frame (jumbo Ethernet ~9 KiB, USB captures ~64 KiB, libpcap's
// MAXIMUM_SNAPLEN is 256 KiB) while bounding the allocation.
const absoluteMaxPacket = 16 << 20

// NewReader reads and validates the 24-byte global pcap header from r.
// Returns an error if the magic is unrecognised or the version is not 2.4.
func NewReader(r io.Reader) (*Reader, error) {
	var hdr [globalHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}

	magic := binary.LittleEndian.Uint32(hdr[0:])
	var order binary.ByteOrder
	var nano bool

	switch magic {
	case 0xa1b2c3d4: // little-endian microseconds
		order = binary.LittleEndian
	case 0xd4c3b2a1: // big-endian microseconds
		order = binary.BigEndian
	case 0xa1b23c4d: // little-endian nanoseconds
		order = binary.LittleEndian
		nano = true
	case 0x4d3cb2a1: // big-endian nanoseconds
		order = binary.BigEndian
		nano = true
	default:
		return nil, errBadMagic
	}

	vmaj := order.Uint16(hdr[4:])
	vmin := order.Uint16(hdr[6:])
	if vmaj != pcapVersionMajor || vmin != pcapVersionMinor {
		return nil, errBadVersion
	}

	// snaplen (hdr[16:20]) bounds the per-packet capture length.
	// Clamp it to the absolute max so a bogus snaplen (0 or
	// 0xFFFFFFFF) can't drive an oversized allocation downstream.
	snaplen := order.Uint32(hdr[16:])
	maxPkt := snaplen
	if maxPkt == 0 || maxPkt > absoluteMaxPacket {
		maxPkt = absoluteMaxPacket
	}

	lt := LinkType(order.Uint32(hdr[20:]))
	return &Reader{r: r, order: order, linkType: lt, nano: nano, maxPkt: maxPkt}, nil
}

// LinkType returns the file's link-type field from the global header.
func (r *Reader) LinkType() LinkType { return r.linkType }

// Next returns the next packet's timestamp and raw frame bytes, or
// io.EOF when the file is exhausted. Any other error indicates a
// malformed or truncated file.
func (r *Reader) Next() (time.Time, []byte, error) {
	var rec [perPacketHeaderLen]byte
	if _, err := io.ReadFull(r.r, rec[:]); err != nil {
		// io.ReadFull converts io.EOF on the very first byte to
		// io.ErrUnexpectedEOF; we want clean io.EOF at packet boundaries.
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return time.Time{}, nil, io.EOF
		}
		return time.Time{}, nil, err
	}

	tsSec := r.order.Uint32(rec[0:])
	tsFrac := r.order.Uint32(rec[4:])
	inclLen := r.order.Uint32(rec[8:])
	// orig_len (rec[12:]) is informational — we read inclLen bytes.

	// Reject a record claiming more captured bytes than the file's
	// snaplen (clamped) allows. Without this, a garbage inclLen of
	// up to 4 GiB would drive make([]byte, inclLen) into an OOM
	// before the io.ReadFull below could fail. Found via fuzzing.
	if inclLen > r.maxPkt {
		return time.Time{}, nil, errPacketTrunc
	}

	var ts time.Time
	if r.nano {
		ts = time.Unix(int64(tsSec), int64(tsFrac)).UTC()
	} else {
		ts = time.Unix(int64(tsSec), int64(tsFrac)*1000).UTC()
	}

	data := make([]byte, inclLen)
	if _, err := io.ReadFull(r.r, data); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return time.Time{}, nil, errPacketTrunc
		}
		return time.Time{}, nil, err
	}

	return ts, data, nil
}
