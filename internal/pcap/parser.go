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
	nano     bool // true if magic was the nanosecond variant
}

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

	lt := LinkType(order.Uint32(hdr[20:]))
	return &Reader{r: r, order: order, linkType: lt, nano: nano}, nil
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
