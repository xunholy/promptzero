// SPDX-License-Identifier: AGPL-3.0-or-later

// Package isotp decodes ISO-TP (ISO 15765-2) transport frames and
// reassembles the multi-frame messages that carry UDS / OBD-II over CAN —
// the transport layer that sits between a raw CAN frame (canfd) and the
// diagnostic application PDU (uds / obd2).
//
// # Wrap-vs-native judgement
//
// Native. The ISO-TP Protocol Control Information (PCI) is a public,
// deterministic encoding (ISO 15765-2): the high nibble of the first data
// byte is the frame type — 0 Single Frame, 1 First Frame, 2 Consecutive
// Frame, 3 Flow Control — and the remaining nibbles/bytes carry the length,
// sequence number, or flow-control parameters. Decoding and reassembly are
// a few branches over byte slices; no bus, no hardware. The uds decoder
// explicitly takes an already-reassembled PDU and notes ISO-TP framing as
// out of scope — this provides exactly that reassembly: feed a captured CAN
// frame's data field (single frame), or the ordered First + Consecutive
// frames of a multi-frame message, and get the application PDU to hand to
// uds_decode / obd2_pid_decode / obd2_dtc_decode.
//
// # Covered / deferred
//
// Classic (≤7-byte CAN) and the CAN-FD escape forms of Single Frame
// (SF_DL=0 → length in the next byte) and First Frame (FF_DL=0 → 32-bit
// length) are handled. Reassembly validates consecutive-frame sequence
// numbers and stops at the declared length. Flow-control frames are decoded
// and skipped during reassembly (they originate from the receiver). The
// addressing modes beyond normal (extended/mixed, with an address byte
// ahead of the PCI) are not assumed — pass the data starting at the PCI
// byte.
package isotp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Frame is one decoded ISO-TP transport frame.
type Frame struct {
	Type           string   `json:"type"`                      // SingleFrame | FirstFrame | ConsecutiveFrame | FlowControl
	PCIType        int      `json:"pci_type"`                  // 0..3
	Length         int      `json:"length,omitempty"`          // SF data length, or FF total message length
	SequenceNumber *int     `json:"sequence_number,omitempty"` // CF
	FlowStatus     *int     `json:"flow_status,omitempty"`     // FC
	FlowStatusName string   `json:"flow_status_name,omitempty"`
	BlockSize      *int     `json:"block_size,omitempty"` // FC
	STmin          *int     `json:"st_min,omitempty"`     // FC (raw byte)
	PayloadHex     string   `json:"payload_hex,omitempty"`
	Notes          []string `json:"notes,omitempty"`
}

var flowStatusNames = map[int]string{0: "ContinueToSend", 1: "Wait", 2: "Overflow/abort"}

// DecodeFrame decodes a single CAN frame's data field as an ISO-TP frame.
func DecodeFrame(data []byte) (*Frame, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("isotp: empty frame")
	}
	pci := int(data[0] >> 4)
	f := &Frame{PCIType: pci}
	switch pci {
	case 0: // Single Frame
		f.Type = "SingleFrame"
		sfDL := int(data[0] & 0x0F)
		if sfDL != 0 {
			f.Length = sfDL
			f.PayloadHex = take(data[1:], sfDL, f)
			return f, nil
		}
		// CAN-FD escape: SF_DL = 0 → length in byte 1.
		if len(data) < 2 {
			f.Notes = append(f.Notes, "single-frame escape but no length byte")
			return f, nil
		}
		f.Length = int(data[1])
		f.PayloadHex = take(data[2:], f.Length, f)
	case 1: // First Frame
		f.Type = "FirstFrame"
		if len(data) < 2 {
			return nil, fmt.Errorf("isotp: first frame truncated")
		}
		ffDL := int(data[0]&0x0F)<<8 | int(data[1])
		if ffDL != 0 {
			f.Length = ffDL
			f.PayloadHex = upper(data[2:])
			return f, nil
		}
		// CAN-FD escape: FF_DL = 0 → 32-bit length in bytes 2..5.
		if len(data) < 6 {
			return nil, fmt.Errorf("isotp: first-frame 32-bit-length escape truncated")
		}
		f.Length = int(binary.BigEndian.Uint32(data[2:6]))
		f.PayloadHex = upper(data[6:])
	case 2: // Consecutive Frame
		f.Type = "ConsecutiveFrame"
		sn := int(data[0] & 0x0F)
		f.SequenceNumber = &sn
		f.PayloadHex = upper(data[1:])
	case 3: // Flow Control
		f.Type = "FlowControl"
		fs := int(data[0] & 0x0F)
		f.FlowStatus = &fs
		f.FlowStatusName = flowStatusNames[fs]
		if f.FlowStatusName == "" {
			f.FlowStatusName = fmt.Sprintf("reserved (0x%X)", fs)
		}
		if len(data) >= 2 {
			bs := int(data[1])
			f.BlockSize = &bs
		}
		if len(data) >= 3 {
			st := int(data[2])
			f.STmin = &st
		}
	}
	return f, nil
}

// take returns up to n bytes of payload as hex, noting a shortfall.
func take(b []byte, n int, f *Frame) string {
	if n > len(b) {
		f.Notes = append(f.Notes, fmt.Sprintf("declared %d payload bytes; only %d present", n, len(b)))
		n = len(b)
	}
	return upper(b[:n])
}

func upper(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) }

// Reassembly is the result of reassembling an ISO-TP message from an
// ordered list of CAN frame data fields.
type Reassembly struct {
	Frames     []Frame  `json:"frames"`
	Complete   bool     `json:"complete"`
	Length     int      `json:"length,omitempty"`      // declared total length
	PayloadHex string   `json:"payload_hex,omitempty"` // reassembled application PDU
	Notes      []string `json:"notes,omitempty"`
}

// Reassemble decodes and reassembles an ordered sequence of CAN frame data
// fields into the carried application PDU. A lone Single Frame yields its
// payload directly; a First Frame followed by Consecutive Frames is
// concatenated up to the declared length. Flow-control frames are decoded
// into the per-frame list but skipped for reassembly.
func Reassemble(framesData [][]byte) (*Reassembly, error) {
	if len(framesData) == 0 {
		return nil, fmt.Errorf("isotp: no frames supplied")
	}
	out := &Reassembly{}
	var payload []byte
	total := -1
	expectSN := 1
	started := false

	for i, fd := range framesData {
		f, err := DecodeFrame(fd)
		if err != nil {
			return nil, fmt.Errorf("isotp: frame %d: %w", i, err)
		}
		out.Frames = append(out.Frames, *f)
		switch f.Type {
		case "FlowControl":
			continue // receiver-originated; not part of the payload
		case "SingleFrame":
			if started {
				out.Notes = append(out.Notes, fmt.Sprintf("frame %d: unexpected SingleFrame mid-message; ignored", i))
				continue
			}
			b, _ := hex.DecodeString(f.PayloadHex)
			out.Length = f.Length
			out.PayloadHex = f.PayloadHex
			out.Complete = len(b) >= f.Length
			return out, nil
		case "FirstFrame":
			if started {
				out.Notes = append(out.Notes, fmt.Sprintf("frame %d: second FirstFrame; restarting", i))
				payload = nil
			}
			started = true
			total = f.Length
			b, _ := hex.DecodeString(f.PayloadHex)
			payload = append(payload, b...)
			expectSN = 1
		case "ConsecutiveFrame":
			if !started {
				out.Notes = append(out.Notes, fmt.Sprintf("frame %d: ConsecutiveFrame before a FirstFrame; ignored", i))
				continue
			}
			if f.SequenceNumber != nil && *f.SequenceNumber != (expectSN&0x0F) {
				out.Notes = append(out.Notes, fmt.Sprintf("frame %d: sequence number %d, expected %d", i, *f.SequenceNumber, expectSN&0x0F))
			}
			expectSN++
			b, _ := hex.DecodeString(f.PayloadHex)
			payload = append(payload, b...)
		}
		if total >= 0 && len(payload) >= total {
			break
		}
	}

	if total < 0 {
		out.Notes = append(out.Notes, "no Single or First frame found")
		return out, nil
	}
	out.Length = total
	if len(payload) > total {
		payload = payload[:total]
	}
	out.PayloadHex = upper(payload)
	out.Complete = len(payload) == total
	if !out.Complete {
		out.Notes = append(out.Notes, fmt.Sprintf("incomplete: have %d of %d bytes", len(payload), total))
	}
	return out, nil
}
