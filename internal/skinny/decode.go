// SPDX-License-Identifier: AGPL-3.0-or-later

// Package skinny decodes the Skinny Client Control Protocol (SCCP) — the
// Cisco-proprietary signalling protocol between a Cisco IP phone and a
// CallManager / CUCM (TCP 2000). It is a VoIP-reconnaissance target: SCCP
// is unencrypted in many deployments, so a captured exchange reveals the
// call flow (register, off-hook, dial, ring, connect, hang-up) and — via
// the KeypadButton messages — the actual digits the user dials, i.e. the
// numbers being called. Decoding it surfaces that activity. It joins the
// project's other VoIP / signalling decoders (internal/sip, rtp, rtcp).
//
// # Wrap-vs-native judgement
//
//	Native. A Skinny message is a trivial little-endian frame: a 4-octet
//	length, a 4-octet reserved field, a 4-octet message ID, then the
//	message body. The length makes the stream self-delimiting, so
//	decoding is a framed walk + an ID lookup — a dependency is not
//	justified. stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The frame structure and the message IDs were verified against
//	scapy's Skinny layer, and the 132-entry message-name table is
//	code-generated from scapy.contrib.skinny (not hand-transcribed).
//	The KeypadButton message (the dialed digit) is decoded because its
//	body is a simple fixed layout. Every other message body is surfaced
//	as raw hex with the message named — Skinny has ~130 message types
//	with varied, version-specific bodies, so decoding them all would
//	invite confidently-wrong output.
package skinny

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of one or more Skinny messages.
type Result struct {
	Messages []Message `json:"messages"`
	Notes    []string  `json:"notes,omitempty"`
}

// Message is one decoded Skinny message.
type Message struct {
	Length      int    `json:"length"`
	MessageID   string `json:"message_id"`
	MessageName string `json:"message_name"`
	DialedDigit string `json:"dialed_digit,omitempty"` // KeypadButton
	BodyHex     string `json:"body_hex,omitempty"`
}

// Decode parses one or more concatenated Skinny messages from hex
// (whitespace / ':' / '-' / '_' separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 12 {
		return nil, fmt.Errorf("skinny: %d bytes — too short for a Skinny message (min 12)", len(b))
	}
	r := &Result{}
	off := 0
	for off+12 <= len(b) {
		length := int(binary.LittleEndian.Uint32(b[off : off+4]))
		// The length counts everything after the 8-octet length+reserved
		// header (i.e. the message ID + body).
		frameEnd := off + 8 + length
		if length < 4 || frameEnd > len(b) {
			if off == 0 {
				return nil, fmt.Errorf("skinny: declared length %d does not fit the buffer — not a Skinny message", length)
			}
			r.Notes = append(r.Notes, fmt.Sprintf("trailing %d bytes after the last complete message (truncated or non-Skinny)", len(b)-off))
			break
		}
		id := binary.LittleEndian.Uint32(b[off+8 : off+12])
		m := Message{Length: length, MessageID: fmt.Sprintf("0x%04X", id), MessageName: messageName(id)}
		body := b[off+12 : frameEnd]
		if id == 0x0003 && len(body) >= 4 { // KeypadButton: the dialed digit
			m.DialedDigit = keypadDigit(binary.LittleEndian.Uint32(body[0:4]))
		}
		if len(body) > 0 {
			m.BodyHex = strings.ToUpper(hex.EncodeToString(body))
		}
		r.Messages = append(r.Messages, m)
		off = frameEnd
	}
	if len(r.Messages) == 0 {
		return nil, fmt.Errorf("skinny: no complete Skinny message found")
	}
	hasKeypad := false
	for _, m := range r.Messages {
		if m.DialedDigit != "" {
			hasKeypad = true
		}
	}
	if hasKeypad {
		r.Notes = append(r.Notes, "KeypadButton messages reveal the digits the user dialed (the called number) — SCCP is unencrypted in many deployments, the VoIP-recon exposure")
	}
	r.Notes = append(r.Notes, "message bodies other than KeypadButton are surfaced as raw hex (Skinny has ~130 message types with varied, version-specific bodies; only the structure + dialed digit are decoded, to avoid confidently-wrong output)")
	return r, nil
}

// keypadDigit maps a Skinny KeypadButton key code to its character.
func keypadDigit(k uint32) string {
	switch {
	case k <= 9:
		return string('0' + byte(k))
	case k == 14:
		return "*"
	case k == 15:
		return "#"
	}
	return fmt.Sprintf("key %d", k)
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("skinny: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("skinny: input is not valid hex: %w", err)
	}
	return b, nil
}
