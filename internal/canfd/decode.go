// SPDX-License-Identifier: AGPL-3.0-or-later

// Package canfd decodes a captured CAN / CAN-FD frame in the SocketCAN
// candump text representation into its structured fields — the
// format-independent signal an automotive pentester reads off a bus
// capture without the bus attached.
//
// # Wrap-vs-native judgement
//
// Native. Like the other offline Sub-GHz / protocol decoders in this
// tree (subghz_tpms_decode, subghz_weather_decode, the canbus_* live
// Specs notwithstanding), the reusable part is a public deterministic
// transform: the SocketCAN candump frame grammar (ID#data /
// ID##flags+data), the ISO 11898-1:2015 CAN-FD DLC→length table, and
// the SAE J1939-21 extended-ID decomposition. The live canbus_* Specs
// drive an MCP2515 daughterboard to read frames; this decodes a frame
// already captured (candump -L, a SavvyCAN/Wireshark export, or a
// Flipper-side CAN sniff) with no hardware attached.
//
// # What it covers
//
//   - Classic CAN 2.0 (ID#data) and CAN-FD (ID##flags+data) candump
//     frames, standard (11-bit) and extended (29-bit) identifiers.
//   - CAN-FD flag nibble: BRS (bit-rate switch) and ESI (error-state
//     indicator); RTR (remote frame) for classic CAN.
//   - The CAN-FD DLC↔length mapping (0-8, 12, 16, 20, 24, 32, 48, 64),
//     flagging payloads that aren't a legal CAN-FD length.
//   - SAE J1939 decomposition of 29-bit IDs: priority, EDP/DP, PDU
//     format/specific, source address, and the resolved PGN with
//     PDU1 (destination-specific) vs PDU2 (broadcast) classification —
//     the heavy-vehicle / agricultural / marine bus most extended-ID
//     traffic uses.
//
// # Out of scope (deliberately)
//
//   - Signal-level decode (physical bytes → engine RPM, etc.): that
//     needs a per-vehicle DBC database and is unverifiable here, so the
//     raw data bytes are surfaced for the operator to apply their DBC —
//     a confidently-wrong signal value is worse than none.
//   - Live capture (use the canbus_* Specs with the MCP2515 board).
package canfd

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// J1939 is the SAE J1939-21 decomposition of a 29-bit extended ID.
type J1939 struct {
	Priority      int    `json:"priority"`
	EDP           int    `json:"extended_data_page"`
	DP            int    `json:"data_page"`
	PDUFormat     int    `json:"pdu_format"`
	PDUSpecific   int    `json:"pdu_specific"`
	SourceAddress int    `json:"source_address"`
	PGN           int    `json:"pgn"`
	PGNHex        string `json:"pgn_hex"`
	Kind          string `json:"kind"`
	DestAddress   *int   `json:"destination_address,omitempty"`
}

// Result is the structured decode of a CAN / CAN-FD frame.
type Result struct {
	Format     string   `json:"format"`
	IDHex      string   `json:"id_hex"`
	IDDecimal  uint32   `json:"id_decimal"`
	Extended   bool     `json:"extended"`
	IDBits     int      `json:"id_bits"`
	RTR        bool     `json:"rtr,omitempty"`
	FDF        bool     `json:"fdf"`
	BRS        bool     `json:"brs"`
	ESI        bool     `json:"esi"`
	DLC        int      `json:"dlc"`
	DataLength int      `json:"data_length"`
	DataHex    string   `json:"data_hex"`
	J1939      *J1939   `json:"j1939,omitempty"`
	Notes      []string `json:"notes,omitempty"`
}

// fdLengths is the set of legal CAN-FD payload lengths, in DLC order
// (index = DLC code 0..15).
var fdLengths = []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64}

// Decode parses a SocketCAN candump frame token. It tolerates a full
// candump line ("(ts) iface FRAME") by taking the last whitespace-
// delimited token, and tolerates ':' '-' '_' / whitespace inside the
// data field.
func Decode(in string) (*Result, error) {
	s := strings.TrimSpace(in)
	if s == "" {
		return nil, fmt.Errorf("canfd: empty frame")
	}
	// A pasted candump line carries a timestamp and interface; the
	// frame is the last token.
	if fields := strings.Fields(s); len(fields) > 1 {
		s = fields[len(fields)-1]
	}

	// CAN-FD uses "##" (must be checked before the classic "#").
	var idPart, payload string
	fd := false
	if i := strings.Index(s, "##"); i >= 0 {
		fd = true
		idPart, payload = s[:i], s[i+2:]
	} else if i := strings.Index(s, "#"); i >= 0 {
		idPart, payload = s[:i], s[i+1:]
	} else {
		return nil, fmt.Errorf("canfd: not a candump frame — expected ID#data (classic CAN) or ID##flags+data (CAN-FD)")
	}
	if idPart == "" {
		return nil, fmt.Errorf("canfd: missing CAN identifier before '#'")
	}

	id, idBits, err := parseID(idPart)
	if err != nil {
		return nil, err
	}

	r := &Result{
		IDHex:     strings.ToUpper(idPart),
		IDDecimal: id,
		Extended:  idBits == 29,
		IDBits:    idBits,
		FDF:       fd,
	}
	if fd {
		r.Format = "CAN-FD (ISO 11898-1:2015)"
		if err := decodeFDPayload(r, payload); err != nil {
			return nil, err
		}
	} else {
		r.Format = "CAN 2.0 (classic)"
		if err := decodeClassicPayload(r, payload); err != nil {
			return nil, err
		}
	}

	if r.Extended {
		r.J1939 = decodeJ1939(id)
		r.Notes = append(r.Notes,
			"29-bit extended ID decoded as SAE J1939 (the dominant extended-ID bus); if this frame is from a proprietary 29-bit protocol the J1939 fields are not meaningful — confirm against the vehicle")
	}
	r.Notes = append(r.Notes,
		"data bytes are raw; signal-level decode (RPM, speed, …) needs a per-vehicle DBC and is not attempted here")
	return r, nil
}

// parseID parses the hex identifier and infers standard (11-bit) vs
// extended (29-bit). candump zero-pads extended IDs to 8 hex chars and
// standard to 3, so length is the primary signal; a value above the
// 11-bit range forces extended.
func parseID(idPart string) (uint32, int, error) {
	clean := strings.ToUpper(idPart)
	v, err := parseHexU32(clean)
	if err != nil {
		return 0, 0, fmt.Errorf("canfd: invalid CAN identifier %q: %w", idPart, err)
	}
	if v > 0x1FFFFFFF {
		return 0, 0, fmt.Errorf("canfd: identifier 0x%X exceeds the 29-bit CAN range", v)
	}
	extended := len(clean) > 3 || v > 0x7FF
	if extended {
		return v, 29, nil
	}
	return v, 11, nil
}

func decodeFDPayload(r *Result, payload string) error {
	if payload == "" {
		return fmt.Errorf("canfd: CAN-FD frame missing the flags nibble after '##'")
	}
	flags, err := parseHexU32(payload[:1])
	if err != nil {
		return fmt.Errorf("canfd: invalid CAN-FD flags nibble %q: %w", payload[:1], err)
	}
	r.BRS = flags&0x1 != 0
	r.ESI = flags&0x2 != 0
	data, err := decodeDataHex(payload[1:])
	if err != nil {
		return err
	}
	r.DataLength = len(data)
	r.DataHex = strings.ToUpper(hex.EncodeToString(data))
	dlc, ok := lengthToDLC(len(data))
	if !ok {
		r.DLC = -1
		r.Notes = append(r.Notes, fmt.Sprintf(
			"payload is %d bytes — not a legal CAN-FD length (0-8, 12, 16, 20, 24, 32, 48, 64); capture may be truncated or misframed", len(data)))
		return nil
	}
	r.DLC = dlc
	return nil
}

func decodeClassicPayload(r *Result, payload string) error {
	// A classic remote frame is written "R" or "Rn" (n = requested DLC).
	if len(payload) > 0 && (payload[0] == 'R' || payload[0] == 'r') {
		r.RTR = true
		if len(payload) > 1 {
			n, err := parseHexU32(payload[1:])
			if err != nil || n > 8 {
				return fmt.Errorf("canfd: invalid classic remote-frame DLC %q", payload[1:])
			}
			r.DLC = int(n)
			r.DataLength = int(n)
		}
		return nil
	}
	data, err := decodeDataHex(payload)
	if err != nil {
		return err
	}
	if len(data) > 8 {
		return fmt.Errorf("canfd: classic CAN frame carries %d data bytes (max 8) — did you mean CAN-FD (use '##')?", len(data))
	}
	r.DataLength = len(data)
	r.DLC = len(data)
	r.DataHex = strings.ToUpper(hex.EncodeToString(data))
	return nil
}

// decodeJ1939 decomposes a 29-bit identifier per SAE J1939-21.
func decodeJ1939(id uint32) *J1939 {
	priority := int((id >> 26) & 0x7)
	edp := int((id >> 25) & 0x1)
	dp := int((id >> 24) & 0x1)
	pf := int((id >> 16) & 0xFF)
	ps := int((id >> 8) & 0xFF)
	sa := int(id & 0xFF)

	j := &J1939{
		Priority:      priority,
		EDP:           edp,
		DP:            dp,
		PDUFormat:     pf,
		PDUSpecific:   ps,
		SourceAddress: sa,
	}
	// PDU1 (PF < 240): destination-specific — PS is the destination
	// address and is NOT part of the PGN. PDU2 (PF >= 240): broadcast —
	// PS is a group extension and IS part of the PGN.
	if pf < 240 {
		j.Kind = "PDU1 (destination-specific)"
		j.PGN = (edp << 17) | (dp << 16) | (pf << 8)
		dest := ps
		j.DestAddress = &dest
	} else {
		j.Kind = "PDU2 (broadcast)"
		j.PGN = (edp << 17) | (dp << 16) | (pf << 8) | ps
	}
	j.PGNHex = fmt.Sprintf("0x%05X", j.PGN)
	return j
}

func lengthToDLC(n int) (int, bool) {
	for dlc, l := range fdLengths {
		if l == n {
			return dlc, true
		}
	}
	return 0, false
}

func decodeDataHex(s string) ([]byte, error) {
	clean := stripSeparators(s)
	if clean == "" {
		return nil, nil
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("canfd: data field has an odd hex-digit count (%d)", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("canfd: invalid hex in data field: %w", err)
	}
	return b, nil
}

func parseHexU32(s string) (uint32, error) {
	clean := stripSeparators(s)
	if clean == "" {
		return 0, fmt.Errorf("empty")
	}
	var v uint32
	for _, c := range clean {
		var d uint32
		switch {
		case c >= '0' && c <= '9':
			d = uint32(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint32(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint32(c-'A') + 10
		default:
			return 0, fmt.Errorf("non-hex character %q", string(c))
		}
		if v > (0xFFFFFFFF-d)/16 {
			return 0, fmt.Errorf("value overflows uint32")
		}
		v = v*16 + d
	}
	return v, nil
}

func stripSeparators(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', ':', '-', '_', '.':
			continue
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
