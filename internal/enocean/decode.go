// SPDX-License-Identifier: AGPL-3.0-or-later

// Package enocean decodes EnOcean ESP3 packets and the ERP1 radio
// telegrams they carry — the self-powered 868 / 902 / 315 MHz building-
// automation protocol behind batteryless light switches, occupancy /
// window-contact / temperature sensors and actuators. A USB gateway
// (USB300/400J) or an SDR emits ESP3 frames; decoding them yields the
// device identity (32-bit sender ID), the telegram type, the radio
// signal strength and an integrity check — the reconnaissance a
// building-automation RF pentest starts from.
//
// # Wrap-vs-native judgement
//
//	Native. ESP3 is a fixed, fully-public framing (EnOcean Serial
//	Protocol 3): 0x55 sync, a 4-byte header (16-bit data length,
//	8-bit optional length, 8-bit packet type), a header CRC-8, the
//	data, the optional data, and a data CRC-8. The CRC is the
//	standard CRC-8 (polynomial 0x07). The RADIO_ERP1 data is
//	RORG + payload + 4-byte sender ID + status byte. All of that is
//	byte-field extraction plus one table-driven CRC-8, reimplemented
//	here from the EnOcean spec / the kipe enocean reference — no new
//	dependency, no shell-out.
//
// # What this covers
//
//   - ESP3 framing: sync, data / optional lengths, packet type (+ name),
//     and BOTH CRC-8s (header + data) recomputed and reported valid /
//     invalid.
//   - RADIO_ERP1 telegram (packet type 1): RORG (+ name: RPS / 1BS /
//     4BS / VLD / MSC / UTE / …), the payload, the 32-bit sender ID,
//     the status byte (+ repeater count), and the optional data
//     (sub-telegram count, destination ID, RSSI in -dBm, security
//     level).
//
// # Deliberately deferred
//
//	EEP (EnOcean Equipment Profile) payload decode — the meaning of
//	the data bytes (which rocker was pressed, the contact open/closed
//	state, a 4BS sensor's temperature/humidity) depends on the device's
//	FUNC/TYPE profile, which the telegram does NOT carry, so it would
//	be a confidently-wrong guess; the raw payload + RORG are surfaced
//	instead. Over-the-air ERP1/ERP2 radio framing (an SDR capture
//	before ESP3 wrapping) and AES secure telegrams are also deferred.
package enocean

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded ESP3 packet.
type Result struct {
	SyncByteOK      bool       `json:"sync_byte_ok"`
	DataLength      int        `json:"data_length"`
	OptionalLength  int        `json:"optional_length"`
	PacketType      int        `json:"packet_type"`
	PacketTypeName  string     `json:"packet_type_name"`
	HeaderCRC8      string     `json:"header_crc8"`
	HeaderCRC8Valid bool       `json:"header_crc8_valid"`
	DataCRC8        string     `json:"data_crc8"`
	DataCRC8Valid   bool       `json:"data_crc8_valid"`
	DataHex         string     `json:"data_hex,omitempty"`
	OptionalHex     string     `json:"optional_hex,omitempty"`
	Radio           *RadioERP1 `json:"radio_erp1,omitempty"`
	Notes           []string   `json:"notes,omitempty"`
}

// RadioERP1 is the decoded RADIO_ERP1 (packet type 1) telegram.
type RadioERP1 struct {
	RORG          string         `json:"rorg"`
	RORGName      string         `json:"rorg_name"`
	PayloadHex    string         `json:"payload_hex,omitempty"`
	SenderID      string         `json:"sender_id"`
	Status        string         `json:"status"`
	RepeaterCount int            `json:"repeater_count"`
	Optional      *RadioOptional `json:"optional,omitempty"`
}

// RadioOptional is the optional-data block of a received RADIO_ERP1.
type RadioOptional struct {
	SubTelegramNum int    `json:"sub_telegram_num"`
	DestinationID  string `json:"destination_id"`
	RSSIdBm        int    `json:"rssi_dbm"`
	SecurityLevel  int    `json:"security_level"`
}

// Decode parses an EnOcean ESP3 packet from hex. ':' / '-' / '_' /
// whitespace separators and a '0x' prefix are tolerated.
func Decode(hexStr string) (*Result, error) {
	b, err := hex.DecodeString(stripSep(hexStr))
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	// 0x55 + 4-byte header + CRC8H + CRC8D minimum.
	if len(b) < 7 {
		return nil, fmt.Errorf("packet too short (%d bytes; minimum ESP3 frame is 7)", len(b))
	}
	r := &Result{SyncByteOK: b[0] == 0x55}
	if !r.SyncByteOK {
		return nil, fmt.Errorf("not an ESP3 frame: first byte is 0x%02X (expected sync 0x55)", b[0])
	}

	r.DataLength = int(b[1])<<8 | int(b[2])
	r.OptionalLength = int(b[3])
	r.PacketType = int(b[4])
	r.PacketTypeName = packetTypeName(b[4])

	r.HeaderCRC8 = fmt.Sprintf("0x%02X", b[5])
	r.HeaderCRC8Valid = crc8(b[1:5]) == b[5]

	total := 6 + r.DataLength + r.OptionalLength + 1 // + CRC8D
	if total > len(b) {
		return nil, fmt.Errorf("declared lengths (data %d + optional %d) overrun the %d-byte packet",
			r.DataLength, r.OptionalLength, len(b))
	}
	data := b[6 : 6+r.DataLength]
	opt := b[6+r.DataLength : 6+r.DataLength+r.OptionalLength]
	crc8d := b[6+r.DataLength+r.OptionalLength]
	r.DataCRC8 = fmt.Sprintf("0x%02X", crc8d)
	r.DataCRC8Valid = crc8(b[6:6+r.DataLength+r.OptionalLength]) == crc8d

	if len(data) > 0 {
		r.DataHex = strings.ToUpper(hex.EncodeToString(data))
	}
	if len(opt) > 0 {
		r.OptionalHex = strings.ToUpper(hex.EncodeToString(opt))
	}
	if !r.HeaderCRC8Valid || !r.DataCRC8Valid {
		r.Notes = append(r.Notes, "CRC-8 check FAILED (corrupt frame, wrong byte boundaries, or truncated capture)")
	}

	// RADIO_ERP1: RORG + payload + sender ID (4) + status (1).
	if r.PacketType == 0x01 && r.DataLength >= 6 {
		rorg := data[0]
		erp := &RadioERP1{
			RORG:          fmt.Sprintf("0x%02X", rorg),
			RORGName:      rorgName(rorg),
			SenderID:      strings.ToUpper(hex.EncodeToString(data[r.DataLength-5 : r.DataLength-1])),
			Status:        fmt.Sprintf("0x%02X", data[r.DataLength-1]),
			RepeaterCount: int(data[r.DataLength-1] & 0x0F),
		}
		if payload := data[1 : r.DataLength-5]; len(payload) > 0 {
			erp.PayloadHex = strings.ToUpper(hex.EncodeToString(payload))
		}
		// Received RADIO_ERP1 optional data: subTelNum + dest(4) + dBm + sec.
		if len(opt) >= 7 {
			erp.Optional = &RadioOptional{
				SubTelegramNum: int(opt[0]),
				DestinationID:  strings.ToUpper(hex.EncodeToString(opt[1:5])),
				RSSIdBm:        -int(opt[5]),
				SecurityLevel:  int(opt[6]),
			}
		}
		r.Radio = erp
		r.Notes = append(r.Notes,
			"EEP (device-profile) payload decode is deferred — the telegram does not carry the FUNC/TYPE; raw payload surfaced")
	}
	return r, nil
}

func stripSep(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r', ',':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
