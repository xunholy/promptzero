// SPDX-License-Identifier: AGPL-3.0-or-later

package osdp

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// The per-reply payload field layouts are ported verbatim from the
// libosdp reference reply builder (src/osdp_pd.c build_reply), which is
// the authoritative wire format — each field's width and endianness is
// stated explicitly there (bwrite_u16_le / u24_le / u32_le / u24_be).

// CardRead is the osdp_RAW (0x50) card-read reply payload.
type CardRead struct {
	ReaderNo    int    `json:"reader_no"`
	Format      int    `json:"format"`
	FormatName  string `json:"format_name"`
	BitCount    int    `json:"bit_count"`
	CardDataHex string `json:"card_data_hex,omitempty"`
}

// DeviceID is the osdp_PDID (0x45) device-identification reply payload.
type DeviceID struct {
	VendorCode      string `json:"vendor_code"` // 24-bit OUI
	Model           int    `json:"model"`
	Version         int    `json:"version"`
	SerialNumber    uint32 `json:"serial_number"`
	FirmwareVersion string `json:"firmware_version"`
}

// ComConfig is the osdp_COM (0x54) communication-configuration reply.
type ComConfig struct {
	Address  int    `json:"address"`
	BaudRate uint32 `json:"baud_rate"`
}

// Keypad is the osdp_KEYPAD (0x53) key-press reply payload.
type Keypad struct {
	ReaderNo  int    `json:"reader_no"`
	Length    int    `json:"length"`
	KeysHex   string `json:"keys_hex,omitempty"`
	KeysASCII string `json:"keys_ascii,omitempty"`
}

// LocalStatus is the osdp_LSTATR (0x48) local-status reply payload.
type LocalStatus struct {
	Tamper int `json:"tamper"`
	Power  int `json:"power"`
}

// decodePayload fills the typed payload field on r for the reply codes
// with a well-defined plaintext layout. data is the bytes between the
// reply code and the trailer; reply is true for a PD->CP frame.
func decodePayload(r *Result, code byte, data []byte, reply bool) {
	if !reply {
		return // command payload field decode is deferred
	}
	switch code {
	case 0x50: // osdp_RAW
		if len(data) >= 4 {
			bitCount := int(data[2]) | int(data[3])<<8
			cr := &CardRead{
				ReaderNo:   int(data[0]),
				Format:     int(data[1]),
				FormatName: cardFormatName(data[1]),
				BitCount:   bitCount,
			}
			if len(data) > 4 {
				cr.CardDataHex = strings.ToUpper(hex.EncodeToString(data[4:]))
			}
			r.CardRead = cr
		}
	case 0x45: // osdp_PDID
		if len(data) >= 12 {
			r.DeviceID = &DeviceID{
				VendorCode:      fmt.Sprintf("0x%06X", int(data[0])|int(data[1])<<8|int(data[2])<<16),
				Model:           int(data[3]),
				Version:         int(data[4]),
				SerialNumber:    uint32(data[5]) | uint32(data[6])<<8 | uint32(data[7])<<16 | uint32(data[8])<<24,
				FirmwareVersion: fmt.Sprintf("%d.%d.%d", data[9], data[10], data[11]), // u24 big-endian
			}
		}
	case 0x54: // osdp_COM
		if len(data) >= 5 {
			r.ComConfig = &ComConfig{
				Address:  int(data[0]),
				BaudRate: uint32(data[1]) | uint32(data[2])<<8 | uint32(data[3])<<16 | uint32(data[4])<<24,
			}
		}
	case 0x53: // osdp_KEYPAD
		if len(data) >= 2 {
			n := int(data[1])
			k := &Keypad{ReaderNo: int(data[0]), Length: n}
			if n > 0 && 2+n <= len(data) {
				keys := data[2 : 2+n]
				k.KeysHex = strings.ToUpper(hex.EncodeToString(keys))
				k.KeysASCII = keypadASCII(keys)
			}
			r.Keypad = k
		}
	case 0x48: // osdp_LSTATR
		if len(data) >= 2 {
			r.LocalStatus = &LocalStatus{Tamper: int(data[0]), Power: int(data[1])}
		}
	}
}

func cardFormatName(f byte) string {
	switch f {
	case 0:
		return "raw/unspecified"
	case 1:
		return "wiegand"
	case 2:
		return "ascii"
	}
	return "unknown"
}

// keypadASCII renders the keypad bytes as text where printable. OSDP
// keypad bytes are typically ASCII digits with 0x0D (#/enter) and 0x7F
// (*/escape) for the function keys.
func keypadASCII(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		switch {
		case c >= 0x20 && c <= 0x7E:
			sb.WriteByte(c)
		case c == 0x0D:
			sb.WriteByte('#')
		case c == 0x7F:
			sb.WriteByte('*')
		default:
			sb.WriteByte('.')
		}
	}
	return sb.String()
}
