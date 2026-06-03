// SPDX-License-Identifier: AGPL-3.0-or-later

// Package iso14443b decodes an ISO/IEC 14443 Type B ATQB (the PICC's answer to
// REQB/WUPB) — the second contact-less proximity standard alongside Type A
// (this project's internal/iso14443a). Type B is the air interface behind most
// ePassports (ICAO 9303), several national eID cards, and some transit/payment
// cards, so identifying a Type B card and its protocol parameters is a common
// recon step. Offline read of an operator-supplied ATQB dump; no hardware.
//
// # Wrap-vs-native judgement
//
// Native. The ATQB is a fixed 12-byte structure (ISO 14443-3 §7.9) — a 0x50
// leading byte, a 4-byte PUPI, 4 bytes of application data, and 3 protocol-info
// bytes of documented bit fields. A few dozen lines of byte parsing.
//
// # Verifiable / no confidently-wrong output
//
// The 0x50 leading byte is the hard anchor: an ATQB that doesn't start 0x50 is
// reported as non-standard rather than mis-decoded. Every interpreted field
// (max frame size FSCI table, FWI→FWT, bit-rate capability, NAD/CID support) is
// a documented ISO 14443-3/-4 bit field — no proprietary guessing; PUPI and
// application data (card-specific) are surfaced raw.
//
// # Covered / deferred
//
// Covered: the 12-byte ATQB (PUPI, application data, and the full protocol-info
// decode). An optional 13th "extended" protocol-info byte (SFGI) is noted but
// not interpreted, and the card-specific application-data layout is surfaced raw.
package iso14443b

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// ATQB is a decoded Type B answer-to-request.
type ATQB struct {
	Raw                string   `json:"raw"`
	Valid              bool     `json:"valid"` // leading byte == 0x50
	PUPI               string   `json:"pupi"`
	ApplicationData    string   `json:"application_data"`
	BitRate            *BitRate `json:"bit_rate,omitempty"`
	FSCI               int      `json:"fsci"`
	MaxFrameSizeBytes  int      `json:"max_frame_size_bytes"`
	SupportsISO14443_4 bool     `json:"supports_iso14443_4"`
	FWI                int      `json:"fwi"`
	FWTms              float64  `json:"fwt_ms"`
	NADSupported       bool     `json:"nad_supported"`
	CIDSupported       bool     `json:"cid_supported"`
	Notes              []string `json:"notes,omitempty"`
}

// BitRate is the decoded Bit_Rate_capability byte (supported rates in kbit/s;
// 106 is always supported and implicit).
type BitRate struct {
	SameBitrateBothWays bool  `json:"same_bitrate_both_ways"`
	PICCtoPCD           []int `json:"picc_to_pcd_kbps"`
	PCDtoPICC           []int `json:"pcd_to_picc_kbps"`
}

// fsciToBytes is the ISO 14443-3 FSCI → FSC (max frame size) table, shared with
// Type A.
var fsciToBytes = []int{16, 24, 32, 40, 48, 64, 96, 128, 256}

// DecodeATQB decodes a 12-byte ATQB given as hex (a trailing 2-byte CRC_B is
// tolerated and ignored).
func DecodeATQB(hexStr string) (*ATQB, error) {
	clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "").Replace(strings.TrimSpace(hexStr))
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("iso14443b: ATQB is not valid hex: %w", err)
	}
	a := &ATQB{Raw: strings.ToUpper(hex.EncodeToString(b))}
	switch {
	case len(b) == 14:
		a.Notes = append(a.Notes, "trailing 2 bytes treated as CRC_B and ignored")
		b = b[:12]
	case len(b) == 13:
		a.Notes = append(a.Notes, "13th byte present (extended protocol-info / SFGI) — not interpreted")
		b = b[:12]
	case len(b) != 12:
		return nil, fmt.Errorf("iso14443b: ATQB must be 12 bytes (got %d)", len(b))
	}

	a.Valid = b[0] == 0x50
	if !a.Valid {
		a.Notes = append(a.Notes, fmt.Sprintf("leading byte 0x%02X is not 0x50 — not a standard ATQB", b[0]))
	}
	a.PUPI = strings.ToUpper(hex.EncodeToString(b[1:5]))
	a.ApplicationData = strings.ToUpper(hex.EncodeToString(b[5:9]))

	// Protocol info: b[9] bit-rate capability, b[10] FSCI|protocol-type,
	// b[11] FWI|ADC|FO.
	a.BitRate = decodeBitRate(b[9])
	a.FSCI = int(b[10] >> 4)
	if a.FSCI < len(fsciToBytes) {
		a.MaxFrameSizeBytes = fsciToBytes[a.FSCI]
	} else {
		a.Notes = append(a.Notes, fmt.Sprintf("FSCI %d is RFU (no defined frame size)", a.FSCI))
	}
	a.SupportsISO14443_4 = b[10]&0x01 != 0 // protocol-type bit
	a.FWI = int(b[11] >> 4)
	// FWT = (256 * 16 / fc) * 2^FWI, fc = 13.56 MHz -> 0.3021 ms * 2^FWI.
	a.FWTms = 0.302064 * float64(int(1)<<uint(a.FWI))
	a.NADSupported = b[11]&0x01 != 0 // FO bit 0
	a.CIDSupported = b[11]&0x02 != 0 // FO bit 1
	return a, nil
}

func decodeBitRate(br byte) *BitRate {
	r := &BitRate{SameBitrateBothWays: br&0x80 != 0}
	// PICC -> PCD: bit6 848, bit5 424, bit4 212.
	if br&0x10 != 0 {
		r.PICCtoPCD = append(r.PICCtoPCD, 212)
	}
	if br&0x20 != 0 {
		r.PICCtoPCD = append(r.PICCtoPCD, 424)
	}
	if br&0x40 != 0 {
		r.PICCtoPCD = append(r.PICCtoPCD, 848)
	}
	// PCD -> PICC: bit2 848, bit1 424, bit0 212.
	if br&0x01 != 0 {
		r.PCDtoPICC = append(r.PCDtoPICC, 212)
	}
	if br&0x02 != 0 {
		r.PCDtoPICC = append(r.PCDtoPICC, 424)
	}
	if br&0x04 != 0 {
		r.PCDtoPICC = append(r.PCDtoPICC, 848)
	}
	return r
}
