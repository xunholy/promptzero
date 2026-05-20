// Package gsmtap decodes GSMTAP pseudo-header bytes per the
// Osmocom GSMTAP specification (osmo-bts / osmo-pcap-server /
// gsmtap.h reference). GSMTAP is the **canonical encapsulation
// for cellular protocol captures** — every Osmocom tool
// (osmo-bts, osmo-bsc, osmo-pcu, osmo-msc, osmo-sgsn,
// osmo-hnbgw, OpenBTS, srsRAN, YateBTS) prepends a 16-byte
// GSMTAP header to captured layer-2 / layer-3 cellular frames
// and ships them via UDP/4729 (default) for Wireshark to
// dissect with the right dissector per payload type.
//
// Operationally, GSMTAP appears in:
//
//   - **DEF CON / Black Hat / HITB cellular CTF** challenges —
//     the GSMTAP-wrapped capture is the canonical "here's a
//     GSM/UMTS/LTE air-interface trace, decode the
//     conversation" challenge.
//   - **SDR cellular research** — RTL-SDR + grgsm_livemon +
//     Wireshark live-decode of nearby base stations; airprobe
//   - Kraken A5/1 cracking pipelines; LimeSDR + srsUE
//     fronthaul captures.
//   - **Osmocom development** — gsmtap.h headers in osmo-*
//     codebases stream traces of internal protocol state for
//     debugging across the cellular stack (BTS → BSC → MSC →
//     HLR → VLR).
//   - **5G research** — SUCI / SUPI extraction from LTE / 5G NR
//     RRC captures (PayloadType 0x0E LTE RRC), IMSI catcher
//     forensics, gNB / eNB fingerprinting.
//
// Wrap-vs-native judgement
//
//	Native. The Osmocom gsmtap.h header is publicly documented
//	(osmocom-bb / libosmocore). The 16-byte fixed pseudo-
//	header is a tight, deterministic structure with a 1-byte
//	PayloadType field discriminating ~15 cellular protocol
//	categories and a 1-byte SubType field that's payload-type-
//	specific. The walker decodes the header + dispatches the
//	PayloadType + SubType against per-type name tables but
//	does not decode the encapsulated cellular layer-2/3 bytes
//	(those are per-protocol and out of scope — surfaced as
//	`payload_hex` for downstream cellular-protocol decoders).
//
// What this package covers
//
//   - **GSMTAP pseudo-header** (16 bytes; multi-byte fields are
//     big-endian):
//
//   - byte 0: Version (= 0x02 for current GSMTAP; v0x01
//     is the legacy version still occasionally seen in
//     old Osmocom captures).
//
//   - byte 1: HeaderLen (in 32-bit words; usually 4 → 16
//     bytes total header).
//
//   - byte 2: **PayloadType** (1 byte; the canonical
//     discriminator — see name table below).
//
//   - byte 3: Timeslot (TDMA slot 0-7 within a GSM
//     frame; -1 / 0xFF if not applicable).
//
//   - bytes 4-5: **ARFCN** (uint16 BE; bottom 14 bits =
//     Absolute Radio Frequency Channel Number; bit 14 =
//     PCS band; bit 15 = uplink). The decoder surfaces
//     the trimmed ARFCN, the PCS-band flag, and the
//     uplink/downlink flag separately.
//
//   - byte 6: Signal level (int8; received signal
//     strength in dBm — negative values are normal).
//
//   - byte 7: SNR (int8; signal-to-noise ratio in dB —
//     positive values are normal; -1 / 0xFF if not
//     measured).
//
//   - bytes 8-11: **Frame Number** (uint32 BE; GSM TDMA
//     frame counter — 0 to 2,715,647; wraps every ~3.5
//     hours).
//
//   - byte 12: **SubType** (1 byte; payload-type-specific
//     — for GSM Um L2 it's the channel type, for LTE
//     RRC it's the channel direction).
//
//   - byte 13: Antenna number (which MIMO antenna; 0 for
//     SISO).
//
//   - byte 14: SubSlot (sub-slot within the Timeslot —
//     used for SDCCH/8 + similar multi-sub-slot channels).
//
//   - byte 15: Reserved (= 0).
//
//   - **15+ entry PayloadType name table** (Osmocom gsmtap.h):
//     0x00 `UM` (legacy alias for `UM_L2`) / 0x01 `UM_L2`
//     (GSM L2 frame on the Um air interface — the most common
//     GSMTAP-wrapped traffic) / 0x02 `ABIS` (BTS↔BSC LAPD) /
//     0x03 `UM_BURST` (raw GSM burst bits) / 0x04 `SIM` (SIM
//     APDU exchange) / 0x05 `TETRA_I1` (TETRA Layer 1) /
//     0x06 `TETRA_I1_BURST` / 0x07 `WMX_BURST` (WiMAX burst)
//     / 0x08 `GB_LLC` (GPRS Gb LLC) / 0x09 `GB_SNDCP` (GPRS
//     Gb SNDCP) / 0x0A `GMR1_UM` (Geo-Mobile Radio 1) /
//     0x0D `UMTS_RLC_MAC` (UMTS RLC-MAC) / 0x0E `LTE_RRC`
//     (LTE Radio Resource Control) / 0x0F `LTE_MAC` / 0x10
//     `LTE_MAC_FRAMED` (LTE MAC with framing for srsRAN
//     compatibility) / 0x11 `OSMOCORE_LOG` (text log lines
//     wrapped for unified capture) / 0x12 `QC_DIAG` (Qualcomm
//     DIAG passthrough from QC modems).
//
//   - **17-entry GSM Um L2 channel name table** (gsmtap.h
//     gsmtap_um_chan; used when PayloadType = 0x01 UM_L2):
//     0x01 `BCCH` (Broadcast Control Channel) / 0x02 `CCCH`
//     (Common Control Channel) / 0x03 `RACH` (Random Access
//     Channel) / 0x04 `AGCH` (Access Grant Channel) / 0x05
//     `PCH` (Paging Channel) / 0x06 `SDCCH` (Standalone
//     Dedicated Control Channel) / 0x07 `SDCCH4` / 0x08
//     `SDCCH8` / 0x09 `TCH_F` (Traffic Channel Full-rate) /
//     0x0A `TCH_H` (Traffic Channel Half-rate) / 0x0B
//     `PACCH` (Packet Associated Control Channel) / 0x0C
//     `CBCH52` (Cell Broadcast Channel on /52) / 0x0D
//     `PDCH` (Packet Data Channel) / 0x0E `PTCCH` (Packet
//     Timing Advance Control Channel) / 0x0F `CBCH51` (Cell
//     Broadcast Channel on /51) / 0x10 `VOICE_F` (full-rate
//     voice TRAU frame) / 0x11 `VOICE_H` (half-rate voice
//     TRAU frame).
//
//   - **2-entry LTE RRC channel direction table** (used when
//     PayloadType = 0x0E LTE_RRC): 0 `Downlink` (BCCH-DL /
//     PCCH-DL / DL-CCCH / DL-DCCH / MCCH) / 1 `Uplink`
//     (UL-CCCH / UL-DCCH).
//
//   - **ARFCN band + uplink decode**: the top 2 bits of the
//     16-bit ARFCN field encode the band — bit 15 is set on
//     **uplink** frames (MS → BTS direction), bit 14 is set
//     for the **PCS** (1900 MHz) band. The decoder surfaces
//     all three as `arfcn`, `arfcn_uplink`, and `arfcn_pcs`.
//
//   - **Encapsulated cellular payload** — bytes after the
//     GSMTAP pseudo-header are the raw cellular layer-2 /
//     layer-3 frame; surfaced as `payload_hex` for downstream
//     cellular-protocol decoders (LAPDm / RR / MM / CM /
//     RANAP / RRC / NAS / etc.).
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Network framing** — feed GSMTAP bytes after the UDP-
//     datagram header strip (default UDP port 4729).
//   - **Encapsulated cellular protocol bodies** — the
//     PayloadType + SubType discriminate which cellular
//     protocol is wrapped (GSM RR / GSM MM / GSM CM / GSM
//     SS / GPRS LLC / UMTS RRC / LTE RRC / LTE NAS / 5G NAS
//     etc.); per-protocol decoders are dataset-specific and
//     surfaced as `payload_hex` for follow-on walkers.
//   - **GSMTAPv1** — the obsolete v1 header (4 bytes shorter)
//     is rare in modern captures; the decoder reports the
//     version byte but only walks v2 (version 0x02) fields.
//   - **Burst data decoding** — PayloadType 0x03 UM_BURST
//     carries raw GSM burst bits (148-bit normal burst); the
//     decoder surfaces the burst-bit payload as hex but does
//     not decode the GMSK modulation symbols.
//   - **Osmocore log text decoding** — PayloadType 0x11
//     OSMOCORE_LOG carries free-form text log lines; the
//     decoder surfaces them as `payload_hex`; UTF-8 decoding
//     is a follow-on step.
//   - **TETRA / WiMAX / GMR-1** payload-type-specific decoders
//     — these are non-3GPP cellular sidebands surfaced as
//     opaque payload_hex.
package gsmtap

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the structured decode of a GSMTAP pseudo-header +
// the opaque cellular payload it wraps.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// Header
	Version      int    `json:"version"`
	HeaderLength int    `json:"header_length_words"`
	HeaderBytes  int    `json:"header_length_bytes"`
	PayloadType  int    `json:"payload_type"`
	PayloadName  string `json:"payload_type_name"`
	Timeslot     int    `json:"timeslot"`
	ARFCN        int    `json:"arfcn"`
	ARFCNUplink  bool   `json:"arfcn_uplink"`
	ARFCNPCSBand bool   `json:"arfcn_pcs_band"`
	SignalDBm    int    `json:"signal_dbm"`
	SNRDb        int    `json:"snr_db"`
	FrameNumber  uint32 `json:"frame_number"`
	SubType      int    `json:"sub_type"`
	SubTypeName  string `json:"sub_type_name,omitempty"`
	Antenna      int    `json:"antenna"`
	SubSlot      int    `json:"sub_slot"`

	// Payload (cellular layer-2 / layer-3 frame)
	PayloadHex string `json:"payload_hex,omitempty"`
}

// Decode parses a GSMTAP message from a hex string starting at
// the Version byte. Separators (':' '-' '_' whitespace)
// tolerated; '0x' prefix tolerated.
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if len(clean) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex (%d nibbles)", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) < 16 {
		return nil, fmt.Errorf("GSMTAP message truncated (%d bytes; need ≥16 for v2 header)",
			len(b))
	}

	r := &Result{
		TotalBytes:   len(b),
		Version:      int(b[0]),
		HeaderLength: int(b[1]),
		PayloadType:  int(b[2]),
		Timeslot:     int(b[3]),
		SignalDBm:    int(int8(b[6])),
		SNRDb:        int(int8(b[7])),
		FrameNumber:  binary.BigEndian.Uint32(b[8:12]),
		SubType:      int(b[12]),
		Antenna:      int(b[13]),
		SubSlot:      int(b[14]),
	}
	r.HeaderBytes = r.HeaderLength * 4
	r.PayloadName = payloadTypeName(r.PayloadType)
	arfcn := binary.BigEndian.Uint16(b[4:6])
	r.ARFCN = int(arfcn & 0x3FFF)
	r.ARFCNPCSBand = arfcn&0x4000 != 0
	r.ARFCNUplink = arfcn&0x8000 != 0
	r.SubTypeName = subTypeName(r.PayloadType, r.SubType)

	// Payload starts after the indicated HeaderLength (defaults
	// to 16 bytes; some early Osmocom tools sent shorter
	// headers).
	payloadStart := r.HeaderBytes
	if payloadStart < 16 {
		payloadStart = 16
	}
	if payloadStart < len(b) {
		r.PayloadHex = strings.ToUpper(hex.EncodeToString(b[payloadStart:]))
	}
	return r, nil
}

func payloadTypeName(t int) string {
	switch t {
	case 0x00:
		return "UM"
	case 0x01:
		return "UM_L2"
	case 0x02:
		return "ABIS"
	case 0x03:
		return "UM_BURST"
	case 0x04:
		return "SIM"
	case 0x05:
		return "TETRA_I1"
	case 0x06:
		return "TETRA_I1_BURST"
	case 0x07:
		return "WMX_BURST"
	case 0x08:
		return "GB_LLC"
	case 0x09:
		return "GB_SNDCP"
	case 0x0A:
		return "GMR1_UM"
	case 0x0D:
		return "UMTS_RLC_MAC"
	case 0x0E:
		return "LTE_RRC"
	case 0x0F:
		return "LTE_MAC"
	case 0x10:
		return "LTE_MAC_FRAMED"
	case 0x11:
		return "OSMOCORE_LOG"
	case 0x12:
		return "QC_DIAG"
	}
	return fmt.Sprintf("uncatalogued payload type 0x%02X", t)
}

// subTypeName decodes the SubType byte against the per-PayloadType
// sub-type registry (only the most useful ones — GSM Um L2 channel
// types + LTE RRC channel directions).
func subTypeName(payload, sub int) string {
	switch payload {
	case 0x01: // UM_L2 → channel type
		return umL2ChannelName(sub)
	case 0x0E: // LTE_RRC → channel direction
		return lteRRCChannelName(sub)
	}
	return ""
}

func umL2ChannelName(c int) string {
	switch c {
	case 0x01:
		return "BCCH"
	case 0x02:
		return "CCCH"
	case 0x03:
		return "RACH"
	case 0x04:
		return "AGCH"
	case 0x05:
		return "PCH"
	case 0x06:
		return "SDCCH"
	case 0x07:
		return "SDCCH4"
	case 0x08:
		return "SDCCH8"
	case 0x09:
		return "TCH_F"
	case 0x0A:
		return "TCH_H"
	case 0x0B:
		return "PACCH"
	case 0x0C:
		return "CBCH52"
	case 0x0D:
		return "PDCH"
	case 0x0E:
		return "PTCCH"
	case 0x0F:
		return "CBCH51"
	case 0x10:
		return "VOICE_F"
	case 0x11:
		return "VOICE_H"
	}
	return fmt.Sprintf("uncatalogued GSM Um L2 channel 0x%02X", c)
}

func lteRRCChannelName(d int) string {
	// Per the gsmtap_lte_rrc_types enum the values are channel
	// type codes (BCCH_BCH=0, BCCH_DL_SCH=1, ...); a full
	// table would have ~10 entries. Surface the most common
	// downlink/uplink distinction by parity for now (Osmocom
	// uses even = DL, odd = UL convention).
	if d%2 == 0 {
		return "Downlink"
	}
	return "Uplink"
}

func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', ':', '-', '_':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
