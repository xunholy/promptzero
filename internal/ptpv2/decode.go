// Package ptpv2 decodes PTPv2 (Precision Time Protocol version 2)
// packets per IEEE 1588-2008. PTPv2 is the de-facto wire-time
// synchronisation protocol for modern networks that need sub-
// microsecond clock alignment across hosts — well beyond what NTP
// can deliver.
//
// PTPv2 is operationally relevant in:
//
//   - **5G / telecom fronthaul** (eCPRI radio units require ±1.5 µs
//     TAE per O-RAN, met via PTP boundary clocks + SyncE).
//   - **Finance** (MiFID II RTS 25 mandates ≤100 µs traceable to UTC
//     for HFT venues; exchanges and broker-dealers run PTP grandmaster
//     hardware fed by GPS).
//   - **Industrial automation** (IEEE 802.1AS — PTP profile gPTP — is
//     the time base for TSN traffic shaping; used in robotics, motion
//     control, autonomous-vehicle in-cabin networks).
//   - **Power grid telemetry** (IEC 61850-9-3 power profile mandates
//     PTP for sampled-values + GOOSE timestamping inside substations).
//   - **Broadcast media** (SMPTE ST 2110 IP video needs PTP for
//     frame-locked playout across switcher/router fabrics).
//
// Wrap-vs-native judgement
//
//	Native. IEEE 1588-2008 is a fully public spec; PTPv2 has a
//	tight 34-byte common header followed by a per-messageType
//	body and (rarely) a TLV suffix. No crypto at the parse layer
//	(the authentication TLVs in IEEE 1588-2019 are out of scope
//	for v2). The decoder is host-side — operators feed PTP bytes
//	from a UDP/319 (event) or UDP/320 (general) packet or from an
//	IEEE 802.3 EtherType 0x88F7 frame.
//
// What this package covers
//
//   - **Common header** (IEEE 1588-2008 §13.3, 34 bytes):
//
//   - byte 0: 4-bit transportSpecific + 4-bit messageType.
//
//   - byte 1: 4-bit Reserved + 4-bit versionPTP (= 2).
//
//   - bytes 2-3: messageLength (uint16 BE; total bytes
//     including header, body, and any suffix TLVs).
//
//   - byte 4: domainNumber (0 = default; multiple PTP domains
//     can co-exist on the same network).
//
//   - byte 5: Reserved.
//
//   - bytes 6-7: flagField (uint16 BE; per-message bits like
//     PTP_LI_61, PTP_LI_59, PTP_UTC_REASONABLE,
//     PTP_TIMESCALE, TIME_TRACEABLE, FREQUENCY_TRACEABLE,
//     alternateMaster, twoStep, unicast — surfaced as hex
//     plus a decoded comma-separated set of well-known flag
//     names).
//
//   - bytes 8-15: correctionField (int64 BE; scaled-
//     nanoseconds — high 48 bits are nanoseconds, low 16 bits
//     are sub-nanosecond fractional; used by transparent
//     clocks to accumulate residence time).
//
//   - bytes 16-19: Reserved.
//
//   - bytes 20-29: sourcePortIdentity = 8-byte clockIdentity
//     (typically EUI-64 derived from MAC) + 2-byte portNumber.
//
//   - bytes 30-31: sequenceId (uint16 BE; per-portIdentity
//     monotonic counter used to pair Sync/Follow_Up,
//     Delay_Req/Delay_Resp, Pdelay_Req/Resp/Resp_Follow_Up).
//
//   - byte 32: controlField (deprecated in v2 but still
//     transmitted; historically encoded messageType for
//     v1-compat receivers).
//
//   - byte 33: logMessageInterval (int8; log base-2 of mean
//     inter-message interval in seconds — e.g. -3 = 125 ms,
//     0 = 1 s, 1 = 2 s).
//
//   - **10-entry messageType name table** (IEEE 1588-2008 §13.3.2.2):
//     0x0 Sync / 0x1 Delay_Req / 0x2 Pdelay_Req / 0x3 Pdelay_Resp /
//     0x8 Follow_Up / 0x9 Delay_Resp / 0xA Pdelay_Resp_Follow_Up /
//     0xB Announce / 0xC Signaling / 0xD Management. (Event messages
//     0x0–0x3 travel on UDP/319 and are hardware-timestamped on entry/
//     exit; general messages 0x8–0xD travel on UDP/320.)
//
//   - **Per-messageType body decoders** (IEEE 1588-2008 §13.6-13.13):
//
//   - **Sync, Delay_Req, Follow_Up, Delay_Resp**: 10-byte
//     PTP-timestamp (6-byte secondsField + 4-byte
//     nanosecondsField). Sync carries the originTimestamp
//     (one-step) or is paired with Follow_Up carrying the
//     preciseOriginTimestamp (two-step, indicated by the
//     twoStep flag). Delay_Resp additionally carries the
//     requestingPortIdentity (10 bytes after the timestamp).
//
//   - **Pdelay_Req**: 10-byte originTimestamp + 10-byte
//     Reserved (preserves length symmetry with Pdelay_Resp).
//
//   - **Pdelay_Resp**: 10-byte requestReceiptTimestamp + 10-
//     byte requestingPortIdentity.
//
//   - **Pdelay_Resp_Follow_Up**: 10-byte
//     responseOriginTimestamp + 10-byte requestingPortIdentity.
//
//   - **Announce**: 10-byte originTimestamp + 2-byte
//     currentUtcOffset (seconds) + 1-byte Reserved + 1-byte
//     grandmasterPriority1 + 4-byte grandmasterClockQuality
//     (1-byte clockClass + 1-byte clockAccuracy + 2-byte
//     offsetScaledLogVariance) + 1-byte grandmasterPriority2
//
//   - 8-byte grandmasterIdentity + 2-byte stepsRemoved +
//     1-byte timeSource. Announce is the Best Master Clock
//     Algorithm (BMCA) input — every clock compares incoming
//     Announce records and elects the best grandmaster.
//
//   - **9-entry timeSource name table** (IEEE 1588-2008 §7.6.2.6):
//     0x10 ATOMIC_CLOCK / 0x20 GPS / 0x30 TERRESTRIAL_RADIO /
//     0x40 PTP / 0x50 NTP / 0x60 HAND_SET / 0x90 OTHER /
//     0xA0 INTERNAL_OSCILLATOR (plus uncatalogued).
//
//   - **8-entry clockAccuracy name table** (IEEE 1588-2008 §7.6.2.5):
//     selected high-runner values 0x20 within 25ns / 0x21
//     within 100ns / 0x22 within 250ns / 0x23 within 1µs /
//     0x24 within 2.5µs / 0x25 within 10µs / 0x31 within 1s /
//     0xFE UNKNOWN.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Network framing** — UDP/319 (event), UDP/320 (general), or
//     IEEE 802.3 EtherType 0x88F7. Feed PTP bytes after the
//     transport-header strip.
//   - **TLV suffix walker** — PTPv2 messages may carry trailing TLVs
//     (organisation-specific extensions, management responses,
//     authentication for IEEE 1588-2019). messageLength surfaces the
//     total bytes and the per-type body decoder consumes the
//     standard portion; remaining bytes are surfaced as
//     `tlv_suffix_hex` for future per-TLV decoders.
//   - **Signaling / Management body decoders** — Signaling (0xC)
//     and Management (0xD) carry a 10-byte targetPortIdentity
//     followed by tlv records; the targetPortIdentity is decoded
//     and the rest is surfaced as raw hex. Per-action TLV decoders
//     (REQUEST_UNICAST_TRANSMISSION, GET / SET responses, etc.) are
//     future work.
//   - **BMCA reasoning** — the decoder surfaces every Announce field
//     needed to drive BMCA (priority1, clockQuality,
//     grandmasterIdentity, stepsRemoved, priority2) but does not
//     itself compare records or pick a winner.
//   - **gPTP (IEEE 802.1AS) profile validation** — gPTP forbids
//     several PTP message subtypes (Delay_Req / Delay_Resp; only
//     P2P delay via Pdelay_* is allowed) and pins specific flag
//     combinations; the decoder surfaces the raw values without
//     profile-conformance checks.
//   - **Cryptographic authentication** — the IEEE 1588-2019 (v2.1)
//     AUTHENTICATION_TLV is out of scope (this package targets
//     v2-2008 bare-wire deployments).
//   - **Clock state-machine reasoning** — slave-side servo loop,
//     transparent-clock residence-time accumulation, boundary-clock
//     port-state changes; higher-level analysis.
package ptpv2

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the structured decode of a PTPv2 packet. Optional
// fields are pointer-typed so they only appear in JSON for the
// messageType that populates them.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// Common header
	TransportSpecific  int    `json:"transport_specific"`
	MessageType        int    `json:"message_type"`
	MessageTypeName    string `json:"message_type_name"`
	VersionPTP         int    `json:"version_ptp"`
	MessageLength      int    `json:"message_length"`
	DomainNumber       int    `json:"domain_number"`
	FlagFieldHex       string `json:"flag_field_hex"`
	FlagsDecoded       string `json:"flags_decoded,omitempty"`
	CorrectionField    int64  `json:"correction_field_scaled_ns"`
	ClockIdentity      string `json:"clock_identity"`
	PortNumber         int    `json:"port_number"`
	SequenceID         int    `json:"sequence_id"`
	ControlField       int    `json:"control_field"`
	LogMessageInterval int    `json:"log_message_interval"`

	// Per-type bodies (only one set populated)
	OriginTimestamp         *PTPTimestamp `json:"origin_timestamp,omitempty"`
	PreciseOriginTimestamp  *PTPTimestamp `json:"precise_origin_timestamp,omitempty"`
	ReceiveTimestamp        *PTPTimestamp `json:"receive_timestamp,omitempty"`
	RequestReceiptTimestamp *PTPTimestamp `json:"request_receipt_timestamp,omitempty"`
	ResponseOriginTimestamp *PTPTimestamp `json:"response_origin_timestamp,omitempty"`
	RequestingPortIdentity  *PortIdentity `json:"requesting_port_identity,omitempty"`
	TargetPortIdentity      *PortIdentity `json:"target_port_identity,omitempty"`

	// Announce
	AnnounceBody *AnnounceBody `json:"announce_body,omitempty"`

	// Trailing TLV bytes (not decoded; surfaced as hex for
	// post-processing or future per-TLV walkers).
	TLVSuffixHex string `json:"tlv_suffix_hex,omitempty"`
}

// PTPTimestamp is the 10-byte PTP-timestamp (6-byte secondsField
// + 4-byte nanosecondsField).
type PTPTimestamp struct {
	Seconds     uint64 `json:"seconds"`
	Nanoseconds uint32 `json:"nanoseconds"`
}

// PortIdentity is the 10-byte clockIdentity + portNumber pair.
type PortIdentity struct {
	ClockIdentity string `json:"clock_identity"`
	PortNumber    int    `json:"port_number"`
}

// AnnounceBody carries the Best Master Clock Algorithm inputs.
type AnnounceBody struct {
	OriginTimestamp               PTPTimestamp `json:"origin_timestamp"`
	CurrentUtcOffsetSeconds       int16        `json:"current_utc_offset_seconds"`
	GrandmasterPriority1          int          `json:"grandmaster_priority1"`
	GrandmasterClockClass         int          `json:"grandmaster_clock_class"`
	GrandmasterClockAccuracy      int          `json:"grandmaster_clock_accuracy"`
	GrandmasterClockAccuracyName  string       `json:"grandmaster_clock_accuracy_name"`
	GrandmasterOffsetScaledLogVar int          `json:"grandmaster_offset_scaled_log_variance"`
	GrandmasterPriority2          int          `json:"grandmaster_priority2"`
	GrandmasterIdentity           string       `json:"grandmaster_identity"`
	StepsRemoved                  int          `json:"steps_removed"`
	TimeSource                    int          `json:"time_source"`
	TimeSourceName                string       `json:"time_source_name"`
}

// Decode parses a PTPv2 packet from a hex string. Separators
// (':' '-' '_' whitespace) are tolerated; a leading '0x' prefix
// is stripped.
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
	if len(b) < 34 {
		return nil, fmt.Errorf("PTPv2 packet truncated (%d bytes; need ≥34 for common header)",
			len(b))
	}

	r := &Result{
		TotalBytes:         len(b),
		TransportSpecific:  int(b[0] >> 4),
		MessageType:        int(b[0] & 0x0F),
		VersionPTP:         int(b[1] & 0x0F),
		MessageLength:      int(binary.BigEndian.Uint16(b[2:4])),
		DomainNumber:       int(b[4]),
		FlagFieldHex:       fmt.Sprintf("0x%04X", binary.BigEndian.Uint16(b[6:8])),
		CorrectionField:    int64(binary.BigEndian.Uint64(b[8:16])),
		ClockIdentity:      formatClockIdentity(b[20:28]),
		PortNumber:         int(binary.BigEndian.Uint16(b[28:30])),
		SequenceID:         int(binary.BigEndian.Uint16(b[30:32])),
		ControlField:       int(b[32]),
		LogMessageInterval: int(int8(b[33])),
	}
	r.MessageTypeName = messageTypeName(r.MessageType)
	r.FlagsDecoded = decodeFlags(binary.BigEndian.Uint16(b[6:8]), r.MessageType)

	off := 34
	switch r.MessageType {
	case 0x0:
		// Sync — 10-byte originTimestamp.
		ts := readTimestamp(b, off)
		if ts != nil {
			r.OriginTimestamp = ts
			off += 10
		}
	case 0x1:
		// Delay_Req — 10-byte originTimestamp.
		ts := readTimestamp(b, off)
		if ts != nil {
			r.OriginTimestamp = ts
			off += 10
		}
	case 0x2:
		// Pdelay_Req — 10-byte originTimestamp + 10-byte reserved.
		ts := readTimestamp(b, off)
		if ts != nil {
			r.OriginTimestamp = ts
			off += 20
		}
	case 0x3:
		// Pdelay_Resp — 10-byte requestReceiptTimestamp + 10-byte
		// requestingPortIdentity.
		ts := readTimestamp(b, off)
		if ts != nil {
			r.RequestReceiptTimestamp = ts
			off += 10
		}
		pi := readPortIdentity(b, off)
		if pi != nil {
			r.RequestingPortIdentity = pi
			off += 10
		}
	case 0x8:
		// Follow_Up — 10-byte preciseOriginTimestamp.
		ts := readTimestamp(b, off)
		if ts != nil {
			r.PreciseOriginTimestamp = ts
			off += 10
		}
	case 0x9:
		// Delay_Resp — 10-byte receiveTimestamp + 10-byte
		// requestingPortIdentity.
		ts := readTimestamp(b, off)
		if ts != nil {
			r.ReceiveTimestamp = ts
			off += 10
		}
		pi := readPortIdentity(b, off)
		if pi != nil {
			r.RequestingPortIdentity = pi
			off += 10
		}
	case 0xA:
		// Pdelay_Resp_Follow_Up — 10-byte responseOriginTimestamp +
		// 10-byte requestingPortIdentity.
		ts := readTimestamp(b, off)
		if ts != nil {
			r.ResponseOriginTimestamp = ts
			off += 10
		}
		pi := readPortIdentity(b, off)
		if pi != nil {
			r.RequestingPortIdentity = pi
			off += 10
		}
	case 0xB:
		// Announce body — 30 bytes.
		ab := readAnnounce(b, off)
		if ab != nil {
			r.AnnounceBody = ab
			off += 30
		}
	case 0xC, 0xD:
		// Signaling / Management — 10-byte targetPortIdentity then
		// TLVs (decoded as raw hex via tlv_suffix).
		pi := readPortIdentity(b, off)
		if pi != nil {
			r.TargetPortIdentity = pi
			off += 10
		}
	}

	if off < len(b) {
		r.TLVSuffixHex = strings.ToUpper(hex.EncodeToString(b[off:]))
	}
	return r, nil
}

func readTimestamp(b []byte, off int) *PTPTimestamp {
	if off+10 > len(b) {
		return nil
	}
	sec := (uint64(b[off]) << 40) | (uint64(b[off+1]) << 32) |
		(uint64(b[off+2]) << 24) | (uint64(b[off+3]) << 16) |
		(uint64(b[off+4]) << 8) | uint64(b[off+5])
	ns := binary.BigEndian.Uint32(b[off+6 : off+10])
	return &PTPTimestamp{Seconds: sec, Nanoseconds: ns}
}

func readPortIdentity(b []byte, off int) *PortIdentity {
	if off+10 > len(b) {
		return nil
	}
	return &PortIdentity{
		ClockIdentity: formatClockIdentity(b[off : off+8]),
		PortNumber:    int(binary.BigEndian.Uint16(b[off+8 : off+10])),
	}
}

func readAnnounce(b []byte, off int) *AnnounceBody {
	if off+30 > len(b) {
		return nil
	}
	ts := readTimestamp(b, off)
	if ts == nil {
		return nil
	}
	ab := &AnnounceBody{
		OriginTimestamp:               *ts,
		CurrentUtcOffsetSeconds:       int16(binary.BigEndian.Uint16(b[off+10 : off+12])),
		GrandmasterPriority1:          int(b[off+13]),
		GrandmasterClockClass:         int(b[off+14]),
		GrandmasterClockAccuracy:      int(b[off+15]),
		GrandmasterOffsetScaledLogVar: int(binary.BigEndian.Uint16(b[off+16 : off+18])),
		GrandmasterPriority2:          int(b[off+18]),
		GrandmasterIdentity:           formatClockIdentity(b[off+19 : off+27]),
		StepsRemoved:                  int(binary.BigEndian.Uint16(b[off+27 : off+29])),
		TimeSource:                    int(b[off+29]),
	}
	ab.GrandmasterClockAccuracyName = clockAccuracyName(ab.GrandmasterClockAccuracy)
	ab.TimeSourceName = timeSourceName(ab.TimeSource)
	return ab
}

func formatClockIdentity(b []byte) string {
	if len(b) != 8 {
		return ""
	}
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
		b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7])
}

func messageTypeName(t int) string {
	switch t {
	case 0x0:
		return "Sync"
	case 0x1:
		return "Delay_Req"
	case 0x2:
		return "Pdelay_Req"
	case 0x3:
		return "Pdelay_Resp"
	case 0x8:
		return "Follow_Up"
	case 0x9:
		return "Delay_Resp"
	case 0xA:
		return "Pdelay_Resp_Follow_Up"
	case 0xB:
		return "Announce"
	case 0xC:
		return "Signaling"
	case 0xD:
		return "Management"
	}
	return fmt.Sprintf("uncatalogued type 0x%X", t)
}

func timeSourceName(t int) string {
	switch t {
	case 0x10:
		return "ATOMIC_CLOCK"
	case 0x20:
		return "GPS"
	case 0x30:
		return "TERRESTRIAL_RADIO"
	case 0x40:
		return "PTP"
	case 0x50:
		return "NTP"
	case 0x60:
		return "HAND_SET"
	case 0x90:
		return "OTHER"
	case 0xA0:
		return "INTERNAL_OSCILLATOR"
	}
	return fmt.Sprintf("uncatalogued time source 0x%X", t)
}

func clockAccuracyName(a int) string {
	switch a {
	case 0x20:
		return "within 25 ns"
	case 0x21:
		return "within 100 ns"
	case 0x22:
		return "within 250 ns"
	case 0x23:
		return "within 1 µs"
	case 0x24:
		return "within 2.5 µs"
	case 0x25:
		return "within 10 µs"
	case 0x26:
		return "within 25 µs"
	case 0x27:
		return "within 100 µs"
	case 0x28:
		return "within 250 µs"
	case 0x29:
		return "within 1 ms"
	case 0x2A:
		return "within 2.5 ms"
	case 0x2B:
		return "within 10 ms"
	case 0x2C:
		return "within 25 ms"
	case 0x2D:
		return "within 100 ms"
	case 0x2E:
		return "within 250 ms"
	case 0x2F:
		return "within 1 s"
	case 0x30:
		return "within 10 s"
	case 0x31:
		return "greater than 10 s"
	case 0xFE:
		return "UNKNOWN"
	}
	return fmt.Sprintf("uncatalogued accuracy 0x%X", a)
}

// decodeFlags walks the per-message flagField bits per IEEE
// 1588-2008 §13.3.2.6. The 2-byte flagField is read as BE uint16,
// so octet 0 (messageType-specific) lives in the high byte and
// octet 1 (Announce timeProperties) lives in the low byte.
func decodeFlags(f uint16, msgType int) string {
	var names []string
	// Octet 0 — messageType-specific (high byte of uint16).
	if f&0x0100 != 0 {
		names = append(names, "alternateMaster")
	}
	if f&0x0200 != 0 {
		names = append(names, "twoStep")
	}
	if f&0x0400 != 0 {
		names = append(names, "unicast")
	}
	if f&0x2000 != 0 {
		names = append(names, "PTP_profile_specific_1")
	}
	if f&0x4000 != 0 {
		names = append(names, "PTP_profile_specific_2")
	}
	// Octet 1 — Announce-only timeProperties (low byte of uint16).
	if msgType == 0xB {
		if f&0x0001 != 0 {
			names = append(names, "leap61")
		}
		if f&0x0002 != 0 {
			names = append(names, "leap59")
		}
		if f&0x0004 != 0 {
			names = append(names, "currentUtcOffsetValid")
		}
		if f&0x0008 != 0 {
			names = append(names, "ptpTimescale")
		}
		if f&0x0010 != 0 {
			names = append(names, "timeTraceable")
		}
		if f&0x0020 != 0 {
			names = append(names, "frequencyTraceable")
		}
	}
	return strings.Join(names, ",")
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
