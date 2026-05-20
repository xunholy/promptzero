// Package goose decodes IEC 61850-8-1 GOOSE (Generic Object
// Oriented Substation Events) messages — the time-critical
// multicast Ethernet protocol that carries protective-relay
// signals between Intelligent Electronic Devices (IEDs) inside
// modern digital substations.
//
// GOOSE is the latency-bounded sibling of MMS (the IEC 61850
// SCADA application layer) and Sampled Values (the
// instantaneous-current/voltage multicast from merging units).
// When a protective relay detects a fault and decides to trip a
// breaker, the trip signal travels as a GOOSE message — and the
// IEC 61850-5 performance requirements demand it reach the trip
// coil within **4 ms** end-to-end (Type 1A "Trip" performance
// class). To make that latency budget realistic, GOOSE rides
// **directly over Ethernet** (EtherType 0x88B8) — no IP, no UDP,
// no TCP — and uses **multicast** so a single sender reaches
// every interested IED on the substation LAN simultaneously.
//
// Operationally, GOOSE carries:
//
//   - **Trip / Block signals** from protection IEDs (line distance,
//     bus differential, transformer differential) to circuit-
//     breaker controllers.
//   - **Interlocking** between IEDs supervising adjacent bays
//     (busbar isolators, transfer switches, earthing switches).
//   - **Synchronisation status + position indications** from
//     bay-control IEDs to the station HMI.
//   - **Test-mode + maintenance signals** during commissioning.
//
// Each GOOSE message carries a **stNum** (state number; increments
// on every state change) and **sqNum** (sequence number;
// increments on each retransmission while state is stable).
// Receivers detect data loss by watching stNum / sqNum and tag
// messages stale once the **timeAllowedToLive** budget expires.
//
// Wrap-vs-native judgement
//
//	Native. IEC 61850-8-1 is publicly available; the GOOSE wire
//	format is a tight 8-byte fixed header (APPID + Length +
//	Reserved1 + Reserved2) followed by an ASN.1 BER-encoded
//	IECGoosePdu. The PDU schema is fully specified — a
//	deterministic walker with implicit context-class tags 0x80
//	through 0x8B. No crypto at the parse layer (IEC 62351-6
//	signs GOOSE with HMAC-SHA256 in a trailing field; that
//	signature appears AFTER the PDU and is surfaced as raw
//	`security_trailer_hex` for future per-signature decoders).
//
// What this package covers
//
//   - **GOOSE header** (IEC 61850-8-1 §A.3, 8 bytes, big-endian;
//     transmitted IMMEDIATELY after the 0x88B8 EtherType):
//
//   - bytes 0-1: **APPID** (uint16 BE; identifies the GOOSE
//     control block; convention is 0x0000-0x3FFF for GOOSE,
//     0x4000-0x7FFF for Sampled Values).
//
//   - bytes 2-3: **Length** (uint16 BE; total bytes from
//     APPID through end of APDU — INCLUDING the 8-byte
//     header itself).
//
//   - bytes 4-5: Reserved1 (= 0x0000).
//
//   - bytes 6-7: Reserved2 (= 0x0000; IEC 62351-6
//     re-purposes these bytes for a security tag).
//
//   - **IECGoosePdu** (ASN.1 BER-encoded; tag 0x61 = IMPLICIT
//     [APPLICATION 1] CONSTRUCTED — IEC 61850-8-1 §A.2):
//
//   - byte 0: 0x61 outer tag.
//
//   - bytes 1+: BER length (short form for ≤127 bytes; long
//     form for ≥128 bytes).
//
//   - Inside the PDU, a sequence of context-class IMPLICIT
//     fields (uniformly tagged 0x80 + N):
//
//   - [0] `gocbRef` IMPLICIT VISIBLE-STRING (tag 0x80)
//     — "<IED-name>/<LD>$GO$<GoCB-name>" reference.
//
//   - [1] `timeAllowedToLive` IMPLICIT INTEGER
//     (tag 0x81; milliseconds — receivers must mark
//     stale after this elapses without a fresh
//     message).
//
//   - [2] `datSet` IMPLICIT VISIBLE-STRING (tag 0x82)
//     — "<IED-name>/<LD>$<DataSet-name>" reference.
//
//   - [3] `goID` IMPLICIT VISIBLE-STRING (tag 0x83;
//     optional human-readable label).
//
//   - [4] `t` IMPLICIT UtcTime (tag 0x84; 8 bytes —
//     4-byte secondsSinceEpoch + 3-byte fractionOfSecond
//
//   - 1-byte timeQuality).
//
//   - [5] `stNum` IMPLICIT INTEGER (tag 0x85).
//
//   - [6] `sqNum` IMPLICIT INTEGER (tag 0x86).
//
//   - [7] `test` IMPLICIT BOOLEAN (tag 0x87).
//
//   - [8] `confRev` IMPLICIT INTEGER (tag 0x88;
//     configuration revision counter).
//
//   - [9] `ndsCom` IMPLICIT BOOLEAN (tag 0x89; "Needs
//     Commissioning").
//
//   - [10] `numDatSetEntries` IMPLICIT INTEGER (tag
//     0x8A).
//
//   - [11] `allData` IMPLICIT SEQUENCE OF Data (tag
//     0xAB; constructed). The per-entry Data choice is
//     dataset-specific and surfaced as raw
//     `all_data_hex`.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **L2 framing** — feed GOOSE bytes after the 14-byte
//     Ethernet header (destination MAC, source MAC, EtherType
//     0x88B8). Standard GOOSE destination is multicast group
//     01:0C:CD:01:00:00 / range 01:0C:CD:01:00:00 -
//     01:0C:CD:01:01:FF. VLAN tagging (IEEE 802.1Q PCP=4
//     priority + VID) is common but is part of the L2 frame
//     and not parsed here.
//   - **Per-entry Data decoder** — the `allData` field carries a
//     sequence of Data choices (Boolean, BitString, Integer,
//     UnsignedInteger, FloatingPoint, OctetString, VisibleString,
//     BinaryTime, UtcTime, BCD, BooleanArray, MMSString,
//     Structure). The per-IED dataset schema is loaded from
//     SCL (SubstationConfigurationLanguage) files at
//     engineering time; this decoder surfaces `all_data_hex`
//     for downstream per-DataSet walkers.
//   - **IEC 62351-6 security** — the trailing HMAC-SHA256
//     signature + key-management metadata appear AFTER the
//     IECGoosePdu in the Length-bounded region; surfaced as
//     `security_trailer_hex`. Verification requires the per-
//     IED shared key.
//   - **Replay / sequence-number reasoning** — the decoder
//     surfaces stNum / sqNum / timeAllowedToLive but does not
//     itself enforce freshness or detect replay (per-flow
//     state is a higher-level concern).
//   - **Sampled Values (SMV)** — IEC 61850-9-2 SMV uses a
//     similar Ethernet header (EtherType 0x88BA) with a
//     different PDU shape; out of scope here.
package goose

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the structured decode of a GOOSE message.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// GOOSE header
	APPID     int `json:"appid"`
	Length    int `json:"length"`
	Reserved1 int `json:"reserved1"`
	Reserved2 int `json:"reserved2"`

	// IECGoosePdu fields (in BER tag order)
	GOCBRef             string   `json:"gocb_ref,omitempty"`
	TimeAllowedToLiveMS int64    `json:"time_allowed_to_live_ms,omitempty"`
	DatSet              string   `json:"dat_set,omitempty"`
	GoID                string   `json:"go_id,omitempty"`
	UtcTime             *UtcTime `json:"utc_time,omitempty"`
	StNum               int64    `json:"st_num"`
	SqNum               int64    `json:"sq_num"`
	Test                bool     `json:"test"`
	ConfRev             int64    `json:"conf_rev,omitempty"`
	NdsCom              bool     `json:"nds_com,omitempty"`
	NumDatSetEntries    int64    `json:"num_dat_set_entries,omitempty"`
	AllDataHex          string   `json:"all_data_hex,omitempty"`

	// Trailing IEC 62351-6 security bytes (if any).
	SecurityTrailerHex string `json:"security_trailer_hex,omitempty"`
}

// UtcTime is the 8-byte IEC 61850 UtcTime breakdown.
type UtcTime struct {
	SecondsSinceEpoch uint32 `json:"seconds_since_epoch"`
	FractionOfSecond  uint32 `json:"fraction_of_second"`
	TimeQualityHex    string `json:"time_quality_hex"`
}

// Decode parses an IEC 61850 GOOSE message from a hex string
// starting at the APPID (i.e. AFTER the 14-byte Ethernet header
// + 0x88B8 EtherType). Separators (':' '-' '_' whitespace) are
// tolerated; a leading '0x' prefix is stripped.
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
	if len(b) < 10 {
		return nil, fmt.Errorf("GOOSE message truncated (%d bytes; need ≥10 for header + outer tag)",
			len(b))
	}

	r := &Result{
		TotalBytes: len(b),
		APPID:      int(binary.BigEndian.Uint16(b[0:2])),
		Length:     int(binary.BigEndian.Uint16(b[2:4])),
		Reserved1:  int(binary.BigEndian.Uint16(b[4:6])),
		Reserved2:  int(binary.BigEndian.Uint16(b[6:8])),
	}

	// PDU starts at byte 8. Outer tag = 0x61.
	if b[8] != 0x61 {
		return r, fmt.Errorf("missing IECGoosePdu outer tag 0x61 (got 0x%02X)", b[8])
	}
	pduLen, lenSize, err := readBERLength(b[9:])
	if err != nil {
		return r, fmt.Errorf("outer PDU length: %w", err)
	}
	pduStart := 9 + lenSize
	pduEnd := pduStart + pduLen
	if pduEnd > len(b) {
		return r, fmt.Errorf("PDU truncated (claims %d bytes, have %d)",
			pduLen, len(b)-pduStart)
	}
	if pduEnd < len(b) {
		r.SecurityTrailerHex = strings.ToUpper(hex.EncodeToString(b[pduEnd:]))
	}

	// Walk PDU body.
	off := pduStart
	for off < pduEnd {
		if off+2 > pduEnd {
			break
		}
		tag := b[off]
		valLen, lSize, err := readBERLength(b[off+1 : pduEnd])
		if err != nil {
			return r, fmt.Errorf("field tag 0x%02X length: %w", tag, err)
		}
		valStart := off + 1 + lSize
		valEnd := valStart + valLen
		if valEnd > pduEnd {
			return r, fmt.Errorf("field tag 0x%02X overruns PDU", tag)
		}
		val := b[valStart:valEnd]
		switch tag {
		case 0x80: // gocbRef VISIBLE-STRING
			r.GOCBRef = string(val)
		case 0x81: // timeAllowedToLive INTEGER
			r.TimeAllowedToLiveMS = readBERInteger(val)
		case 0x82: // datSet VISIBLE-STRING
			r.DatSet = string(val)
		case 0x83: // goID VISIBLE-STRING
			r.GoID = string(val)
		case 0x84: // t UtcTime (8 bytes)
			r.UtcTime = readUtcTime(val)
		case 0x85: // stNum INTEGER
			r.StNum = readBERInteger(val)
		case 0x86: // sqNum INTEGER
			r.SqNum = readBERInteger(val)
		case 0x87: // test BOOLEAN
			if len(val) >= 1 && val[0] != 0 {
				r.Test = true
			}
		case 0x88: // confRev INTEGER
			r.ConfRev = readBERInteger(val)
		case 0x89: // ndsCom BOOLEAN
			if len(val) >= 1 && val[0] != 0 {
				r.NdsCom = true
			}
		case 0x8A: // numDatSetEntries INTEGER
			r.NumDatSetEntries = readBERInteger(val)
		case 0xAB: // allData SEQUENCE OF Data (constructed)
			r.AllDataHex = strings.ToUpper(hex.EncodeToString(val))
		}
		off = valEnd
	}
	return r, nil
}

// readBERLength reads an ASN.1 BER length field, returning the
// decoded length value and the number of bytes consumed.
func readBERLength(b []byte) (int, int, error) {
	if len(b) == 0 {
		return 0, 0, fmt.Errorf("empty length field")
	}
	first := b[0]
	if first < 0x80 {
		return int(first), 1, nil
	}
	n := int(first & 0x7F)
	if n == 0 || n > 4 {
		return 0, 0, fmt.Errorf("unsupported long-form length (%d octets)", n)
	}
	if 1+n > len(b) {
		return 0, 0, fmt.Errorf("long-form length truncated")
	}
	v := 0
	for i := 0; i < n; i++ {
		v = (v << 8) | int(b[1+i])
	}
	return v, 1 + n, nil
}

// readBERInteger reads an ASN.1 BER INTEGER as a signed int64.
func readBERInteger(b []byte) int64 {
	if len(b) == 0 {
		return 0
	}
	var v int64
	if b[0]&0x80 != 0 {
		v = -1
	}
	for _, c := range b {
		v = (v << 8) | int64(c)
	}
	return v
}

func readUtcTime(b []byte) *UtcTime {
	if len(b) != 8 {
		return nil
	}
	return &UtcTime{
		SecondsSinceEpoch: binary.BigEndian.Uint32(b[0:4]),
		// Fraction of second is 24-bit BE, padded to uint32.
		FractionOfSecond: (uint32(b[4]) << 16) |
			(uint32(b[5]) << 8) | uint32(b[6]),
		TimeQualityHex: fmt.Sprintf("0x%02X", b[7]),
	}
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
