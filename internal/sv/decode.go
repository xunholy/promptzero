// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sv decodes IEC 61850-9-2 (and 9-2LE) Sampled Values (SV / SMV) —
// the substation-automation multicast that streams digitised current and
// voltage samples from a merging unit (the device that samples the
// instrument transformers on the primary plant) to the protection and
// measurement IEDs. SV rides directly over Ethernet (EtherType 0x88BA, no IP
// / no UDP) at a high, fixed sample rate (4000 or 4800 Hz for 50/60 Hz
// protection). It is the sampled-measurement sibling of GOOSE (internal/goose,
// EtherType 0x88B8) and a real substation-security target: SV is
// unauthenticated by default, so an attacker on the process bus who can
// inject forged SV frames — replaying an old sample block or spoofing the
// sample counter — can feed protection relays false current/voltage,
// triggering or blocking a trip (the SV-injection attack class). A captured
// SV frame identifies the **stream** (svID — the merging unit), the **sample
// counter** (smpCnt — the per-sample sequence number that replay/spoof
// attacks manipulate), the configuration revision, the **synchronisation
// source** (smpSynch — whether the samples are GPS-disciplined) and surfaces
// the raw sampled-value block, which is the recon headline for process-bus
// reconnaissance.
//
// # Wrap-vs-native judgement
//
//	Native. SV is the same shape as GOOSE: an 8-byte APPID / length /
//	reserved header followed by an ASN.1 BER-encoded savPdu (outer tag 0x60)
//	whose seqASDU (tag 0xA2) holds one or more ASDUs (each a 0x30 SEQUENCE of
//	IMPLICIT context-tagged fields). A deterministic BER tag/length/value
//	walk, reusing the same approach as internal/goose; stdlib only, no new
//	go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The savPdu / ASDU tag layout follows the authoritative IEC 61850-9-2
//	ASN.1 (and matches Wireshark's sv dissector) — there is no scapy model
//	for SV (nor for GOOSE), so verification is by the deterministic,
//	byte-checkable BER walk against spec-built vectors. Only the standardised
//	envelope is decoded: svID, smpCnt, confRev, smpSynch, datSet, refrTm,
//	smpRate, smpMod; the **sampled-value data block itself (the `sample`
//	OCTET STRING) is dataset-configuration-dependent and is surfaced as raw
//	hex** (decoding individual channel values would be confidently-wrong
//	without the dataset definition), exactly as GOOSE surfaces allData. The
//	security field (IEC 62351) is surfaced raw. A missing 0x60 outer tag or a
//	truncated TLV is reported, not guessed.
package sv

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the structured decode of an IEC 61850-9-2 Sampled Values message.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// SV header (after the 0x88BA EtherType).
	APPID     int `json:"appid"`
	Length    int `json:"length"`
	Reserved1 int `json:"reserved1"`
	Reserved2 int `json:"reserved2"`

	NoASDU      int    `json:"no_asdu"`
	SecurityHex string `json:"security_hex,omitempty"`
	ASDUs       []ASDU `json:"asdus,omitempty"`

	Notes []string `json:"notes,omitempty"`
}

// ASDU is one Application-Specific Data Unit within the savPdu's seqASDU.
type ASDU struct {
	SvID         string `json:"sv_id,omitempty"`
	DatSet       string `json:"dat_set,omitempty"`
	SmpCnt       int    `json:"smp_cnt"`
	ConfRev      int64  `json:"conf_rev,omitempty"`
	RefrTimeHex  string `json:"refr_time_hex,omitempty"`
	SmpSynch     int    `json:"smp_synch"`
	SmpSynchName string `json:"smp_synch_name,omitempty"`
	SmpRate      int    `json:"smp_rate,omitempty"`
	SampleHex    string `json:"sample_hex,omitempty"`
	SmpMod       int    `json:"smp_mod,omitempty"`
}

// Decode parses an IEC 61850-9-2 Sampled Values message from a hex string
// starting at the APPID (i.e. AFTER the Ethernet header + 0x88BA EtherType).
// Separators (':' '-' '_' whitespace) and a leading '0x' are tolerated.
func Decode(hexStr string) (*Result, error) {
	b, err := normaliseHex(hexStr)
	if err != nil {
		return nil, err
	}
	if len(b) < 10 {
		return nil, fmt.Errorf("sv: message truncated (%d bytes; need ≥10 for the header + outer tag)", len(b))
	}
	r := &Result{
		TotalBytes: len(b),
		APPID:      int(binary.BigEndian.Uint16(b[0:2])),
		Length:     int(binary.BigEndian.Uint16(b[2:4])),
		Reserved1:  int(binary.BigEndian.Uint16(b[4:6])),
		Reserved2:  int(binary.BigEndian.Uint16(b[6:8])),
	}
	// savPdu starts at byte 8; outer tag = 0x60 ([APPLICATION 0] IMPLICIT).
	if b[8] != 0x60 {
		return r, fmt.Errorf("sv: missing savPdu outer tag 0x60 (got 0x%02X)", b[8])
	}
	pduLen, lenSize, err := readBERLength(b[9:])
	if err != nil {
		return r, fmt.Errorf("sv: outer savPdu length: %w", err)
	}
	pduStart := 9 + lenSize
	pduEnd := pduStart + pduLen
	if pduEnd > len(b) {
		return r, fmt.Errorf("sv: savPdu truncated (claims %d bytes, have %d)", pduLen, len(b)-pduStart)
	}

	off := pduStart
	for off < pduEnd {
		if off+2 > pduEnd {
			break
		}
		tag := b[off]
		valLen, lSize, err := readBERLength(b[off+1 : pduEnd])
		if err != nil {
			return r, fmt.Errorf("sv: field tag 0x%02X length: %w", tag, err)
		}
		valStart := off + 1 + lSize
		valEnd := valStart + valLen
		if valEnd > pduEnd {
			return r, fmt.Errorf("sv: field tag 0x%02X overruns savPdu", tag)
		}
		val := b[valStart:valEnd]
		switch tag {
		case 0x80: // noASDU INTEGER
			r.NoASDU = int(readBERInteger(val))
		case 0x81: // security ANY (IEC 62351) — surfaced raw
			r.SecurityHex = strings.ToUpper(hex.EncodeToString(val))
		case 0xA2: // seqASDU SEQUENCE OF ASDU (constructed)
			asdus, err := walkASDUs(val)
			if err != nil {
				return r, err
			}
			r.ASDUs = asdus
		}
		off = valEnd
	}

	r.Notes = append(r.Notes, "IEC 61850-9-2 Sampled Values (process-bus, EtherType 0x88BA) — svID identifies the merging-unit stream; smpCnt is the per-sample counter that SV-injection / replay attacks manipulate; the sampled-value block is surfaced raw (dataset-dependent)")
	return r, nil
}

// walkASDUs walks the seqASDU body: a concatenation of ASDU SEQUENCEs (0x30).
func walkASDUs(b []byte) ([]ASDU, error) {
	var out []ASDU
	off := 0
	for off < len(b) {
		if off+2 > len(b) {
			break
		}
		if b[off] != 0x30 { // ASDU is a universal SEQUENCE
			return out, fmt.Errorf("sv: expected ASDU SEQUENCE tag 0x30, got 0x%02X", b[off])
		}
		alen, lsize, err := readBERLength(b[off+1:])
		if err != nil {
			return out, fmt.Errorf("sv: ASDU length: %w", err)
		}
		start := off + 1 + lsize
		end := start + alen
		if end > len(b) {
			return out, fmt.Errorf("sv: ASDU overruns seqASDU")
		}
		a, err := parseASDU(b[start:end])
		if err != nil {
			return out, err
		}
		out = append(out, a)
		off = end
	}
	return out, nil
}

// parseASDU walks one ASDU's IMPLICIT context-tagged fields.
func parseASDU(b []byte) (ASDU, error) {
	var a ASDU
	off := 0
	for off < len(b) {
		if off+2 > len(b) {
			break
		}
		tag := b[off]
		vlen, lsize, err := readBERLength(b[off+1:])
		if err != nil {
			return a, fmt.Errorf("sv: ASDU field tag 0x%02X length: %w", tag, err)
		}
		vs := off + 1 + lsize
		ve := vs + vlen
		if ve > len(b) {
			return a, fmt.Errorf("sv: ASDU field tag 0x%02X overruns", tag)
		}
		val := b[vs:ve]
		switch tag {
		case 0x80: // svID VisibleString
			a.SvID = string(val)
		case 0x81: // datSet VisibleString (optional)
			a.DatSet = string(val)
		case 0x82: // smpCnt OCTET STRING (2)
			a.SmpCnt = int(readBERUint(val))
		case 0x83: // confRev INTEGER
			a.ConfRev = readBERInteger(val)
		case 0x84: // refrTm OCTET STRING (8, optional)
			a.RefrTimeHex = strings.ToUpper(hex.EncodeToString(val))
		case 0x85: // smpSynch INTEGER / ENUMERATED
			a.SmpSynch = int(readBERInteger(val))
			a.SmpSynchName = smpSynchName(a.SmpSynch)
		case 0x86: // smpRate OCTET STRING (2, optional)
			a.SmpRate = int(readBERUint(val))
		case 0x87: // sample (the sampled-value data block) — surfaced raw
			a.SampleHex = strings.ToUpper(hex.EncodeToString(val))
		case 0x88: // smpMod OCTET STRING (2, optional)
			a.SmpMod = int(readBERUint(val))
		}
		off = ve
	}
	return a, nil
}

// smpSynchName maps the smpSynch value (IEC 61850-9-2LE) to the clock source.
func smpSynchName(v int) string {
	switch v {
	case 0:
		return "None (not synchronised)"
	case 1:
		return "Local (local-area clock)"
	case 2:
		return "Global (global / GPS-disciplined clock)"
	}
	return ""
}

// readBERLength reads an ASN.1 BER length, returning the value + bytes consumed.
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

// readBERUint reads a big-endian unsigned integer (smpCnt / smpRate / smpMod
// are OCTET STRINGs holding an unsigned value).
func readBERUint(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = (v << 8) | uint64(c)
	}
	return v
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("sv: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("sv: input is not valid hex: %w", err)
	}
	return b, nil
}
