// SPDX-License-Identifier: AGPL-3.0-or-later

// Package esmc decodes the ESMC — Ethernet Synchronization Messaging Channel
// (ITU-T G.8264) — the control channel of Synchronous Ethernet (SyncE). SyncE
// distributes a physical-layer frequency reference across an Ethernet network
// (the way SDH/SONET did over TDM); ESMC is the small Slow-Protocol frame
// (EtherType 0x8809, subtype 0x0A) that advertises the Synchronization Status
// Message (SSM) — the Quality Level (QL) of the clock each node is traceable
// to. It is the frequency-sync companion to PTP / IEEE 1588 (internal/ptpv2,
// phase/time sync): together they carry the timing plane that 5G fronthaul,
// power-grid teleprotection and broadcast networks depend on. Timing is an
// emerging attack surface — degrading or spoofing the advertised QL can push
// a network onto a worse clock or trigger a sync-loss reconfiguration — so a
// captured ESMC frame reveals the timing hierarchy: the advertised clock
// **Quality Level** (PRC / SSU / EEC / DNU), whether the frame is a periodic
// **information** heartbeat or an **event** (a QL change), and, in the
// enhanced TLV, the source clock identity. This is the recon headline for
// timing-network reconnaissance.
//
// # Wrap-vs-native judgement
//
//	Native. ESMC is a fixed 10-byte Slow-Protocol/ESMC header (subtype + ITU
//	OUI + ITU subtype + version/event flags + reserved) followed by a short
//	TLV stream (the QL TLV is type + 2-byte length + a 1-byte SSM code). A
//	byte/bit read + a TLV walk; stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The header layout and the QL / Enhanced-QL TLVs were verified
//	field-for-field against scapy's ESMC layer (scapy.contrib.esmc). The one
//	genuine ambiguity is the SSM-code → Quality-Level name: ITU-T G.781
//	defines three option tables (Option I = ETSI/SDH, Option II = ANSI/SONET,
//	Option III = TTC/Japan) that assign DIFFERENT names to the same 4-bit
//	code, and the in-use option is a deployment setting NOT carried on the
//	wire. To avoid a confidently-wrong single answer, the raw SSM code is
//	surfaced together with BOTH the Option-I and Option-II names. A non-ESMC
//	Slow-Protocol subtype is rejected; a malformed TLV stops the walk.
package esmc

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of an ESMC (SyncE) frame.
type Result struct {
	Subtype     int      `json:"subtype"`
	SubtypeName string   `json:"subtype_name"`
	ITUOUIHex   string   `json:"itu_oui_hex"`
	ITUSubtype  int      `json:"itu_subtype"`
	Version     int      `json:"version"`
	EventFlag   bool     `json:"event_flag"`
	MessageType string   `json:"message_type"`
	TLVs        []TLV    `json:"tlvs,omitempty"`
	Notes       []string `json:"notes,omitempty"`
}

// TLV is one entry in the ESMC TLV stream.
type TLV struct {
	Type     int    `json:"type"`
	TypeName string `json:"type_name"`
	Length   int    `json:"length"`

	// Quality Level TLV (type 1)
	SSMCodeHex           string `json:"ssm_code_hex,omitempty"`
	QualityLevel         int    `json:"quality_level,omitempty"`
	QualityLevelOptionI  string `json:"quality_level_option_i,omitempty"`
	QualityLevelOptionII string `json:"quality_level_option_ii,omitempty"`

	// Enhanced Quality Level TLV (type 2)
	EnhancedSSMCodeHex string `json:"enhanced_ssm_code_hex,omitempty"`
	ClockIdentity      string `json:"clock_identity,omitempty"`

	ValueHex string `json:"value_hex,omitempty"`
}

// Decode parses an ESMC frame (the Slow-Protocol payload, starting at the
// subtype byte — i.e. after the Ethernet header + EtherType 0x8809) from hex
// (whitespace / ':' / '-' / '_' separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 10 {
		return nil, fmt.Errorf("esmc: %d bytes — too short for the 10-byte ESMC header", len(b))
	}
	if b[0] != 0x0A {
		return nil, fmt.Errorf("esmc: Slow-Protocol subtype 0x%02X is not ESMC (0x0A)", b[0])
	}
	r := &Result{
		Subtype:     int(b[0]),
		SubtypeName: "ESMC (Ethernet Synchronization Messaging Channel)",
		ITUOUIHex:   strings.ToUpper(hex.EncodeToString(b[1:4])),
		ITUSubtype:  int(binary.BigEndian.Uint16(b[4:6])),
		Version:     int(b[6] >> 4),
		EventFlag:   b[6]&0x08 != 0,
	}
	if r.EventFlag {
		r.MessageType = "event (QL change — sent immediately)"
	} else {
		r.MessageType = "information (periodic heartbeat, 1/s)"
	}
	if r.ITUOUIHex != "0019A7" {
		r.Notes = append(r.Notes, fmt.Sprintf("ITU-T OUI is %s, expected 0019A7", r.ITUOUIHex))
	}
	r.TLVs = walkTLVs(b[10:])
	r.Notes = append(r.Notes, "ESMC / SyncE (ITU-T G.8264) — the frequency-sync control channel; the QL TLV advertises the clock Quality Level the node is traceable to. SSM-code → QL name is option-dependent (G.781 Option I = ETSI/SDH, Option II = ANSI/SONET), so both are surfaced")
	return r, nil
}

func walkTLVs(b []byte) []TLV {
	var out []TLV
	off := 0
	for off+3 <= len(b) {
		typ := int(b[off])
		length := int(binary.BigEndian.Uint16(b[off+1 : off+3]))
		// length counts the type (1) + length (2) + value; so value = length-3.
		if length < 3 || off+length > len(b) {
			// A type-0 padding TLV or end-of-data; stop the walk.
			break
		}
		val := b[off+3 : off+length]
		t := TLV{Type: typ, TypeName: tlvTypeName(typ), Length: length}
		switch typ {
		case 0x01: // Quality Level TLV
			if len(val) >= 1 {
				ql := int(val[0] & 0x0F)
				t.SSMCodeHex = fmt.Sprintf("0x%02X", val[0])
				t.QualityLevel = ql
				t.QualityLevelOptionI = qlOptionI(ql)
				t.QualityLevelOptionII = qlOptionII(ql)
			}
		case 0x02: // Enhanced Quality Level TLV
			if len(val) >= 1 {
				t.EnhancedSSMCodeHex = fmt.Sprintf("0x%02X", val[0])
			}
			if len(val) >= 9 {
				t.ClockIdentity = strings.ToUpper(hex.EncodeToString(val[1:9]))
			}
		default:
			if len(val) > 0 {
				t.ValueHex = strings.ToUpper(hex.EncodeToString(val))
			}
		}
		out = append(out, t)
		off += length
	}
	return out
}

func tlvTypeName(t int) string {
	switch t {
	case 0x01:
		return "Quality Level"
	case 0x02:
		return "Enhanced Quality Level"
	}
	return fmt.Sprintf("type %d", t)
}

// qlOptionI maps the SSM code to the ITU-T G.781 Option I (ETSI / SDH) QL name.
func qlOptionI(code int) string {
	switch code {
	case 0x0:
		return "QL-STU (sync traceability unknown)"
	case 0x2:
		return "QL-PRC (G.811 primary reference clock)"
	case 0x4:
		return "QL-SSU-A (G.812 transit)"
	case 0x8:
		return "QL-SSU-B (G.812 local)"
	case 0xB:
		return "QL-SEC / QL-EEC1 (G.813/G.8262 Ethernet equipment clock)"
	case 0xF:
		return "QL-DNU (do not use for synchronisation)"
	}
	return "reserved / unassigned (Option I)"
}

// qlOptionII maps the SSM code to the ITU-T G.781 Option II (ANSI / SONET) QL name.
func qlOptionII(code int) string {
	switch code {
	case 0x0:
		return "QL-STU (sync traceability unknown)"
	case 0x1:
		return "QL-PRS (Stratum 1 / PRS)"
	case 0x7:
		return "QL-ST2 (Stratum 2)"
	case 0xA:
		return "QL-TNC (transit node clock)"
	case 0xC:
		return "QL-ST3E"
	case 0xD:
		return "QL-ST3 / QL-EEC2 (Stratum 3)"
	case 0xE:
		return "QL-SMC (SONET minimum clock) / QL-PROV"
	case 0xF:
		return "QL-DUS (do not use for synchronisation)"
	}
	return "reserved / unassigned (Option II)"
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("esmc: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("esmc: input is not valid hex: %w", err)
	}
	return b, nil
}
