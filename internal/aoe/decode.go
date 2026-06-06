// SPDX-License-Identifier: AGPL-3.0-or-later

// Package aoe decodes ATA over Ethernet (AoE, EtherType 0x88A2) — the
// CORAID protocol that exposes raw ATA disk commands directly over an
// Ethernet segment. AoE has **no authentication and no IP layer**: any
// host on the same L2 segment can issue ATA READ / WRITE to an exposed
// AoE target (a major unauthenticated data-theft / data-destruction
// surface). A captured AoE frame is storage-reconnaissance: it reveals
// the target disk (shelf.slot), the ATA command (READ / WRITE / IDENTIFY),
// the 48-bit LBA and sector count being transferred, or — via the Query
// Config Information command — the target's config string and firmware.
// It joins the project's other L2 / capture decoders.
//
// # Wrap-vs-native judgement
//
//	Native. An AoE frame is a fixed 10-byte header (version/flags, error,
//	shelf, slot, command, tag) plus a command-specific body. A byte-field
//	read + a command switch; stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The structural fields — version, shelf (major), slot (minor), command,
//	tag, and the ATA command / sector count / 48-bit little-endian LBA,
//	plus the Query-Config fields — were verified field-for-field against
//	scapy's AoE layer (scapy.contrib.aoe). The header **Response / Error**
//	flags are decoded per the AoE spec (bit 3 = 0x08 Response, bit 2 =
//	0x04 Error, as Wireshark's dissector does): scapy's AoE layer maps
//	those flag bits incorrectly, so the spec is followed and the raw flag
//	nibble is also surfaced. The ATA aflags byte's bit meanings are not
//	authoritatively settled across implementations, so it is surfaced raw
//	rather than labelled — the read-vs-write intent is already unambiguous
//	from the ATA command byte.
package aoe

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// ATACommand is the decoded Issue-ATA-Command body.
type ATACommand struct {
	AFlagsHex   string `json:"aflags_hex"`
	ErrFeature  int    `json:"err_feature"`
	SectorCount int    `json:"sector_count"`
	ATACmd      int    `json:"ata_command"`
	ATACmdName  string `json:"ata_command_name"`
	LBA         uint64 `json:"lba"`
	DataHex     string `json:"data_hex,omitempty"`
}

// QueryConfig is the decoded Query-Config-Information body.
type QueryConfig struct {
	BufferCount int    `json:"buffer_count"`
	Firmware    int    `json:"firmware_version"`
	SectorCount int    `json:"sector_count"`
	AoEVersion  int    `json:"aoe_version"`
	ConfigCmd   int    `json:"config_command"`
	ConfigName  string `json:"config_command_name"`
	ConfigStr   string `json:"config_string,omitempty"`
	ConfigHex   string `json:"config_hex,omitempty"`
}

// Result is the decoded view of an AoE frame.
type Result struct {
	Version   int    `json:"version"`
	FlagsHex  string `json:"flags_hex"`
	Response  bool   `json:"response"`
	Error     bool   `json:"error_flag"`
	ErrorCode int    `json:"error_code"`
	ErrorName string `json:"error_name,omitempty"`
	Shelf     int    `json:"shelf"` // major
	Slot      int    `json:"slot"`  // minor
	Command   int    `json:"command"`
	CmdName   string `json:"command_name"`
	Tag       string `json:"tag"`

	ATA   *ATACommand  `json:"ata_command,omitempty"`
	Query *QueryConfig `json:"query_config,omitempty"`

	BodyHex string   `json:"body_hex,omitempty"`
	Notes   []string `json:"notes,omitempty"`
}

// Decode parses an AoE frame (the EtherType-0x88A2 payload) from hex
// (whitespace / ':' / '-' / '_' separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 10 {
		return nil, fmt.Errorf("aoe: %d bytes — too short for the 10-byte AoE header", len(b))
	}
	r := &Result{
		Version:   int(b[0] >> 4),
		FlagsHex:  fmt.Sprintf("0x%X", b[0]&0x0f),
		Response:  b[0]&0x08 != 0, // AoE spec / Wireshark: Response = bit 3
		Error:     b[0]&0x04 != 0, // Error = bit 2
		ErrorCode: int(b[1]),
		ErrorName: errorName(b[1]),
		Shelf:     int(binary.BigEndian.Uint16(b[2:4])),
		Slot:      int(b[4]),
		Command:   int(b[5]),
		CmdName:   cmdName(b[5]),
		Tag:       fmt.Sprintf("0x%08X", binary.BigEndian.Uint32(b[6:10])),
	}
	body := b[10:]
	switch b[5] {
	case 0: // Issue ATA Command
		r.ATA = decodeATA(body, r)
	case 1: // Query Config Information
		r.Query = decodeQuery(body, r)
	default:
		if len(body) > 0 {
			r.BodyHex = hexUpper(body)
		}
		r.Notes = append(r.Notes, "AoE command "+r.CmdName+": body surfaced raw")
	}
	r.Notes = append(r.Notes, "AoE exposes raw ATA disk commands over L2 with no authentication — any host on the segment can read/write an exposed target (shelf.slot)")
	return r, nil
}

func decodeATA(body []byte, r *Result) *ATACommand {
	if len(body) < 12 {
		r.Notes = append(r.Notes, "ATA command body truncated (need 12 bytes)")
		return nil
	}
	a := &ATACommand{
		AFlagsHex:   fmt.Sprintf("0x%02X", body[0]),
		ErrFeature:  int(body[1]),
		SectorCount: int(body[2]),
		ATACmd:      int(body[3]),
		ATACmdName:  ataCmdName(int(body[3])),
		// 48-bit LBA, little-endian: lba0 (body[4]) is the least-significant byte.
		LBA: uint64(body[4]) | uint64(body[5])<<8 | uint64(body[6])<<16 |
			uint64(body[7])<<24 | uint64(body[8])<<32 | uint64(body[9])<<40,
	}
	if data := body[12:]; len(data) > 0 {
		a.DataHex = hexUpper(data)
	}
	r.Notes = append(r.Notes, fmt.Sprintf("ATA %s: %d sector(s) at LBA %d on shelf.slot %d.%d", a.ATACmdName, a.SectorCount, a.LBA, r.Shelf, r.Slot))
	return a
}

func decodeQuery(body []byte, r *Result) *QueryConfig {
	if len(body) < 8 {
		r.Notes = append(r.Notes, "Query Config body truncated")
		return nil
	}
	q := &QueryConfig{
		BufferCount: int(binary.BigEndian.Uint16(body[0:2])),
		Firmware:    int(binary.BigEndian.Uint16(body[2:4])),
		SectorCount: int(body[4]),
		AoEVersion:  int(body[5] >> 4),
		ConfigCmd:   int(body[5] & 0x0f),
		ConfigName:  configCmdName(body[5] & 0x0f),
	}
	clen := int(binary.BigEndian.Uint16(body[6:8]))
	if clen > 0 && 8+clen <= len(body) {
		cfg := body[8 : 8+clen]
		if s, ok := printableASCII(cfg); ok {
			q.ConfigStr = s
		} else {
			q.ConfigHex = hexUpper(cfg)
		}
	}
	r.Notes = append(r.Notes, "AoE Query Config Information ("+q.ConfigName+"): reveals the target's config string + firmware")
	return q
}

func cmdName(c byte) string {
	switch c {
	case 0:
		return "Issue ATA Command"
	case 1:
		return "Query Config Information"
	case 2:
		return "MAC Mask List"
	case 3:
		return "Reserve / Release"
	}
	return fmt.Sprintf("command-%d", c)
}

func errorName(e byte) string {
	switch e {
	case 0:
		return ""
	case 1:
		return "Unrecognized command code"
	case 2:
		return "Bad argument parameter"
	case 3:
		return "Device unavailable"
	case 4:
		return "Config string present"
	case 5:
		return "Unsupported version"
	case 6:
		return "Target is reserved"
	}
	return fmt.Sprintf("error-%d", e)
}

func ataCmdName(c int) string {
	switch c {
	case 0x20:
		return "READ SECTORS"
	case 0x24:
		return "READ SECTORS EXT"
	case 0x30:
		return "WRITE SECTORS"
	case 0x34:
		return "WRITE SECTORS EXT"
	case 0x25:
		return "READ DMA EXT"
	case 0x35:
		return "WRITE DMA EXT"
	case 0xC8:
		return "READ DMA"
	case 0xCA:
		return "WRITE DMA"
	case 0xEC:
		return "IDENTIFY DEVICE"
	case 0xE7:
		return "FLUSH CACHE"
	case 0xEA:
		return "FLUSH CACHE EXT"
	case 0xE5:
		return "CHECK POWER MODE"
	}
	return fmt.Sprintf("0x%02X", c)
}

func configCmdName(c byte) string {
	switch c {
	case 0:
		return "read config string"
	case 1:
		return "test config string"
	case 2:
		return "test config string prefix"
	case 3:
		return "set config string"
	case 4:
		return "force set config string"
	}
	return fmt.Sprintf("ccmd-%d", c)
}

func printableASCII(b []byte) (string, bool) {
	s := strings.TrimRight(string(b), "\x00")
	for _, c := range []byte(s) {
		if c < 0x20 || c > 0x7e {
			return "", false
		}
	}
	return s, s != ""
}

func hexUpper(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("aoe: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("aoe: input is not valid hex: %w", err)
	}
	return b, nil
}
