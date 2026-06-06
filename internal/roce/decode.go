// SPDX-License-Identifier: AGPL-3.0-or-later

// Package roce decodes the InfiniBand Base Transport Header (BTH) of RoCE —
// RDMA over Converged Ethernet — the datacenter Remote Direct Memory Access
// fabric. RoCEv2 carries the InfiniBand transport over UDP (destination port
// 4791), letting one host read and write another host's memory directly,
// bypassing the remote CPU. It is the fabric under high-performance storage
// (NVMe-oF), GPU clusters (NCCL / GPUDirect) and HPC. RDMA is a real and
// often-overlooked attack surface: the wire protocol is unencrypted and
// unauthenticated by default, isolation rests only on the 16-bit Partition
// Key (P_Key) and the Queue-Pair number, and an attacker on the fabric who
// can forge a BTH can issue RDMA READ / WRITE operations against a remote
// host's registered memory regions. A captured RoCE BTH identifies the
// **RDMA operation** in flight — an RDMA READ / WRITE (direct remote memory
// access), an atomic compare-swap / fetch-add, a SEND, an ACK or a
// congestion-notification (CNP) — together with the **destination Queue
// Pair**, the **Partition Key** (the fabric isolation domain) and the packet
// sequence number, which is the recon headline for RDMA-fabric reconnaissance.
// It is the InfiniBand transport member of the project's network-decoder
// family, a distinct domain.
//
// # Wrap-vs-native judgement
//
//	Native. The BTH is a fixed 12-byte header — a byte opcode + a handful of
//	bit-fields (flags, P_Key, a 24-bit destination QP, a 24-bit PSN). A
//	byte/bit read + an opcode lookup; stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The 12-byte BTH layout and the 57-entry opcode table were verified
//	field-for-field against scapy's RoCE layer (scapy.contrib.roce). The
//	opcode name table is code-generated from scapy's authoritative map (not
//	hand-transcribed). Only the always-present BTH is decoded: the per-opcode
//	extended transport headers (RETH for RDMA, AETH for ACKs, AtomicETH, the
//	ImmDt / immediate data) and the payload vary by opcode and are surfaced
//	as raw hex — the trailing 4 bytes are the ICRC. The transport-service
//	type is derived from the opcode's top three bits per the IBA spec; an
//	opcode outside the known table is reported by value with a note rather
//	than guessed.
package roce

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of a RoCE InfiniBand Base Transport Header.
type Result struct {
	Opcode           int      `json:"opcode"`
	OpcodeHex        string   `json:"opcode_hex"`
	OpcodeName       string   `json:"opcode_name"`
	TransportService string   `json:"transport_service"`
	Solicited        bool     `json:"solicited"`
	MigReq           bool     `json:"mig_req"`
	PadCount         int      `json:"pad_count"`
	HeaderVersion    int      `json:"header_version"`
	PKey             string   `json:"p_key"`
	FECN             bool     `json:"fecn"`
	BECN             bool     `json:"becn"`
	DestQP           string   `json:"dest_qp"`
	AckReq           bool     `json:"ack_req"`
	PSN              int      `json:"psn"`
	PayloadHex       string   `json:"payload_hex,omitempty"`
	Notes            []string `json:"notes,omitempty"`
}

// Decode parses a RoCE Base Transport Header (the UDP-port-4791 payload, or
// the IB BTH directly) from hex (whitespace / ':' / '-' / '_' separators and
// a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 12 {
		return nil, fmt.Errorf("roce: %d bytes — too short for the 12-byte InfiniBand Base Transport Header", len(b))
	}
	opcode := b[0]
	r := &Result{
		Opcode:           int(opcode),
		OpcodeHex:        fmt.Sprintf("0x%02X", opcode),
		OpcodeName:       opcodeName(opcode),
		TransportService: transportService(opcode),
		Solicited:        b[1]&0x80 != 0,
		MigReq:           b[1]&0x40 != 0,
		PadCount:         int(b[1] >> 4 & 0x3),
		HeaderVersion:    int(b[1] & 0x0F),
		PKey:             fmt.Sprintf("0x%04X", binary.BigEndian.Uint16(b[2:4])),
		FECN:             b[4]&0x80 != 0,
		BECN:             b[4]&0x40 != 0,
		DestQP:           fmt.Sprintf("0x%06X", uint32(b[5])<<16|uint32(b[6])<<8|uint32(b[7])),
		AckReq:           b[8]&0x80 != 0,
		PSN:              int(uint32(b[9])<<16 | uint32(b[10])<<8 | uint32(b[11])),
	}
	if len(b) > 12 {
		r.PayloadHex = strings.ToUpper(hex.EncodeToString(b[12:]))
	}
	r.Notes = append(r.Notes, "RoCE / InfiniBand BTH — RDMA over Converged Ethernet (RoCEv2 over UDP port 4791); the opcode names the RDMA operation and transport service")
	if r.OpcodeName == "" {
		r.OpcodeName = r.OpcodeHex
		r.Notes = append(r.Notes, fmt.Sprintf("opcode 0x%02X is not in the IBA opcode table — surfaced by value (transport-service bits still decoded)", opcode))
	}
	switch {
	case strings.Contains(r.OpcodeName, "RDMA_READ"):
		r.Notes = append(r.Notes, "RDMA READ: a direct read of the remote host's registered memory (the remote CPU is bypassed) — high-value RDMA-fabric activity")
	case strings.Contains(r.OpcodeName, "RDMA_WRITE"):
		r.Notes = append(r.Notes, "RDMA WRITE: a direct write into the remote host's registered memory (the remote CPU is bypassed) — high-value RDMA-fabric activity")
	case strings.Contains(r.OpcodeName, "COMPARE_SWAP"), strings.Contains(r.OpcodeName, "FETCH_ADD"):
		r.Notes = append(r.Notes, "RDMA ATOMIC: a remote atomic memory operation against the target's registered memory")
	case r.OpcodeName == "CNP":
		r.Notes = append(r.Notes, "Congestion Notification Packet — RoCE explicit congestion control (DCQCN), not a data transfer")
	}
	r.Notes = append(r.Notes, "the extended transport headers (RETH / AETH / AtomicETH / ImmDt) and payload follow the BTH and are surfaced as raw hex; the trailing 4 bytes are the ICRC")
	return r, nil
}

// transportService maps the opcode's top three bits to the IBA transport
// service type (structurally defined by the spec, so safe for any opcode).
func transportService(opcode byte) string {
	switch opcode >> 5 {
	case 0:
		return "RC (Reliable Connection)"
	case 1:
		return "UC (Unreliable Connection)"
	case 2:
		return "RD (Reliable Datagram)"
	case 3:
		return "UD (Unreliable Datagram)"
	case 4:
		return "CNP / Manufacturer-specific"
	case 5:
		return "XRC (Extended Reliable Connection)"
	}
	return "reserved"
}

// opcodeName maps the BTH opcode to its name (code-generated from scapy's
// authoritative scapy.contrib.roce opcode table). Empty for unknown opcodes.
func opcodeName(op byte) string {
	names := map[byte]string{
		0x00: "RC_SEND_FIRST",
		0x01: "RC_SEND_MIDDLE",
		0x02: "RC_SEND_LAST",
		0x03: "RC_SEND_LAST_WITH_IMMEDIATE",
		0x04: "RC_SEND_ONLY",
		0x05: "RC_SEND_ONLY_WITH_IMMEDIATE",
		0x06: "RC_RDMA_WRITE_FIRST",
		0x07: "RC_RDMA_WRITE_MIDDLE",
		0x08: "RC_RDMA_WRITE_LAST",
		0x09: "RC_RDMA_WRITE_LAST_WITH_IMMEDIATE",
		0x0A: "RC_RDMA_WRITE_ONLY",
		0x0B: "RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE",
		0x0C: "RC_RDMA_READ_REQUEST",
		0x0D: "RC_RDMA_READ_RESPONSE_FIRST",
		0x0E: "RC_RDMA_READ_RESPONSE_MIDDLE",
		0x0F: "RC_RDMA_READ_RESPONSE_LAST",
		0x10: "RC_RDMA_READ_RESPONSE_ONLY",
		0x11: "RC_ACKNOWLEDGE",
		0x12: "RC_ATOMIC_ACKNOWLEDGE",
		0x13: "RC_COMPARE_SWAP",
		0x14: "RC_FETCH_ADD",
		0x20: "UC_SEND_FIRST",
		0x21: "UC_SEND_MIDDLE",
		0x22: "UC_SEND_LAST",
		0x23: "UC_SEND_LAST_WITH_IMMEDIATE",
		0x24: "UC_SEND_ONLY",
		0x25: "UC_SEND_ONLY_WITH_IMMEDIATE",
		0x26: "UC_RDMA_WRITE_FIRST",
		0x27: "UC_RDMA_WRITE_MIDDLE",
		0x28: "UC_RDMA_WRITE_LAST",
		0x29: "UC_RDMA_WRITE_LAST_WITH_IMMEDIATE",
		0x2A: "UC_RDMA_WRITE_ONLY",
		0x2B: "UC_RDMA_WRITE_ONLY_WITH_IMMEDIATE",
		0x40: "RD_SEND_FIRST",
		0x41: "RD_SEND_MIDDLE",
		0x42: "RD_SEND_LAST",
		0x43: "RD_SEND_LAST_WITH_IMMEDIATE",
		0x44: "RD_SEND_ONLY",
		0x45: "RD_SEND_ONLY_WITH_IMMEDIATE",
		0x46: "RD_RDMA_WRITE_FIRST",
		0x47: "RD_RDMA_WRITE_MIDDLE",
		0x48: "RD_RDMA_WRITE_LAST",
		0x49: "RD_RDMA_WRITE_LAST_WITH_IMMEDIATE",
		0x4A: "RD_RDMA_WRITE_ONLY",
		0x4B: "RD_RDMA_WRITE_ONLY_WITH_IMMEDIATE",
		0x4C: "RD_RDMA_READ_REQUEST",
		0x4D: "RD_RDMA_READ_RESPONSE_FIRST",
		0x4E: "RD_RDMA_READ_RESPONSE_MIDDLE",
		0x4F: "RD_RDMA_READ_RESPONSE_LAST",
		0x50: "RD_RDMA_READ_RESPONSE_ONLY",
		0x51: "RD_ACKNOWLEDGE",
		0x52: "RD_ATOMIC_ACKNOWLEDGE",
		0x53: "RD_COMPARE_SWAP",
		0x54: "RD_FETCH_ADD",
		0x64: "UD_SEND_ONLY",
		0x65: "UD_SEND_ONLY_WITH_IMMEDIATE",
		0x81: "CNP",
	}
	return names[op]
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("roce: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("roce: input is not valid hex: %w", err)
	}
	return b, nil
}
