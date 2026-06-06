// roce_decode.go — host-side RoCE / InfiniBand Base Transport Header (BTH)
// decoder Spec, delegating to internal/roce.
//
// Wrap-vs-native: native — a fixed 12-byte BTH: a byte opcode + a handful of
// bit-fields (flags, P_Key, a 24-bit destination QP, a 24-bit PSN); a
// byte/bit read + an opcode lookup, stdlib only. The InfiniBand transport
// decoder — surfaces the RDMA operation (READ / WRITE / ATOMIC / SEND / ACK /
// CNP), the transport service, the destination Queue Pair and the Partition
// Key from a captured RoCEv2 (UDP 4791) frame. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/roce"
)

func init() { //nolint:gochecknoinits
	Register(roceDecodeSpec)
}

var roceDecodeSpec = Spec{
	Name: "roce_decode",
	Description: "Decode the InfiniBand **Base Transport Header (BTH)** of **RoCE — RDMA over Converged " +
		"Ethernet**, the datacenter Remote Direct Memory Access fabric. RoCEv2 carries the InfiniBand " +
		"transport over UDP (destination port 4791), letting one host **read and write another host's memory " +
		"directly**, bypassing the remote CPU — the fabric under high-performance storage (NVMe-oF), GPU " +
		"clusters (NCCL / GPUDirect) and HPC. RDMA is a real, often-overlooked **attack surface**: the wire " +
		"protocol is unencrypted and unauthenticated by default, isolation rests only on the 16-bit Partition " +
		"Key (P_Key) and the Queue-Pair number, and an attacker on the fabric who can forge a BTH can issue " +
		"RDMA READ / WRITE operations against a remote host's registered memory.\n\n" +
		"A captured RoCE BTH identifies the **RDMA operation** in flight — an RDMA **READ / WRITE** (direct " +
		"remote memory access), an **atomic** compare-swap / fetch-add, a SEND, an ACK or a " +
		"**congestion-notification** (CNP) — with the **transport service** (RC / UC / RD / UD), the " +
		"**destination Queue Pair**, the **Partition Key** (the fabric isolation domain), the FECN/BECN " +
		"congestion flags and the packet sequence number. The InfiniBand transport member of the project's " +
		"network-decoder family, a distinct domain.\n\n" +
		"No confidently-wrong output: the 12-byte BTH layout + the 57-entry opcode table are verified " +
		"field-for-field against scapy's RoCE layer (and the opcode name table is code-generated from scapy's " +
		"authoritative map); only the always-present BTH is decoded — the per-opcode extended transport " +
		"headers (RETH / AETH / AtomicETH / ImmDt) and payload vary by opcode and are surfaced as raw hex (the " +
		"trailing 4 bytes are the ICRC). The transport-service type is derived from the opcode's top three " +
		"bits per the IBA spec; an opcode outside the known table is reported by value with a note. No " +
		"network, no device, transmits nothing, so it is Low risk. ':' / '-' / '_' / whitespace separators and " +
		"a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (RDMA / InfiniBand fabric recon). Wrap-vs-native: native — a " +
		"byte/bit read + an opcode lookup, stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The RoCE InfiniBand Base Transport Header (the UDP-port-4791 payload, or the BTH directly) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   roceDecodeHandler,
}

func roceDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("roce_decode: 'hex' is required")
	}
	res, err := roce.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("roce_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
