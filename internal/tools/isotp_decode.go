// isotp_decode.go — host-side ISO-TP (ISO 15765-2) transport decoder +
// reassembler Spec, delegating to the internal/isotp package.
//
// Wrap-vs-native: native — the ISO-TP PCI encoding is a public,
// deterministic standard (ISO 15765-2). This is the transport layer that
// sits between canbus_fd_decode (frame) and uds_decode / obd2_*_decode
// (application PDU): reassemble a multi-frame message off a CAN capture,
// then feed the payload to the diagnostic decoders.

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/isotp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(isotpDecodeSpec)
}

var isotpDecodeSpec = Spec{
	Name: "isotp_decode",
	Description: "Decode and reassemble ISO-TP (ISO 15765-2) transport frames — the layer that carries " +
		"multi-frame UDS / OBD-II messages over CAN. Feed the data field(s) of one or more captured " +
		"CAN frames (in order); each frame's Protocol Control Information is decoded (Single Frame / " +
		"First Frame / Consecutive Frame / Flow Control) and the carried application PDU is " +
		"reassembled.\n\n" +
		"This is the missing link between canbus_fd_decode (the CAN frame) and uds_decode / " +
		"obd2_pid_decode / obd2_dtc_decode (the diagnostic application message): hand a Single Frame, " +
		"or the ordered First + Consecutive frames of a multi-frame response, and the reassembled " +
		"`payload_hex` is the application PDU. When the reassembly is **complete**, the PDU is " +
		"**chained to the UDS decoder inline** (the `uds` field) — so the diagnostic service " +
		"(ReadDataByIdentifier, SecurityAccess, RoutineControl, …) is decoded in one shot, the CAN-side " +
		"parallel to doip_decode's UDS chaining. ISO-TP is a **generic transport** (it also carries " +
		"KWP2000 / OBD-II / raw data), so the UDS interpretation is a best effort, flagged with a note; " +
		"a non-UDS payload degrades to an unknown-service result. The raw `payload_hex` is kept for " +
		"handing to obd2_* / kwp_decode when the application protocol is not UDS.\n\n" +
		"Per-frame fields: the PCI type, the SF data length / FF total message length, the CF sequence " +
		"number, and the FC flow-status (ContinueToSend / Wait / Overflow) + block size + STmin. " +
		"Reassembly validates consecutive-frame sequence numbers (noting gaps), stops at the declared " +
		"length, and decodes-but-skips receiver-originated Flow-Control frames; an incomplete message " +
		"is reported as such with a note. Classic (≤7-byte) and the CAN-FD escape forms of SF/FF are " +
		"handled. Pass the data starting at the PCI byte (normal addressing). ':' / '-' / '_' / " +
		"whitespace and a 0x prefix tolerated per frame.\n\n" +
		"Pure offline transform — no bus or adapter. Wrap-vs-native: native — public ISO 15765-2 PCI " +
		"format, a few branches over byte slices, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"frames":{
				"type":"array",
				"description":"CAN frame data fields in order, each as hex (e.g. ['100A22F190010203','2104050607']). A single element decodes/uses that one frame.",
				"items":{"type":"string"}
			}
		},
		"required":["frames"]
	}`),
	Required:  []string{"frames"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   isotpDecodeHandler,
}

func isotpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	rawFrames, ok := p["frames"].([]any)
	if !ok || len(rawFrames) == 0 {
		return "", fmt.Errorf("isotp_decode: 'frames' must be a non-empty array of hex strings")
	}
	frames := make([][]byte, 0, len(rawFrames))
	for i, rf := range rawFrames {
		s, ok := rf.(string)
		if !ok {
			return "", fmt.Errorf("isotp_decode: frames[%d] is not a string", i)
		}
		clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "").Replace(strings.TrimSpace(s))
		clean = strings.TrimPrefix(strings.TrimPrefix(clean, "0x"), "0X")
		b, err := hex.DecodeString(clean)
		if err != nil {
			return "", fmt.Errorf("isotp_decode: frames[%d] invalid hex: %w", i, err)
		}
		frames = append(frames, b)
	}

	res, err := isotp.Reassemble(frames)
	if err != nil {
		return "", fmt.Errorf("isotp_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
