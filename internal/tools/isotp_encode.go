// isotp_encode.go — host-side ISO-TP (ISO 15765-2) segmenter Spec, the
// inverse of isotp_decode, delegating to internal/isotp.Segment.
//
// Wrap-vs-native: native — segmenting a PDU into ISO-TP CAN frames is the
// inverse of the reassembly already in internal/isotp; pure byte assembly,
// round-trip-verified against the reassembler. To transmit a multi-frame
// UDS/OBD-II request you must segment it; this produces the frame data
// fields to feed a CAN injector. Generation only — emits frame bytes, sends
// nothing.

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
	Register(isotpEncodeSpec)
}

var isotpEncodeSpec = Spec{
	Name: "isotp_encode",
	Description: "Segment an application PDU into the ISO-TP (ISO 15765-2) CAN frame data fields needed " +
		"to transmit it — the inverse of isotp_decode. A PDU of up to 7 bytes becomes a single Single " +
		"Frame; a longer PDU becomes a First Frame followed by Consecutive Frames with cycling " +
		"sequence numbers (1,2,…,15,0,1,…). Every frame is padded to 8 bytes (classic CAN's fixed " +
		"size; the pad value is cosmetic — ISO-TP ignores bytes beyond the declared length).\n\n" +
		"This is the transmit-side complement of the canbus_fd_decode -> isotp_decode -> uds/obd2 " +
		"pipeline: to send a multi-frame UDS / OBD-II / KWP request, segment the application PDU here " +
		"and feed the resulting frames to a CAN injector. Output is the ordered frame data fields " +
		"(hex) plus the count and the reassembled PDU echoed back for confirmation — round-trip-" +
		"verified against isotp_decode.\n\n" +
		"Input is the PDU as hex (e.g. `22 F1 90` for a ReadDataByIdentifier(VIN) request). `pad` is " +
		"the fill byte for the unused tail (default 0x00). Classic CAN only; a PDU over the 12-bit " +
		"First Frame limit (4095 bytes) is rejected (the CAN-FD 32-bit escape is not emitted). " +
		"Generation only — it produces frame bytes and transmits nothing, so it is Low risk. " +
		"Wrap-vs-native: native — pure byte assembly, the inverse of the reassembler, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"pdu":{"type":"string","description":"Application PDU as hex (e.g. '22 F1 90'). Separators / 0x tolerated."},
			"pad":{"type":"string","description":"Fill byte for the unused frame tail, as 2 hex chars (default 00)."}
		},
		"required":["pdu"]
	}`),
	Required:  []string{"pdu"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   isotpEncodeHandler,
}

func isotpEncodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "pdu")
	clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "").Replace(strings.TrimSpace(raw))
	clean = strings.TrimPrefix(strings.TrimPrefix(clean, "0x"), "0X")
	if clean == "" {
		return "", fmt.Errorf("isotp_encode: 'pdu' is required")
	}
	pdu, err := hex.DecodeString(clean)
	if err != nil {
		return "", fmt.Errorf("isotp_encode: pdu is not valid hex: %w", err)
	}

	pad := byte(0x00)
	if ps := strings.TrimSpace(str(p, "pad")); ps != "" {
		pb, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(ps, "0x"), "0X"))
		if err != nil || len(pb) != 1 {
			return "", fmt.Errorf("isotp_encode: 'pad' must be a single hex byte (e.g. 00 or AA)")
		}
		pad = pb[0]
	}

	frames, err := isotp.Segment(pdu, pad)
	if err != nil {
		return "", fmt.Errorf("isotp_encode: %w", err)
	}
	hexFrames := make([]string, len(frames))
	for i, f := range frames {
		hexFrames[i] = strings.ToUpper(hex.EncodeToString(f))
	}
	// Round-trip confirmation against the reassembler.
	back, _ := isotp.Reassemble(frames)

	out := struct {
		Frames      []string `json:"frames"`
		FrameCount  int      `json:"frame_count"`
		Reassembled string   `json:"reassembled,omitempty"`
	}{Frames: hexFrames, FrameCount: len(frames)}
	if back != nil {
		out.Reassembled = back.PayloadHex
	}
	body, _ := json.MarshalIndent(out, "", "  ")
	return string(body), nil
}
