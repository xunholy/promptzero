// kwp_encode.go — host-side KWP2000 (ISO 14230) message builder Spec, the
// inverse of kwp_decode, delegating to internal/kwp.Encode.
//
// Wrap-vs-native: native — building a KWP PDU is the inverse of the parser
// already in internal/kwp; pure byte assembly over the public ISO 14230
// framing, round-trip-verified against kwp_decode. The legacy-vehicle
// counterpart of uds_encode: build the request here, then segment with
// isotp_encode and frame with canbus_fd_encode to inject (KWP-over-CAN).
// Generation only — emits a PDU, transmits nothing.

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/kwp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(kwpEncodeSpec)
}

var kwpEncodeSpec = Spec{
	Name: "kwp_encode",
	Description: "Build a KWP2000 (Keyword Protocol 2000, ISO 14230) message from fields — the offline " +
		"inverse of kwp_decode, for the legacy / pre-CAN ECUs KWP targets. The legacy-vehicle " +
		"counterpart of uds_encode: build the request here, segment with isotp_encode, frame with " +
		"canbus_fd_encode, and inject (KWP-over-CAN).\n\n" +
		"Assembles SID, an optional param byte (a local identifier / session type / access mode — " +
		"KWP uses a single 1-byte param, not UDS's 16-bit DID or suppress-positive-response bit), then " +
		"payload:\n" +
		" - **request** (default): service 0x21 + param 0x01 -> 2101 (ReadDataByLocalIdentifier); " +
		"service 0x81 -> 81 (StartCommunication); service 0x3B + param + data (WriteDataByLocal-" +
		"Identifier).\n" +
		" - **positive_response**: the +0x40 is applied to the SID automatically.\n" +
		" - **negative_response**: emits 0x7F <SID> <nrc>.\n\n" +
		"Returns the PDU (hex) plus the message decoded back for confirmation — round-trip-verified " +
		"against kwp_decode. Fields accept hex (0x21 / 21) or decimal. Generation only — it produces a " +
		"PDU and transmits nothing, so it is Low risk. Wrap-vs-native: native — pure byte assembly, " +
		"the inverse of the parser, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"service":{"type":"string","description":"Service ID as hex (0x21 / 21) or decimal. For a positive response the +0x40 is applied automatically."},
			"direction":{"type":"string","description":"request (default), positive_response, or negative_response."},
			"param":{"type":"integer","description":"Optional param byte after the SID (local identifier / session type / access mode)."},
			"nrc":{"type":"string","description":"Negative-response code as hex/decimal (required for direction=negative_response)."},
			"payload":{"type":"string","description":"Trailing data as hex. Separators tolerated."}
		},
		"required":["service"]
	}`),
	Required:  []string{"service"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   kwpEncodeHandler,
}

func kwpEncodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	svc, err := parseIntOrHex(p["service"], "service")
	if err != nil {
		return "", fmt.Errorf("kwp_encode: %w", err)
	}
	req := kwp.EncodeRequest{Service: svc, Direction: str(p, "direction")}
	if v, ok := p["param"].(float64); ok {
		pv := int(v)
		req.Param = &pv
	}
	if nrc, ok, err := optIntOrHex(p["nrc"], "nrc"); err != nil {
		return "", fmt.Errorf("kwp_encode: %w", err)
	} else if ok {
		req.NRC = &nrc
	}
	if ps := strings.TrimSpace(str(p, "payload")); ps != "" {
		clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "").Replace(ps)
		clean = strings.TrimPrefix(strings.TrimPrefix(clean, "0x"), "0X")
		b, err := hex.DecodeString(clean)
		if err != nil {
			return "", fmt.Errorf("kwp_encode: payload is not valid hex: %w", err)
		}
		req.Payload = b
	}

	b, err := kwp.Encode(req)
	if err != nil {
		return "", fmt.Errorf("kwp_encode: %w", err)
	}
	back, _ := kwp.DecodeBytes(b)
	out := struct {
		Hex     string   `json:"hex"`
		Decoded *kwp.KWP `json:"decoded_back,omitempty"`
	}{Hex: strings.ToUpper(hex.EncodeToString(b)), Decoded: back}
	body, _ := json.MarshalIndent(out, "", "  ")
	return string(body), nil
}
