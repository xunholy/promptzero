// uds_encode.go — host-side UDS (ISO 14229) message builder Spec, the
// inverse of uds_decode, delegating to internal/uds.Encode.
//
// Wrap-vs-native: native — building a UDS PDU is the inverse of the parser
// already in internal/uds; pure byte assembly over the public ISO 14229
// framing, round-trip-verified against uds_decode. It is the application-
// layer top of the inject pipeline: build the request here, segment with
// isotp_encode, wrap with canbus_fd_encode, send via canbus_inject.
// Generation only — emits a PDU, transmits nothing.

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/uds"
)

func init() { //nolint:gochecknoinits
	Register(udsEncodeSpec)
}

var udsEncodeSpec = Spec{
	Name: "uds_encode",
	Description: "Build a UDS (Unified Diagnostic Services, ISO 14229) message from fields — the " +
		"offline inverse of uds_decode. This is the application-layer top of the CAN injection " +
		"pipeline: build the request here, segment it with isotp_encode, wrap each frame with " +
		"canbus_fd_encode, and send via canbus_inject (the encode mirror of the canbus_fd_decode -> " +
		"isotp_decode -> uds_decode read path).\n\n" +
		"Assembles the bytes in the canonical order — SID, optional sub-function (with the " +
		"suppress-positive-response bit), optional 16-bit data identifier, then payload:\n" +
		" - **request** (default): e.g. service 0x10 + sub_function 0x03 -> 1003 " +
		"(DiagnosticSessionControl extended); service 0x22 + data_identifier 0xF190 -> 22F190 " +
		"(ReadDataByIdentifier VIN); service 0x3E + sub_function 0 + suppress -> 3E80.\n" +
		" - **positive_response**: the +0x40 is applied to the SID automatically.\n" +
		" - **negative_response**: emits 0x7F <SID> <nrc>.\n\n" +
		"Returns the PDU (hex) plus the message decoded back for confirmation — round-trip-verified " +
		"against uds_decode. Fields accept hex (0x22 / 22) or decimal. Generation only — it produces " +
		"a PDU and transmits nothing, so it is Low risk. Companion to kwp_encode-less kwp_decode and " +
		"the isotp_encode / canbus_fd_encode inject chain. Wrap-vs-native: native — pure byte " +
		"assembly, the inverse of the parser, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"service":{"type":"string","description":"Service ID as hex (0x22 / 22) or decimal. For a positive response the +0x40 is applied automatically."},
			"direction":{"type":"string","description":"request (default), positive_response, or negative_response."},
			"sub_function":{"type":"integer","description":"Optional sub-function byte (0..127), e.g. session/reset/routine type."},
			"suppress_positive_response":{"type":"boolean","description":"Set bit 7 of the sub-function (request only) to suppress the positive response."},
			"data_identifier":{"type":"string","description":"Optional 16-bit DID as hex (0xF190) or decimal, for Read/Write DataByIdentifier."},
			"nrc":{"type":"string","description":"Negative-response code as hex/decimal (required for direction=negative_response)."},
			"payload":{"type":"string","description":"Trailing data as hex (e.g. a key, a value to write). Separators tolerated."}
		},
		"required":["service"]
	}`),
	Required:  []string{"service"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   udsEncodeHandler,
}

func udsEncodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	svc, err := parseIntOrHex(p["service"], "service")
	if err != nil {
		return "", fmt.Errorf("uds_encode: %w", err)
	}
	req := uds.EncodeRequest{
		Service:                  svc,
		Direction:                str(p, "direction"),
		SuppressPositiveResponse: boolOf(p["suppress_positive_response"]),
	}
	if v, ok := p["sub_function"].(float64); ok {
		sf := int(v)
		req.SubFunction = &sf
	}
	if did, ok, err := optIntOrHex(p["data_identifier"], "data_identifier"); err != nil {
		return "", fmt.Errorf("uds_encode: %w", err)
	} else if ok {
		req.DataIdentifier = &did
	}
	if nrc, ok, err := optIntOrHex(p["nrc"], "nrc"); err != nil {
		return "", fmt.Errorf("uds_encode: %w", err)
	} else if ok {
		req.NRC = &nrc
	}
	if ps := strings.TrimSpace(str(p, "payload")); ps != "" {
		clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "").Replace(ps)
		clean = strings.TrimPrefix(strings.TrimPrefix(clean, "0x"), "0X")
		b, err := hex.DecodeString(clean)
		if err != nil {
			return "", fmt.Errorf("uds_encode: payload is not valid hex: %w", err)
		}
		req.Payload = b
	}

	b, err := uds.Encode(req)
	if err != nil {
		return "", fmt.Errorf("uds_encode: %w", err)
	}
	back, _ := uds.DecodeBytes(b)
	out := struct {
		Hex     string   `json:"hex"`
		Decoded *uds.UDS `json:"decoded_back,omitempty"`
	}{Hex: strings.ToUpper(hex.EncodeToString(b)), Decoded: back}
	body, _ := json.MarshalIndent(out, "", "  ")
	return string(body), nil
}

// parseIntOrHex coerces a JSON number or a hex/decimal string into an int.
func parseIntOrHex(v any, field string) (int, error) {
	switch t := v.(type) {
	case float64:
		return int(t), nil
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return 0, fmt.Errorf("%s is required", field)
		}
		base := 10
		if strings.HasPrefix(strings.ToLower(s), "0x") {
			s, base = s[2:], 16
		} else if strings.ContainsAny(s, "ABCDEFabcdef") {
			base = 16
		}
		n, err := strconv.ParseInt(s, base, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid %s %q: %w", field, t, err)
		}
		return int(n), nil
	default:
		return 0, fmt.Errorf("%s must be a hex/decimal string or number", field)
	}
}

// optIntOrHex is parseIntOrHex for an optional field; the bool reports
// whether a value was present.
func optIntOrHex(v any, field string) (int, bool, error) {
	if v == nil {
		return 0, false, nil
	}
	if s, ok := v.(string); ok && strings.TrimSpace(s) == "" {
		return 0, false, nil
	}
	n, err := parseIntOrHex(v, field)
	return n, err == nil, err
}
