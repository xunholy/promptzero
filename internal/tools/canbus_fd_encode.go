// canbus_fd_encode.go — host-side CAN / CAN-FD frame builder Spec, the
// inverse of canbus_fd_decode, delegating to internal/canfd.Encode.
//
// Wrap-vs-native: native — building a SocketCAN candump frame string is the
// inverse of the parser already in internal/canfd; pure string assembly,
// round-trip-verified against the decoder. It is the frame-layer complement
// to isotp_encode: wrap each ISO-TP frame data field in a CAN frame here,
// then send via canbus_inject. Generation only — emits a candump string,
// transmits nothing.

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/xunholy/promptzero/internal/canfd"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(canbusFDEncodeSpec)
}

var canbusFDEncodeSpec = Spec{
	Name: "canbus_fd_encode",
	Description: "Build a SocketCAN candump frame string for a CAN / CAN-FD frame from fields — the " +
		"offline inverse of canbus_fd_decode. Renders the identifier the way candump pads it (3 hex " +
		"chars for an 11-bit standard ID, 8 for a 29-bit extended ID) so it round-trips; classic " +
		"frames use ID#data (or ID#R / ID#Rn for a remote frame) and CAN-FD frames use " +
		"ID##<flags-nibble><data> with BRS/ESI in the nibble.\n\n" +
		"This is the frame-layer complement to isotp_encode: to inject a multi-frame UDS/OBD-II/KWP " +
		"request, segment the PDU with isotp_encode, then wrap each frame's data field in a CAN frame " +
		"here (with the request's arbitration ID) and send via canbus_inject. Output is the candump " +
		"frame string plus the frame decoded back for confirmation — round-trip-verified against " +
		"canbus_fd_decode.\n\n" +
		"Fields: **id** (hex like 0x7DF / 7DF, or decimal), **extended** (29-bit), **fd** (CAN-FD), " +
		"**brs** / **esi** (CAN-FD flags), **rtr** + **remote_dlc** (classic remote frame), and " +
		"**data** (hex payload). Validates the CAN ranges (≤11-bit unless extended; ≤29-bit), classic " +
		"≤8 bytes, and legal CAN-FD lengths (0-8/12/16/20/24/32/48/64). Generation only — it produces " +
		"a candump string and transmits nothing, so it is Low risk. Wrap-vs-native: native — pure " +
		"string assembly, the inverse of the parser, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"id":{"type":"string","description":"CAN identifier as hex (0x7DF / 7DF) or decimal."},
			"extended":{"type":"boolean","description":"29-bit extended identifier (default false = 11-bit standard)."},
			"fd":{"type":"boolean","description":"CAN-FD frame (## grammar, allows >8-byte payloads)."},
			"brs":{"type":"boolean","description":"CAN-FD bit-rate switch (fd only)."},
			"esi":{"type":"boolean","description":"CAN-FD error-state indicator (fd only)."},
			"rtr":{"type":"boolean","description":"Classic remote frame (classic only)."},
			"remote_dlc":{"type":"integer","description":"Requested DLC for a remote frame (0..8)."},
			"data":{"type":"string","description":"Payload as hex (ignored for rtr). Separators tolerated."}
		},
		"required":["id"]
	}`),
	Required:  []string{"id"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   canbusFDEncodeHandler,
}

func canbusFDEncodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	id, err := parseCANID(p["id"])
	if err != nil {
		return "", fmt.Errorf("canbus_fd_encode: %w", err)
	}
	req := canfd.EncodeRequest{
		ID:        id,
		Extended:  boolOf(p["extended"]),
		FD:        boolOf(p["fd"]),
		BRS:       boolOf(p["brs"]),
		ESI:       boolOf(p["esi"]),
		RTR:       boolOf(p["rtr"]),
		RemoteDLC: intOf(p["remote_dlc"]),
	}
	if ds := strings.TrimSpace(str(p, "data")); ds != "" {
		clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "").Replace(ds)
		clean = strings.TrimPrefix(strings.TrimPrefix(clean, "0x"), "0X")
		b, err := hex.DecodeString(clean)
		if err != nil {
			return "", fmt.Errorf("canbus_fd_encode: data is not valid hex: %w", err)
		}
		req.Data = b
	}

	frame, err := canfd.Encode(req)
	if err != nil {
		return "", fmt.Errorf("canbus_fd_encode: %w", err)
	}
	back, _ := canfd.Decode(frame)
	out := struct {
		Frame   string        `json:"frame"`
		Decoded *canfd.Result `json:"decoded_back,omitempty"`
	}{Frame: frame, Decoded: back}
	body, _ := json.MarshalIndent(out, "", "  ")
	return string(body), nil
}

// parseCANID coerces a hex string ("0x7DF"/"7DF"), decimal string, or JSON
// number into a CAN identifier.
func parseCANID(v any) (uint32, error) {
	switch t := v.(type) {
	case float64:
		if t < 0 || t > 0x1FFFFFFF {
			return 0, fmt.Errorf("id %v out of CAN range", t)
		}
		return uint32(t), nil
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return 0, fmt.Errorf("id is required")
		}
		base := 10
		if strings.HasPrefix(strings.ToLower(s), "0x") {
			s, base = s[2:], 16
		} else if strings.ContainsAny(s, "ABCDEFabcdef") {
			base = 16
		}
		n, err := strconv.ParseUint(s, base, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid id %q: %w", t, err)
		}
		return uint32(n), nil
	default:
		return 0, fmt.Errorf("id must be a hex/decimal string or number")
	}
}

// boolOf coerces a JSON bool, tolerating nil as false.
func boolOf(v any) bool {
	b, _ := v.(bool)
	return b
}
