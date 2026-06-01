// nfc_t2t_encode.go — host-side NFC Forum Type 2 Tag header builder Spec,
// the inverse of nfc_t2t_decode, delegating to internal/t2t.EncodeHeader.
//
// Wrap-vs-native: native — building the Type 2 Tag header (UID + computed
// BCCs + lock + CC) is the inverse of the parser already in internal/t2t;
// pure byte assembly reusing the same BCC formula, round-trip-verified
// against the decoder. The NFC analogue of ibutton_encode: the clone-prep
// step for writing a chosen UID to a magic NTAG/Ultralight. Generation only.

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/t2t"
)

func init() { //nolint:gochecknoinits
	Register(nfcT2TEncodeSpec)
}

var nfcT2TEncodeSpec = Spec{
	Name: "nfc_t2t_encode",
	Description: "Build the first four pages (16 bytes) of an NFC Forum Type 2 Tag (NTAG / MIFARE " +
		"Ultralight) from a chosen UID — the offline inverse of nfc_t2t_decode. The two UID BCC check " +
		"bytes are COMPUTED for you (BCC0 = 0x88 XOR UID0..2, BCC1 = UID3..6), so the result passes a " +
		"reader's UID-integrity check. This is the clone-prep step for writing a chosen UID to a " +
		"UID-rewritable (\"magic\") NTAG/Ultralight — the NFC analogue of ibutton_encode. It writes " +
		"nothing and touches no card (generation only), so it is Low risk like the decoder.\n\n" +
		"Fields: **uid** (7-byte hex, required), **cc** (4-byte Capability Container hex; default " +
		"E1101200 = NDEF-formatted v1.0 / 144-byte / free access — override to replicate a specific " +
		"tag), **lock** (2-byte static-lock hex, default 0000 = unlocked), **internal** (page-2 " +
		"internal byte, default 0x48). Returns the 16-byte header (hex) plus the header decoded back " +
		"for confirmation — round-trip-verified against nfc_t2t_decode (BCCs validate).\n\n" +
		"Write this header to pages 0-3 of a magic tag (prepend it to your NDEF/user pages). " +
		"Separators / 0x tolerated. Companion to nfc_t2t_decode / ndef_encode. Wrap-vs-native: native " +
		"— public Type 2 layout, the same BCC formula as the decoder, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"uid":{"type":"string","description":"7-byte UID as hex (e.g. 04112233445566). Separators / 0x tolerated."},
			"cc":{"type":"string","description":"4-byte Capability Container as hex (default E1101200)."},
			"lock":{"type":"string","description":"2-byte static lock bytes as hex (default 0000 = unlocked)."},
			"internal":{"type":"string","description":"Page-2 internal byte as hex (default 48)."}
		},
		"required":["uid"]
	}`),
	Required:  []string{"uid"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   nfcT2TEncodeHandler,
}

func nfcT2TEncodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	uid := str(p, "uid")
	if strings.TrimSpace(uid) == "" {
		return "", fmt.Errorf("nfc_t2t_encode: 'uid' is required (7 bytes hex)")
	}
	req := t2t.EncodeRequest{UID: uid, CC: str(p, "cc")}

	if ls := strings.TrimSpace(str(p, "lock")); ls != "" {
		lb, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(strings.NewReplacer(" ", "", ":", "").Replace(ls), "0x"), "0X"))
		if err != nil || len(lb) != 2 {
			return "", fmt.Errorf("nfc_t2t_encode: 'lock' must be 2 hex bytes (e.g. 0000)")
		}
		req.Lock0, req.Lock1 = lb[0], lb[1]
	}
	if is := strings.TrimSpace(str(p, "internal")); is != "" {
		ib, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(is, "0x"), "0X"))
		if err != nil || len(ib) != 1 {
			return "", fmt.Errorf("nfc_t2t_encode: 'internal' must be a single hex byte (e.g. 48)")
		}
		req.Internal = ib[0]
	}

	b, err := t2t.EncodeHeader(req)
	if err != nil {
		return "", fmt.Errorf("nfc_t2t_encode: %w", err)
	}
	back, _ := t2t.Decode(hex.EncodeToString(b))
	out := struct {
		Hex     string   `json:"hex"`
		Decoded *t2t.T2T `json:"decoded_back,omitempty"`
	}{Hex: strings.ToUpper(hex.EncodeToString(b)), Decoded: back}
	body, _ := json.MarshalIndent(out, "", "  ")
	return string(body), nil
}
