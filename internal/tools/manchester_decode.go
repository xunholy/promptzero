// manchester_decode.go — host-side Manchester line-code decoder Spec,
// delegating to internal/linecode.
//
// Wrap-vs-native: native — Manchester is a fixed bi-phase pair mapping;
// decoding is a pair walk with a validity gate. It is the reverse-engineering
// layer between a raw OOK/FSK/RFID capture and the protocol decoders: "is this
// Manchester, and what's the data?" — the constant first question when bringing
// up a decoder. The project already does this inline across em4100 / z-wave /
// m-bus / weather / tpms; this exposes it as a reusable RE primitive. Offline.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/linecode"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(manchesterDecodeSpec)
}

var manchesterDecodeSpec = Spec{
	Name: "manchester_decode",
	Description: "Decode a raw '0'/'1' bitstream as standard Manchester line code — the reverse-" +
		"engineering layer between a raw OOK/FSK/RFID capture and the protocol decoders. When bringing " +
		"up a decoder for an unknown bitstream, 'is this Manchester, and if so what's the data?' is the " +
		"constant first question; this answers it.\n\n" +
		"Valid Manchester contains only the bit pairs 01 and 10, so a non-Manchester or mis-aligned " +
		"stream is flagged by its illegal 00/11 pairs rather than mis-decoded. The two naming conventions " +
		"(IEEE 802.3: 10→1, 01→0; and G.E. Thomas: the inverse) cannot be told apart from the bits alone, " +
		"so BOTH decodes are returned and the operator picks per the protocol's convention — never a " +
		"silent guess. Both bit alignments (from the first bit, or skipping a leading half-bit) are " +
		"tried, and the fully-valid alignment is highlighted — the framing hint.\n\n" +
		"Field: **bits** — a '0'/'1' string (space / '-' / '_' separators tolerated). Output is, per " +
		"alignment, the IEEE-802.3 and Thomas decodes, a validity flag, and any illegal-pair positions. " +
		"Offline transform — reads bits, transmits nothing, so it is Low risk. Wrap-vs-native: native — " +
		"a bi-phase pair walk over a bit string.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"bits":{"type":"string","description":"Raw '0'/'1' bitstream. Space / '-' / '_' separators tolerated."}
		},
		"required":["bits"]
	}`),
	Required:  []string{"bits"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   manchesterDecodeHandler,
}

func manchesterDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "bits")) == "" {
		return "", fmt.Errorf("manchester_decode: 'bits' is required")
	}
	res, err := linecode.DecodeManchester(str(p, "bits"))
	if err != nil {
		return "", fmt.Errorf("manchester_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
