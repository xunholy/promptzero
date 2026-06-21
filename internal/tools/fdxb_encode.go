// fdxb_encode.go — host-side FDX-B (ISO 11784/11785) LF data-block generator
// Spec, the inverse of fdxb_decode, delegating to internal/fdxb.Encode.
//
// Wrap-vs-native: native — fixed LSB-first bit placement in the 64-bit ID block
// + the Proxmark3 FDX-B CRC-16; stdlib only. Round-trips with fdxb_decode,
// extending the LF clone-generation set (em4100_encode / ioprox_encode /
// noralsy_encode / viking_encode / jablotron_encode / presco_encode) to the
// animal-microchip format. Offline transform, transmits nothing.

package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/fdxb"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(fdxbEncodeSpec)
}

// fdxbMaxNational is the largest 38-bit national identification number.
const fdxbMaxNational = (1 << 38) - 1

var fdxbEncodeSpec = Spec{
	Name: "fdxb_encode",
	Description: "Generate the 10-byte **FDX-B (ISO 11784/11785)** LF data block — the 134.2 kHz animal / pet " +
		"microchip transponder format — from a national identification number and country code. The inverse of " +
		"`fdxb_decode`, extending the LF **clone-generation set** (`em4100_encode`, `ioprox_encode`, " +
		"`noralsy_encode`, `viking_encode`, `jablotron_encode`, `presco_encode`) to the animal-tag format: the " +
		"block is the de-stuffed ID block you would feed a transponder writer to clone an FDX-B credential for " +
		"an authorized test.\n\n" +
		"Builds the documented data block — the 38-bit national code (LSB-first at bit 0), the 10-bit country " +
		"code (bit 38), the data-block-status and animal-application flag bits (48/49), the reserved bits " +
		"(50-63, emitted as zero) — packed MSB-first into 8 bytes, then appends the 2-byte FDX-B CRC-16 (CCITT " +
		"polynomial 0x1021, init 0, output-reflected, over the first 8 bytes). **No confidently-wrong output**: " +
		"the layout + CRC are the same Proxmark3-referenced ones `fdxb_decode` uses, and the encoder " +
		"**round-trips** with it (decoding the emitted block reproduces the national / country / flags with a " +
		"valid CRC) and reproduces the decoder's published real-tag vector on the identity bytes (country 528 / " +
		"national 140000795552 → ID bytes `05D94D19042100…`). The on-air framing (11-bit preamble + the control " +
		"'1' after every 8 bits) is the transponder writer's concern and out of scope, exactly as on the decode " +
		"side. Produces the block only — it transmits nothing and writes to no device, so it is Low risk.\n\n" +
		"Inputs: **national_code** (0-274877906943, 38 bits), **country_code** (0-1023, 10 bits), optional " +
		"**animal_application** (bool, the animal-tag flag) and **data_block** (bool, the extended-block-present " +
		"flag; the 24-bit extended block itself is vendor-specific and out of scope). Wrap-vs-native: native — " +
		"fixed bit placement + a CRC-16, stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"national_code":{"type":"integer","description":"38-bit national identification number (0-274877906943)."},
			"country_code":{"type":"integer","description":"10-bit country code (0-1023; 900-999 are manufacturer/test ranges)."},
			"animal_application":{"type":"boolean","description":"Set the animal-application flag (bit 49). Default false."},
			"data_block":{"type":"boolean","description":"Set the extended-data-block-present flag (bit 48). Default false; the 24-bit extended block itself is out of scope."}
		},
		"required":["national_code","country_code"]
	}`),
	Required:  []string{"national_code", "country_code"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   fdxbEncodeHandler,
}

func fdxbEncodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	national, err := intField(p, "national_code", 0, fdxbMaxNational)
	if err != nil {
		return "", fmt.Errorf("fdxb_encode: %w", err)
	}
	country, err := intField(p, "country_code", 0, 1023)
	if err != nil {
		return "", fmt.Errorf("fdxb_encode: %w", err)
	}
	animal := boolOr(p, "animal_application", false)
	dataBlock := boolOr(p, "data_block", false)

	block, err := fdxb.EncodeHex(uint64(national), country, animal, dataBlock)
	if err != nil {
		return "", fmt.Errorf("fdxb_encode: %w", err)
	}
	out := map[string]any{
		"format":             "FDX-B (ISO 11784/11785)",
		"national_code":      national,
		"country_code":       country,
		"animal_application": animal,
		"data_block_present": dataBlock,
		"id_crc_block_hex":   block,
		"note":               "de-stuffed 10-byte ID+CRC block (8-byte ID + 2-byte CRC-16); on-air preamble/bit-stuffing is the writer's concern. Generation only — transmits nothing.",
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return string(b), nil
}
