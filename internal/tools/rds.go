// rds.go — host-side RDS / RBDS (FM Radio Data System) group
// decoder Spec, delegating to the internal/rds package.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/rds"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(rdsDecodeSpec)
}

var rdsDecodeSpec = Spec{
	Name: "rds_decode",
	Description: "Decode RDS / RBDS (Radio Data System) groups — the digital sub-carrier (57 kHz) " +
		"riding on every FM broadcast station, carrying the station's Programme Service name, " +
		"RadioText (now-playing / scrolling text), programme type, traffic flags and (for North " +
		"American RBDS) the call sign. This is the data an SDR pipeline (rtl_fm → redsea, or an " +
		"FM tuner with RDS) pulls off the air, and a staple of broadcast-RF forensics / spectrum " +
		"survey. Per IEC 62106 (RDS) / NRSC-4 (RBDS). Decodes:\n\n" +
		"- **Block A — PI** (Programme Identification) code, plus the **RBDS four-letter call " +
		"sign** derived from it (K/W stations; e.g. PI 0x4569 → KUFX) when `rbds` is set.\n" +
		"- **Block B** — group type (0A..15B), **TP** (traffic programme) flag, and the 5-bit " +
		"**programme type (PTY)** with both the RDS (European) and RBDS (North American) name " +
		"tables.\n" +
		"- **Group 0A/0B — Programme Service name** (8 characters, assembled across the four " +
		"segments) plus the **TA** (traffic announcement), **MS** (music/speech) and **DI** " +
		"(decoder-identification: stereo / artificial-head / compressed / dynamic-PTY) flags.\n" +
		"- **Group 2A/2B — RadioText** (up to 64 characters, assembled across segments and " +
		"truncated at the 0x0D terminator) with the A/B text flag.\n" +
		"- The **RDS G0 default character set** (IEC 62106 Annex E) for both Programme Service " +
		"and RadioText, so non-ASCII station text (e.g. ä, ö, é) renders correctly.\n\n" +
		"Input is the post-demodulation block hex: four 16-bit blocks (A B C D = 16 hex digits) " +
		"per group, one or more groups. The redsea `0xAAAA'BBBB'CCCC'DDDD` form, plain " +
		"concatenated hex, and ':' / '-' / '_' / whitespace / comma separators are all accepted. " +
		"Multiple groups are assembled into the full Programme Service name and RadioText.\n\n" +
		"Out of scope (deferred): clock-time (group 4A), alternative-frequency lists, Open Data " +
		"Applications / TMC traffic messages (3A / 8A), Enhanced Other Networks (14), PIN (1A), " +
		"PTYN (10A), and the legacy three-letter / nationally-linked RBDS call signs — the group " +
		"type is still reported for these so nothing is silently dropped.\n\n" +
		"Source: docs/catalog/gap-analysis.md (FM broadcast / SDR decode space). Wrap-vs-native: " +
		"native — RDS is fully public; a group is four 16-bit blocks decoded by pure bit-field " +
		"extraction plus the G0 charset, the PTY name tables and the RBDS PI→call-sign " +
		"arithmetic; no DSP, no crypto. The reference decoder (redsea) is reimplemented here, " +
		"not wrapped. Verified byte-for-byte against redsea's own test vectors.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"RDS group block hex: four 16-bit blocks (A B C D = 16 hex digits) per group, one or more groups. redsea 0x..'..'..'.. form, plain hex, and ':' '-' '_' whitespace ',' separators all tolerated."},
			"rbds":{"type":"boolean","description":"Use the North American RBDS programme-type names and derive the four-letter call sign from the PI code. Default false (European RDS programme-type names; no call sign)."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   rdsDecodeHandler,
}

func rdsDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("rds_decode: 'hex' is required")
	}
	res, err := rds.Decode(raw, rds.Options{RBDS: boolOr(p, "rbds", false)})
	if err != nil {
		return "", fmt.Errorf("rds_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
