package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/fileformat"
	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/validator"
)

// nrf24.go registers NRF24 tools. Waves 3 and 4 contribute:
//   - nrf24_sniff_start   (Wave 3) — launch Sniffer FAP (AgentOnly)
//   - nrf24_list_targets  (Wave 3) — read captured addresses (AgentOnly)
//   - nrf24_mousejack_start (Wave 4) — launch Mousejacker FAP (AgentOnly, Critical)
//   - nrf24_payload_build   (Wave 4) — DuckyScript synthesis (AgentOnly, Medium)

//nolint:gochecknoinits
func init() {
	Register(Spec{
		Name: "nrf24_sniff_start",
		Description: "Launch the NRF24 Sniffer FAP. Scans 2.4 GHz bands for active wireless-peripheral addresses " +
			"(Logitech Unifying, Microsoft Wireless, some keyboards/mice) and writes hits to " +
			"/ext/apps_data/nrfsniff/addresses.txt. Requires an NRF24L01+ module wired to the Flipper GPIO header. " +
			"Operator drives the UI; exit via the back button.",
		Schema:    json.RawMessage(`{"type":"object","properties":{}}`),
		Required:  nil,
		Risk:      risk.Medium,
		Group:     GroupMetaUtil,
		AgentOnly: true,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.LoaderNRF24Sniffer()
		},
	})

	Register(Spec{
		Name: "nrf24_list_targets",
		Description: "Read and parse the NRF24 Sniffer's captured address list from " +
			"/ext/apps_data/nrfsniff/addresses.txt. Returns a JSON array of {address, rate} entries. " +
			"Invalid lines are returned as warnings. Run this before building a mousejack payload so the " +
			"operator sees which targets are live.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"path":{"type":"string","description":"SD path to the addresses file (default /ext/apps_data/nrfsniff/addresses.txt)"}}}`),
		Required: nil,
		Risk:     risk.Low,
		Group:    GroupMetaUtil,
		// Read-only SD-card file parse (needs only Deps.Flipper). Like every
		// tool it is exposed on all surfaces; the active nrf24_* tools
		// (sniff/mousejack) are exposed too but consent-gated by their risk
		// level. This lets an operator inspect captured targets before acting.
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			path := str(p, "path")
			if path == "" {
				path = "/ext/apps_data/nrfsniff/addresses.txt"
			}
			raw, err := d.Flipper.StorageRead(path)
			if err != nil {
				// The FAP writes the file only after a successful scan.
				// Surface an actionable message rather than a raw serial err.
				return fmt.Sprintf("no NRF24 targets captured yet (%s not readable: %v). Run nrf24_sniff_start first.", path, err), nil
			}
			targets, warnings, err := fileformat.ParseNRF24Addresses(raw)
			if err != nil {
				return fmt.Sprintf("addresses.txt unparseable: %v\n\nRaw content:\n%s", err, raw), nil
			}
			payload := map[string]interface{}{
				"path":     path,
				"targets":  targets,
				"warnings": warnings,
			}
			b, _ := json.Marshal(payload)
			return string(b), nil
		},
	})

	// --- Wave 4: LLM compositions ---

	Register(Spec{
		Name: "nrf24_mousejack_start",
		Description: "Launch the NRF24 Mousejacker FAP. The FAP reads targets from " +
			"/ext/apps_data/nrfsniff/addresses.txt and payloads from /ext/mousejacker/ — populate both before " +
			"launching. Keystroke injection happens via the FAP UI; PromptZero cannot drive it beyond input_send " +
			"button presses. Back button exits. Critical-risk tool.",
		Schema:    json.RawMessage(`{"type":"object","properties":{}}`),
		Required:  nil,
		Risk:      risk.Critical,
		Group:     GroupMetaUtil,
		AgentOnly: true,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.LoaderNRF24Mousejacker()
		},
	})

	Register(Spec{
		Name: "nrf24_payload_build",
		Description: "Synthesise a DuckyScript keystroke payload for the NRF24 Mousejacker FAP and write it to " +
			"/ext/mousejacker/<name>.txt. The script is validated against the mousejack-specific DELAY ceiling " +
			"(2.4 GHz injection loses sync on long pauses) and run through the BadUSB static validator for " +
			"destructive-pattern detection. High/critical validator hits block write unless verify_bypass=true.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"name":{"type":"string","description":"Payload filename (written to /ext/mousejacker/<name>.txt)"},` +
			`"script":{"type":"string","description":"DuckyScript body — STRING/DELAY/GUI combos the FAP will replay at the remote keyboard"},` +
			`"target_os":{"type":"string","description":"Target OS hint: windows, macos, linux (default windows)"},` +
			`"max_delay_ms":{"type":"integer","description":"Override the default 5000 ms DELAY ceiling"},` +
			`"verify_bypass":{"type":"boolean","description":"Skip the block on critical static-validator findings"}` +
			`}}`),
		Required:  []string{"name", "script"},
		Risk:      risk.Medium,
		Group:     GroupMetaUtil,
		AgentOnly: true,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			name := str(p, "name")
			script := str(p, "script")
			if name == "" {
				return "", fmt.Errorf("name required")
			}
			if script == "" {
				return "", fmt.Errorf("script required")
			}
			raw, err := fileformat.BuildMousejackPayload(fileformat.MousejackPayloadParams{
				Script:     script,
				TargetOS:   str(p, "target_os"),
				MaxDelayMS: intOr(p, "max_delay_ms", 0),
			})
			if err != nil {
				return "", err
			}
			// Reuse the BadUSB static validator — DuckyScript is the same
			// lexical surface, so rm_rf / reverse shell / persistence rules
			// are a free lift.
			rep := validator.Validate(name, string(raw))
			if rep.Has(validator.SeverityCritical) && !boolOr(p, "verify_bypass", false) {
				return fmt.Sprintf("mousejack payload blocked by static validator.\n\n%s\n\nPass verify_bypass=true to override.", nrf24RenderReport(rep)), nil
			}
			path := "/ext/mousejacker/" + name + ".txt"
			d.SnapshotBeforeWrite(ctx, path)
			if err := d.Flipper.WriteFileCtx(ctx, path, raw); err != nil {
				return "", fmt.Errorf("write %s: %w", path, err)
			}
			return fmt.Sprintf("built %d-byte mousejack payload → %s\n%s", len(raw), path, nrf24RenderReport(rep)), nil
		},
	})
}

// nrf24RenderReport renders a validator.Report into a concise string.
// Kept local to nrf24.go to avoid a cross-file helper dependency.
func nrf24RenderReport(r validator.Report) string {
	if len(r.Findings) == 0 {
		return fmt.Sprintf("static validator: %s (no findings)", r.Severity)
	}
	s := fmt.Sprintf("static validator: %s — %d finding(s)", r.Severity, len(r.Findings))
	for _, f := range r.Findings {
		if f.Line > 0 {
			s += fmt.Sprintf("\n  [%s] L%d %s: %s", f.Severity, f.Line, f.Rule, f.Message)
		} else {
			s += fmt.Sprintf("\n  [%s] %s: %s", f.Severity, f.Rule, f.Message)
		}
	}
	return s
}
