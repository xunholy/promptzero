package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/fileformat"
	"github.com/xunholy/promptzero/internal/risk"
)

// nrf24.go registers the nrf24_sniff_start and nrf24_list_targets primitives
// as AgentOnly specs. Both tools use the Flipper (not the Marauder):
// nrf24_sniff_start launches the NRF24 Sniffer FAP via the Flipper loader, and
// nrf24_list_targets reads the FAP's SD-card artefact.
//
// Excluded from Wave 3 (Wave 4 scope, both are LLM compositions):
//   - nrf24_mousejack_start: Critical-risk FAP launcher + workflow gating
//   - nrf24_payload_build:  DuckyScript synthesis + BadUSB validator chain

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
		Required:  nil,
		Risk:      risk.Low,
		Group:     GroupMetaUtil,
		AgentOnly: true,
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
}
