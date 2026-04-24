package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/targetmem"
)

// target.go registers the target_remember, target_recall, and target_forget
// tools. All three are AgentOnly:true — they operate on the TargetMem store
// which is only wired in agent mode. Handlers short-circuit with a friendly
// error when TargetMem is nil.

//nolint:gochecknoinits
func init() {
	Register(Spec{
		Name: "target_remember",
		Description: "Persist facts about a target across sessions. Keyed by (identifier, kind). " +
			"Use after a scan/detect to record what the operator learned — BSSIDs with SSID + channel, " +
			"NFC UIDs with tag type, Sub-GHz captures with frequency + protocol. Facts are arbitrary JSON.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"identifier":{"type":"string","description":"Stable identifier: BSSID, card UID hex, freq+protocol tuple, etc."},` +
			`"kind":{"type":"string","description":"One of bssid, nfc_uid, rfid_data, subghz, ibutton (default bssid)"},` +
			`"facts":{"type":"object","description":"Free-form JSON object with the facts to store"}` +
			`}}`),
		Required:  []string{"identifier"},
		Risk:      risk.Medium,
		Group:     GroupMetaUtil,
		AgentOnly: true,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if d.TargetMem == nil {
				return "", fmt.Errorf("target memory not initialised")
			}
			id := str(p, "identifier")
			if id == "" {
				return "", fmt.Errorf("identifier required")
			}
			kind := str(p, "kind")
			t := targetmem.Target{Identifier: id, Kind: kind}
			if facts, ok := p["facts"]; ok {
				t.Facts = facts
			}
			if err := d.TargetMem.Remember(t); err != nil {
				return "", err
			}
			return fmt.Sprintf("remembered %s (%s)", id, t.Kind), nil
		},
	})

	Register(Spec{
		Name: "target_recall",
		Description: "Look up remembered facts for a target, or list recent targets when no identifier " +
			"is supplied. Use at session start or before a tool call to see what PromptZero already " +
			"knows about a specific BSSID / UID / frequency.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"identifier":{"type":"string","description":"If omitted, returns the most-recently-seen targets"},` +
			`"kind":{"type":"string","description":"Kind of identifier (default bssid)"},` +
			`"limit":{"type":"integer","description":"Max rows when listing recent (default 10)"}` +
			`}}`),
		Required:  nil,
		Risk:      risk.Low,
		Group:     GroupMetaUtil,
		AgentOnly: true,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if d.TargetMem == nil {
				return "", fmt.Errorf("target memory not initialised")
			}
			id := str(p, "identifier")
			if id == "" {
				// No ID → list recent.
				n := intOr(p, "limit", 10)
				recent, err := d.TargetMem.Recent(n)
				if err != nil {
					return "", err
				}
				if len(recent) == 0 {
					return "no remembered targets", nil
				}
				b, _ := json.Marshal(recent)
				return string(b), nil
			}
			kind := str(p, "kind")
			if kind == "" {
				kind = targetmem.KindBSSID
			}
			t, ok, err := d.TargetMem.Lookup(id, kind)
			if err != nil {
				return "", err
			}
			if !ok {
				return fmt.Sprintf("no facts for %s (%s)", id, kind), nil
			}
			b, _ := json.Marshal(t)
			return string(b), nil
		},
	})

	Register(Spec{
		Name: "target_forget",
		Description: "Remove a target and its facts from memory. Used by operators who want to reset " +
			"the store for a given device, or to drop stale facts after a site re-survey.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"identifier":{"type":"string","description":"Target identifier to forget"},` +
			`"kind":{"type":"string","description":"Kind of identifier (default bssid)"}` +
			`}}`),
		Required:  []string{"identifier"},
		Risk:      risk.Medium,
		Group:     GroupMetaUtil,
		AgentOnly: true,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if d.TargetMem == nil {
				return "", fmt.Errorf("target memory not initialised")
			}
			id := str(p, "identifier")
			if id == "" {
				return "", fmt.Errorf("identifier required")
			}
			kind := str(p, "kind")
			if kind == "" {
				kind = targetmem.KindBSSID
			}
			if err := d.TargetMem.Forget(id, kind); err != nil {
				return "", err
			}
			return fmt.Sprintf("forgot %s (%s)", id, kind), nil
		},
	})
}
