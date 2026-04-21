// Package attack maps PromptZero tools and workflows to MITRE ATT&CK
// techniques. The registry is intentionally a small, curated subset of
// MITRE's full catalog — just the techniques PromptZero's hardware
// surfaces can actually execute — rather than a wrapped copy of the
// entire matrix. Operators who need full MITRE reference material
// should consult attack.mitre.org; this package exists to give the
// agent's planner and the report generator a stable handle on which
// techniques each tool contributes to.
//
// Design notes:
//
//   - Tool → technique mapping is N:M. wifi_sniff_pmkid produces both
//     a network-sniffing signal (T1040) and a credential-grab signal
//     (T1552.004), so both attach.
//   - Technique IDs follow MITRE's own notation (T1040, T1557.004).
//     Sub-technique IDs carry a dot. Callers should treat them as
//     opaque strings — never split.
//   - The built-in list is curated, not exhaustive. Add new techniques
//     to builtinTechniques and new mappings to builtinToolMap as new
//     tools land. Unknown tools return an empty slice rather than
//     erroring, so this package never blocks a feature.
package attack

import (
	"sort"
	"sync"
)

// Technique is a compact ATT&CK technique descriptor. Tactic names
// follow MITRE's enterprise-matrix column headers (e.g. "Credential
// Access", "Discovery"). Parent is set for sub-techniques only (e.g.
// T1557.004 has Parent = "T1557").
type Technique struct {
	ID     string `json:"id"`               // "T1040", "T1557.004"
	Name   string `json:"name"`             // "Network Sniffing"
	Tactic string `json:"tactic"`           // "Discovery", "Credential Access", ...
	Parent string `json:"parent,omitempty"` // parent technique ID for sub-techniques
}

// Registry holds the known ATT&CK technique metadata. Safe for
// concurrent reads; Register is rarely called at runtime (typically
// just at package init from builtinTechniques).
type Registry struct {
	mu       sync.RWMutex
	byID     map[string]Technique
	byTactic map[string][]string // tactic → technique IDs
}

// NewRegistry returns an empty Registry. NewDefaultRegistry is the
// typical entry point for production code.
func NewRegistry() *Registry {
	return &Registry{
		byID:     make(map[string]Technique),
		byTactic: make(map[string][]string),
	}
}

// Register adds or replaces a technique entry. Technique IDs are
// unique; re-registering an ID overwrites.
func (r *Registry) Register(t Technique) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byID[t.ID] = t
	r.byTactic[t.Tactic] = appendUnique(r.byTactic[t.Tactic], t.ID)
}

// Lookup returns the technique registered for the given ID, along
// with a found flag. Sub-technique IDs (with a dot) and parent IDs
// both resolve as long as they were registered.
func (r *Registry) Lookup(id string) (Technique, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.byID[id]
	return t, ok
}

// Tactics returns the sorted list of tactic names referenced by any
// registered technique. Useful for the report generator's heatmap
// column layout.
func (r *Registry) Tactics() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.byTactic))
	for tactic := range r.byTactic {
		out = append(out, tactic)
	}
	sort.Strings(out)
	return out
}

// TechniquesForTactic returns technique IDs grouped under a tactic.
func (r *Registry) TechniquesForTactic(tactic string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := r.byTactic[tactic]
	out := make([]string, len(ids))
	copy(out, ids)
	sort.Strings(out)
	return out
}

// Index maps tool names to the ATT&CK techniques they contribute to.
// Lookups are cheap and lock-free after construction.
type Index struct {
	registry *Registry
	byTool   map[string][]string // tool name → technique IDs
	byTech   map[string][]string // technique ID → tool names
}

// NewIndex builds an Index over the supplied Registry using the
// provided mapping. Unknown technique IDs in the mapping are silently
// dropped — logging them noisily at init time would wake operators up
// for a typo in a constant.
func NewIndex(r *Registry, mapping map[string][]string) *Index {
	idx := &Index{
		registry: r,
		byTool:   make(map[string][]string),
		byTech:   make(map[string][]string),
	}
	for tool, ids := range mapping {
		for _, id := range ids {
			if _, ok := r.Lookup(id); !ok {
				continue
			}
			idx.byTool[tool] = appendUnique(idx.byTool[tool], id)
			idx.byTech[id] = appendUnique(idx.byTech[id], tool)
		}
	}
	return idx
}

// TechniquesForTool returns the ATT&CK technique IDs associated with
// the given tool. Empty slice when the tool is untagged — callers
// should treat that as "no contribution to the coverage heatmap"
// rather than as an error.
func (i *Index) TechniquesForTool(tool string) []string {
	ids := i.byTool[tool]
	out := make([]string, len(ids))
	copy(out, ids)
	sort.Strings(out)
	return out
}

// ToolsForTechnique returns the tool names tagged with a technique.
// Useful for a planner that wants to answer "which tools give me
// coverage on T1557.004?".
func (i *Index) ToolsForTechnique(id string) []string {
	names := i.byTech[id]
	out := make([]string, len(names))
	copy(out, names)
	sort.Strings(out)
	return out
}

// Registry returns the underlying technique registry for lookups
// that need more than just the tool mapping.
func (i *Index) Registry() *Registry { return i.registry }

// Techniques returns every technique ID that has at least one tool
// tagged with it, sorted. The report generator uses this to compute
// coverage heatmaps without iterating every technique MITRE publishes.
func (i *Index) Techniques() []string {
	out := make([]string, 0, len(i.byTech))
	for id := range i.byTech {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// appendUnique appends v to dst unless it's already present. Keeps
// slices small enough that a linear scan is the right call.
func appendUnique(dst []string, v string) []string {
	for _, existing := range dst {
		if existing == v {
			return dst
		}
	}
	return append(dst, v)
}

// NewDefaultRegistry returns a Registry populated with the curated set
// of ATT&CK techniques PromptZero's Flipper + Marauder tools can
// execute. Not exhaustive — operators running custom workflows can
// register additional techniques at setup time via Registry.Register.
func NewDefaultRegistry() *Registry {
	r := NewRegistry()
	for _, t := range builtinTechniques {
		r.Register(t)
	}
	return r
}

// NewDefaultIndex returns an Index bound to NewDefaultRegistry with
// the built-in tool → technique mapping installed. The typical entry
// point for the agent and report generator.
func NewDefaultIndex() *Index {
	return NewIndex(NewDefaultRegistry(), builtinToolMap)
}

// builtinTechniques is the curated subset of MITRE ATT&CK techniques
// that PromptZero tools concretely execute. Keep this list alphabetised
// by ID (with sub-techniques following their parent) for readability —
// the tactic assignment is informational and doesn't affect runtime.
//
// References:
//
//	https://attack.mitre.org/techniques/<ID>/
var builtinTechniques = []Technique{
	{ID: "T1018", Name: "Remote System Discovery", Tactic: "Discovery"},
	{ID: "T1040", Name: "Network Sniffing", Tactic: "Discovery"},
	{ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "Execution"},
	{ID: "T1078", Name: "Valid Accounts", Tactic: "Initial Access"},
	{ID: "T1119", Name: "Automated Collection", Tactic: "Collection"},
	{ID: "T1200", Name: "Hardware Additions", Tactic: "Initial Access"},
	{ID: "T1499", Name: "Endpoint Denial of Service", Tactic: "Impact"},
	{ID: "T1552", Name: "Unsecured Credentials", Tactic: "Credential Access"},
	{ID: "T1552.004", Name: "Private Keys", Tactic: "Credential Access", Parent: "T1552"},
	{ID: "T1556", Name: "Modify Authentication Process", Tactic: "Defense Evasion"},
	{ID: "T1557", Name: "Adversary-in-the-Middle", Tactic: "Credential Access"},
	{ID: "T1557.004", Name: "Evil Twin", Tactic: "Credential Access", Parent: "T1557"},
	{ID: "T1562.006", Name: "Impair Defenses: Indicator Blocking", Tactic: "Defense Evasion", Parent: "T1562"},
	{ID: "T1592.004", Name: "Gather Victim Host Information: Client Configurations", Tactic: "Reconnaissance", Parent: "T1592"},
}

// builtinToolMap is the N:M tool → technique mapping. Only tools with
// at least one technique are listed; everything else contributes no
// coverage. Updated as new tool families land (e.g. BLE spam would
// map to T1499, skimmer detection maps nowhere offensive).
//
// Kept alphabetised by tool name for readability.
var builtinToolMap = map[string][]string{
	// Generation pipeline.
	"generate_badusb":      {"T1200", "T1059"},
	"generate_evil_portal": {"T1557.004"},
	"generate_ir":          {"T1200"},
	"generate_nfc":         {"T1556", "T1078"},
	"generate_subghz":      {"T1200"},

	// BadUSB / HID.
	"badusb_run": {"T1200", "T1059"},

	// iButton.
	"ibutton_emulate": {"T1556", "T1078"},
	"ibutton_write":   {"T1556", "T1078"},

	// IR.
	"ir_transmit":     {"T1200"},
	"ir_transmit_raw": {"T1200"},

	// NFC.
	"nfc_emulate":       {"T1556", "T1078"},
	"nfc_mfu_wrbl":      {"T1556", "T1078"},
	"nfc_dump_protocol": {"T1119"},

	// RFID / 125kHz badges.
	"rfid_emulate":     {"T1556", "T1078"},
	"rfid_raw_emulate": {"T1556", "T1078"},
	"rfid_write":       {"T1556", "T1078"},

	// SubGHz.
	"subghz_receive":  {"T1040"},
	"subghz_rx_raw":   {"T1040"},
	"subghz_transmit": {"T1200"},
	"subghz_tx_key":   {"T1200"},

	// WiFi / Marauder.
	"wifi_beacon_clone":        {"T1557.004"},
	"wifi_beacon_random":       {"T1499"},
	"wifi_beacon_spam":         {"T1499"},
	"wifi_deauth":              {"T1499", "T1557"},
	"wifi_deauth_station_list": {"T1499", "T1557"},
	"wifi_evil_portal_start":   {"T1557.004"},
	"wifi_probe_flood":         {"T1499"},
	"wifi_scan_ap":             {"T1018"},
	"wifi_sniff_beacon":        {"T1040"},
	"wifi_sniff_deauth":        {"T1040"},
	"wifi_sniff_pmkid":         {"T1040", "T1552.004"},
	"wifi_sniff_probe":         {"T1040", "T1592.004"},
	"wifi_sniff_raw":           {"T1040"},
	"wifi_sniff_skimmer":       {"T1040"},
}
