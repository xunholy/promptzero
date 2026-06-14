package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	toolsreg "github.com/xunholy/promptzero/internal/tools"
)

// agentOnlyAllowlist is the documented set of registry tools deliberately
// hidden from the MCP surface, each with a reason. This is the parity contract:
// a tool may be AgentOnly ONLY if it is listed here. Adding `AgentOnly: true` to
// a new Spec without justifying it here fails TestMCPParity_AgentOnlyAllowlist,
// which forces an explicit decision rather than a silent MCP capability gap.
//
// Reason codes:
//   - llm-gen: needs Deps.Generator (LLM), which the MCP server leaves nil.
//   - workflow: multi-step agent-loop orchestration, not a single tool call.
//   - rag: needs Deps.RAG (retrieval), not wired in MCP.
//   - vision: needs Deps.Vision, not wired in MCP.
//   - agent-state: depends on live agent-session state (last result / target memory).
//   - config: needs Deps.Config (user device-name mappings), not wired in MCP.
//   - active-device: long-running / active hardware session (sniff / brute / sweep / on-device save).
var agentOnlyAllowlist = map[string]string{ //nolint:gochecknoglobals
	"generate_badusb":            "llm-gen",
	"generate_deploy_run":        "llm-gen",
	"generate_evil_portal":       "llm-gen",
	"generate_ir":                "llm-gen",
	"generate_nfc":               "llm-gen",
	"generate_subghz":            "llm-gen",
	"run_payload":                "llm-gen",
	"ir_build":                   "llm-gen",
	"nfc_build":                  "llm-gen",
	"rfid_build":                 "llm-gen",
	"subghz_build":               "llm-gen",
	"subghz_bruteforce_generate": "llm-gen",

	"workflow_badusb_target_profile":  "workflow",
	"workflow_mousejack":              "workflow",
	"workflow_nfc_badge_pipeline":     "workflow",
	"workflow_rolljam_lab_demo":       "workflow",
	"workflow_wifi_target_to_hashcat": "workflow",

	"discover_apps": "rag",
	"docs_search":   "rag",

	"analyze_image": "vision",

	"explain_last_result": "agent-state",
	"target_remember":     "agent-state",
	"target_recall":       "agent-state",
	"target_forget":       "agent-state",

	"list_devices": "config",

	"nrf24_sniff_start":     "active-device",
	"nrf24_mousejack_start": "active-device",
	"nrf24_list_targets":    "active-device",
	"nrf24_payload_build":   "active-device",
	"ir_bruteforce":         "active-device",
	"subghz_bruteforce":     "active-device",
	"subghz_freq_sweep":     "active-device",
	"nfc_read_save":         "active-device",
}

// TestMCPParity_NonAgentOnlyExposed is the core parity guard: every non-AgentOnly
// registry tool MUST be reachable over MCP. If a new tool is added and silently
// fails to register on the MCP surface, this fails.
func TestMCPParity_NonAgentOnlyExposed(t *testing.T) {
	s := NewServer(nil, nil)
	exposed := make(map[string]bool)
	for _, n := range s.ToolNames() {
		exposed[n] = true
	}
	var missing []string
	for _, spec := range toolsreg.All() {
		if spec.AgentOnly {
			continue
		}
		if !exposed[spec.Name] {
			missing = append(missing, spec.Name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d non-AgentOnly tools are NOT exposed over MCP (parity gap): %v", len(missing), missing)
	}
}

// TestMCPParity_AgentOnlyAllowlist enforces that every AgentOnly tool is
// documented in agentOnlyAllowlist (forward), and that the allowlist has no
// stale entries (reverse). A new AgentOnly tool must justify its MCP exclusion.
func TestMCPParity_AgentOnlyAllowlist(t *testing.T) {
	for _, spec := range toolsreg.All() {
		if spec.AgentOnly {
			if _, ok := agentOnlyAllowlist[spec.Name]; !ok {
				t.Errorf("tool %q is AgentOnly (hidden from MCP) but not in agentOnlyAllowlist — "+
					"add it with a reason, or remove AgentOnly to expose it over MCP", spec.Name)
			}
		}
	}
	for name := range agentOnlyAllowlist {
		spec, ok := toolsreg.Get(name)
		if !ok {
			t.Errorf("agentOnlyAllowlist names %q which is not a registered tool — remove it", name)
			continue
		}
		if !spec.AgentOnly {
			t.Errorf("agentOnlyAllowlist names %q but it is no longer AgentOnly — remove it from the allowlist", name)
		}
	}
}

// TestOptsFromSchema_PreservesEnumArrayRequired guards the MCP schema-translation
// fidelity fix: enum constraints, array element types, and required flags must
// survive the JSON-Schema -> MCP-tool-input-schema conversion.
func TestOptsFromSchema_PreservesEnumArrayRequired(t *testing.T) {
	schema := []byte(`{"type":"object","properties":{
		"format":{"type":"string","enum":["json","csv"],"description":"output format"},
		"tags":{"type":"array","items":{"type":"string"},"description":"labels"}
	}}`)
	opts := optsFromSchema(schema, []string{"format"})
	tool := mcp.NewTool("t", opts...)
	raw, err := json.Marshal(tool)
	if err != nil {
		t.Fatalf("marshal tool: %v", err)
	}
	got := string(raw)
	for _, want := range []string{
		`"enum":["json","csv"]`,     // enum forwarded
		`"items":{"type":"string"}`, // array element type forwarded
		`"required":["format"]`,     // required preserved
	} {
		if !strings.Contains(got, want) {
			t.Errorf("MCP input schema missing %s\nfull schema: %s", want, got)
		}
	}
}

// TestOptsFromSchema_NonStringEnumKeepsProperty ensures a non-string enum does
// not error the whole property out (the enum is skipped, the property survives).
func TestOptsFromSchema_NonStringEnumKeepsProperty(t *testing.T) {
	schema := []byte(`{"type":"object","properties":{
		"n":{"type":"integer","enum":[1,2,3],"description":"choice"}
	}}`)
	opts := optsFromSchema(schema, nil)
	if len(opts) != 1 {
		t.Fatalf("expected the integer-enum property to be registered, got %d opts", len(opts))
	}
	tool := mcp.NewTool("t", opts...)
	raw, _ := json.Marshal(tool)
	if !strings.Contains(string(raw), `"n"`) {
		t.Errorf("integer-enum property dropped: %s", string(raw))
	}
}
