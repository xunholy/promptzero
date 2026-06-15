package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/xunholy/promptzero/internal/config"
	toolsreg "github.com/xunholy/promptzero/internal/tools"
)

// TestSetConfig_FlowsToDeps guards that the MCP server's Config wiring reaches
// the tool Deps, so config-backed tools (list_devices) work over MCP.
func TestSetConfig_FlowsToDeps(t *testing.T) {
	s := NewServer(nil, nil)
	cfg := &config.Config{}
	s.SetConfig(cfg)
	if s.deps().Config != cfg {
		t.Error("SetConfig did not flow to deps().Config — config-backed tools would be inert over MCP")
	}
}

// TestMCPParity_AllToolsExposed is the core parity guard: EVERY registry tool
// MUST be reachable over MCP. Discoverability is universal — nothing is hidden;
// risk is handled by the consent gate in add(), not by concealment. If a new
// tool is added and silently fails to register on the MCP surface (or someone
// reintroduces an exposure filter), this fails. AgentOnly is advisory metadata
// only and does NOT exempt a tool from exposure.
func TestMCPParity_AllToolsExposed(t *testing.T) {
	s := NewServer(nil, nil)
	exposed := make(map[string]bool)
	for _, n := range s.ToolNames() {
		exposed[n] = true
	}
	var missing []string
	for _, spec := range toolsreg.All() {
		if !exposed[spec.Name] {
			missing = append(missing, spec.Name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d registry tools are NOT exposed over MCP (parity gap — every tool must be reachable): %v",
			len(missing), missing)
	}
}

// TestMCPParity_AgentOnlyStillExposed guards the inversion: tools flagged
// AgentOnly (advisory: needs agent-mode deps to function fully) must STILL be
// exposed over MCP — the flag is informational, never an exposure gate. This
// pins the "nothing undiscoverable" contract against a regression that re-couples
// AgentOnly to exposure.
func TestMCPParity_AgentOnlyStillExposed(t *testing.T) {
	s := NewServer(nil, nil)
	exposed := make(map[string]bool)
	for _, n := range s.ToolNames() {
		exposed[n] = true
	}
	var agentOnlyCount int
	for _, spec := range toolsreg.All() {
		if !spec.AgentOnly {
			continue
		}
		agentOnlyCount++
		if !exposed[spec.Name] {
			t.Errorf("AgentOnly tool %q is not exposed over MCP — AgentOnly is advisory, not an exposure gate", spec.Name)
		}
	}
	if agentOnlyCount == 0 {
		t.Error("no AgentOnly tools found — expected several advisory-flagged tools; test wiring may be broken")
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
