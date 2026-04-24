// Package mcp exposes PromptZero's tool surface over the Model Context
// Protocol (stdio transport). Started by `promptzero --mcp` and intended
// to be plugged into MCP clients like Claude Desktop or Claude Code as a
// local tool server.
//
// Every registered tool carries risk metadata derived from
// internal/risk.Classify, surfaced to the client as MCP annotations
// (readOnlyHint, destructiveHint, openWorldHint). Operators can use those
// hints to gate destructive calls in their MCP client.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/marauder"
	"github.com/xunholy/promptzero/internal/persona"
	"github.com/xunholy/promptzero/internal/risk"
	toolsreg "github.com/xunholy/promptzero/internal/tools"
	"github.com/xunholy/promptzero/internal/workflows"
)

// Server is the stdio MCP server wrapping a connected Flipper and
// optional Marauder sidecar.
type Server struct {
	flipper  *flipper.Flipper
	marauder *marauder.Marauder
	srv      *mcpserver.MCPServer
	tools    []string
	prompts  []string
}

type toolHandler func(ctx context.Context, args map[string]interface{}) (string, error)

// NewServer builds the MCP server and registers every tool compatible
// with the connected devices. The Marauder parameter may be nil; when
// absent, WiFi tools are not advertised.
func NewServer(f *flipper.Flipper, m *marauder.Marauder) *Server {
	s := &Server{flipper: f, marauder: m}

	s.srv = mcpserver.NewMCPServer(
		"promptzero",
		"1.0.0",
		mcpserver.WithToolCapabilities(true),
		mcpserver.WithPromptCapabilities(false),
	)

	s.registerWorkflowTools()
	s.registerFromRegistry()
	s.registerPersonaPrompts()

	return s
}

// MCPServer returns the underlying mcp-go server. Exposed so tests can
// attach alternate transports (e.g. in-process pipes) without going
// through the stdio wiring.
func (s *Server) MCPServer() *mcpserver.MCPServer { return s.srv }

// ToolNames returns the list of registered tool names in registration
// order.
func (s *Server) ToolNames() []string {
	out := make([]string, len(s.tools))
	copy(out, s.tools)
	return out
}

// PromptNames returns the list of registered prompt names.
func (s *Server) PromptNames() []string {
	out := make([]string, len(s.prompts))
	copy(out, s.prompts)
	return out
}

// ServeStdio starts the server on the process's stdin/stdout pair. Blocks
// until the client disconnects or the process is signalled.
func (s *Server) ServeStdio() error {
	// MCP has no shell to prompt on; every tool executes immediately.
	// Surface that trust boundary on startup so it's never implicit.
	fmt.Fprintln(os.Stderr, "\x1b[33m●\x1b[0m MCP mode: all tools execute without confirmation — trust your MCP client")
	return mcpserver.ServeStdio(s.srv)
}

// add registers a tool against the underlying MCP server. The handler is
// wrapped with argument unmarshalling, required-field validation, and
// risk-based MCP annotations. Required field names are the subset of opts
// that callers must supply — they are validated in addition to any
// schema-level Required() markers already attached to opts.
func (s *Server) add(name, desc string, opts []mcp.ToolOption, required []string, handler toolHandler) {
	level := risk.Classify(name)

	readOnly := level == risk.Low
	destructive := level >= risk.High
	openWorld := level != risk.Low

	annotations := []mcp.ToolOption{
		mcp.WithDescription(desc),
		mcp.WithTitleAnnotation(fmt.Sprintf("%s (%s)", name, level.String())),
		mcp.WithReadOnlyHintAnnotation(readOnly),
		mcp.WithDestructiveHintAnnotation(destructive),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(openWorld),
	}
	allOpts := append(annotations, opts...)
	tool := mcp.NewTool(name, allOpts...)

	s.srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, err := decodeArgs(req)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
		}
		if missing := missingRequired(args, required); len(missing) > 0 {
			return mcp.NewToolResultError(
				fmt.Sprintf("missing required argument(s): %s", strings.Join(missing, ", ")),
			), nil
		}
		result, err := handler(ctx, args)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("error: %v", err)), nil
		}
		return mcp.NewToolResultText(result), nil
	})
	s.tools = append(s.tools, name)
}

func decodeArgs(req mcp.CallToolRequest) (map[string]interface{}, error) {
	args := map[string]interface{}{}
	if req.Params.Arguments == nil {
		return args, nil
	}
	data, err := json.Marshal(req.Params.Arguments)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &args); err != nil {
		return nil, err
	}
	return args, nil
}

func missingRequired(args map[string]interface{}, required []string) []string {
	var missing []string
	for _, name := range required {
		v, ok := args[name]
		if !ok {
			missing = append(missing, name)
			continue
		}
		switch t := v.(type) {
		case string:
			if strings.TrimSpace(t) == "" {
				missing = append(missing, name)
			}
		case nil:
			missing = append(missing, name)
		}
	}
	return missing
}

// --- Registration: workflows (Flipper-only composites) ---

func (s *Server) registerWorkflowTools() {
	deps := workflows.Deps{
		Flipper:  s.flipper,
		Marauder: s.marauder,
	}

	s.add("workflow_hw_recon_blackbox_device",
		"Recon an unknown PCB on the GPIO header: i2c_scan, onewire_search, GPIO sweep, bt_hci_info, device_info. Read-only.",
		[]mcp.ToolOption{mcp.WithArray("gpios", mcp.Description("Optional pin list override"))},
		nil,
		func(ctx context.Context, a map[string]interface{}) (string, error) {
			return workflows.HWReconBlackbox(ctx, deps, a)
		})

	s.add("workflow_garage_door_triage",
		"Scan common garage/gate/car-remote Sub-GHz frequencies and decode captures. Receive-only.",
		[]mcp.ToolOption{
			mcp.WithArray("frequencies", mcp.Description("Frequency list in Hz (default: 7 common bands)")),
			mcp.WithNumber("per_freq_seconds", mcp.Description("Seconds per frequency (default 5)")),
		},
		nil,
		func(ctx context.Context, a map[string]interface{}) (string, error) {
			return workflows.GarageDoorTriage(ctx, deps, a)
		})

	s.add("workflow_phys_pentest_badge_walk",
		"Continuous RFID + NFC + iButton census, dedup unique UIDs, write CSV to SD card.",
		[]mcp.ToolOption{
			mcp.WithNumber("duration_seconds", mcp.Description("Total walk duration (default 300)")),
			mcp.WithNumber("dedupe_window_seconds", mcp.Description("Dedupe window (default 0 = forever)")),
			mcp.WithString("csv_path", mcp.Description("Destination CSV path")),
		},
		nil,
		func(ctx context.Context, a map[string]interface{}) (string, error) {
			return workflows.PhysPentestBadgeWalk(ctx, deps, a)
		})
}

// --- Registration: persona prompts ---

// registerPersonaPrompts advertises each built-in persona as an MCP prompt
// so MCP clients (Claude Desktop, Claude Code) can surface them in their
// slash-command picker. Returning the persona's system prompt as a user
// message lets the downstream model adopt the operator mode without
// PromptZero needing to stream the mode switch itself.
func (s *Server) registerPersonaPrompts() {
	reg := persona.NewRegistry()
	for _, name := range reg.Names() {
		pp, ok := reg.Get(name)
		if !ok {
			continue
		}
		captured := *pp
		promptName := "persona_" + captured.Name
		prompt := mcp.NewPrompt(promptName, mcp.WithPromptDescription(captured.Description))
		s.srv.AddPrompt(prompt, func(_ context.Context, _ mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			return &mcp.GetPromptResult{
				Description: captured.Description,
				Messages: []mcp.PromptMessage{{
					Role:    mcp.RoleUser,
					Content: mcp.NewTextContent(captured.SystemPrompt),
				}},
			}, nil
		})
		s.prompts = append(s.prompts, promptName)
	}
}

// --- Registry adapter ---

// registerFromRegistry wires every non-AgentOnly Spec from the central
// tool registry into the MCP server. This is the adapter that bridges
// internal/tools into the MCP host. Called from NewServer after the
// legacy register* chain so that, during Waves 0-4, the registry-backed
// tools are registered without the legacy s.add() calls that were
// removed in the same wave commit.
func (s *Server) registerFromRegistry() {
	for _, spec := range toolsreg.All() {
		if spec.AgentOnly {
			continue
		}
		opts := optsFromSchema(spec.Schema, spec.Required)
		names := append([]string{spec.Name}, spec.Aliases...)
		for _, name := range names {
			specCopy := spec
			nameCopy := name
			s.add(nameCopy, specCopy.Description, opts, specCopy.Required,
				func(ctx context.Context, args map[string]interface{}) (string, error) {
					return specCopy.Handler(ctx, s.deps(), args)
				})
		}
	}
}

// deps returns a Deps bag populated with only the transports the MCP
// server has access to. The LLM-specific fields (Generator, Vision,
// Snapshot, etc.) are nil — only non-AgentOnly handlers are called
// through this path, so they must degrade gracefully on nil fields.
func (s *Server) deps() *toolsreg.Deps {
	return &toolsreg.Deps{
		Flipper:  s.flipper,
		Marauder: s.marauder,
	}
}

// optsFromSchema converts a JSON Schema object into mcp.ToolOption entries.
// Only top-level property types are handled: string, integer, number,
// boolean, array, object. Properties listed in required get mcp.Required().
func optsFromSchema(schema []byte, required []string) []mcp.ToolOption {
	if len(schema) == 0 {
		return nil
	}
	var s struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(schema, &s); err != nil || len(s.Properties) == 0 {
		return nil
	}
	reqSet := make(map[string]bool, len(required))
	for _, r := range required {
		reqSet[r] = true
	}
	var opts []mcp.ToolOption
	for name, propRaw := range s.Properties {
		var prop struct {
			Type        string `json:"type"`
			Description string `json:"description"`
		}
		if err := json.Unmarshal(propRaw, &prop); err != nil {
			continue
		}
		var propOpts []mcp.PropertyOption
		propOpts = append(propOpts, mcp.Description(prop.Description))
		if reqSet[name] {
			propOpts = append(propOpts, mcp.Required())
		}
		switch prop.Type {
		case "string":
			opts = append(opts, mcp.WithString(name, propOpts...))
		case "integer", "number":
			opts = append(opts, mcp.WithNumber(name, propOpts...))
		case "boolean":
			opts = append(opts, mcp.WithBoolean(name, propOpts...))
		case "array":
			opts = append(opts, mcp.WithArray(name, propOpts...))
		case "object":
			opts = append(opts, mcp.WithObject(name, propOpts...))
		}
	}
	return opts
}
