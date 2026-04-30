// Package mcp exposes PromptZero's tool surface over the Model Context
// Protocol (stdio transport). Started by `promptzero --mcp` and intended
// to be plugged into MCP clients like Claude Desktop or Claude Code as a
// local tool server.
//
// Every registered tool carries risk metadata derived from
// internal/risk.Classify, surfaced to the client as MCP annotations
// (readOnlyHint, destructiveHint, openWorldHint). Operators can use those
// hints to gate destructive calls in their MCP client.
//
// # Risk consent gate
//
// Tools at risk.High or risk.Critical are refused by default. Set the
// following environment variables to opt in:
//
//   - PROMPTZERO_MCP_ALLOW_HIGH=1     — permits risk.High tool calls.
//   - PROMPTZERO_MCP_ALLOW_CRITICAL=1 — permits risk.Critical tool calls
//     (implies High is also permitted).
//
// Denied calls are still recorded in the audit log (if wired) so the
// operator has a full record of attempted MCP tool invocations.
//
// # MCP resources
//
// Built-in wordlists are exposed as static MCP resources so clients can
// introspect their contents before invoking hash_crack_dictionary or
// http_enum_common:
//
//   - promptzero://wordlists/common.txt   — ~500-entry HTTP common-paths list
//   - promptzero://wordlists/passwords.txt — ~100-entry common-password list
//
// # _confirmed ↔ Risk-tier equivalence (for MCP client integrations)
//
// Some reference MCPs (e.g. pm3-mcp) require a `{"_confirmed": true}` arg
// on every destructive tool call. PromptZero uses a different mechanism:
// the Spec.Risk field and the corresponding MCP tool annotations. The
// equivalence table is:
//
//	pm3-mcp tier    →  PromptZero Risk      →  MCP annotations
//	read-only       →  Low                  →  readOnlyHint:true,   destructiveHint:false
//	allowed-write   →  Medium               →  readOnlyHint:false,  destructiveHint:false
//	approval-write  →  High / Critical      →  readOnlyHint:false,  destructiveHint:true
//
// MCP clients (Claude Desktop, Claude Code) can gate Critical-tier calls
// using their built-in auto-approve settings keyed on destructiveHint:true.
// No `_confirmed` arg is added to PromptZero schemas — enforcement is
// at the client layer via annotations, not schema validation.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/xunholy/promptzero/internal/audit"
	"github.com/xunholy/promptzero/internal/bruce"
	"github.com/xunholy/promptzero/internal/buspirate"
	"github.com/xunholy/promptzero/internal/faultier"
	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/marauder"
	"github.com/xunholy/promptzero/internal/persona"
	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/snapshot"
	toolsreg "github.com/xunholy/promptzero/internal/tools"
	"github.com/xunholy/promptzero/internal/wordlists"
)

// Server is the stdio MCP server wrapping a connected Flipper and
// optional Marauder sidecar.
type Server struct {
	flipper   *flipper.Flipper
	marauder  *marauder.Marauder
	bruce     *bruce.Client
	faultier  *faultier.Client
	busPirate *buspirate.Client
	audit     *audit.Log
	snapshot  *snapshot.Manager
	// workflowConfirm is intentionally nil in MCP mode: sub-tool confirm
	// gates auto-approve when no hook is installed (see gateSubtool).
	workflowConfirm func(ctx context.Context, tool string, input any, riskLevel string) bool
	srv             *mcpserver.MCPServer
	tools           []string
	prompts         []string
	resources       []string
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
		// Enable resource capabilities so built-in wordlists are introspectable.
		// subscribe=false (no per-resource subscription), listChanged=false
		// (static wordlists never change at runtime).
		mcpserver.WithResourceCapabilities(false, false),
	)

	s.registerFromRegistry()
	s.registerPersonaPrompts()
	s.registerWordlistResources()

	return s
}

// SetAuditLog wires an audit log so every MCP tool call (including
// consent-denied ones) is recorded. Call before ServeStdio.
func (s *Server) SetAuditLog(l *audit.Log) { s.audit = l }

// SetBruce wires an optional Bruce devboard so bruce_* handlers do not
// short-circuit with "not connected" in MCP mode.
func (s *Server) SetBruce(b *bruce.Client) { s.bruce = b }

// SetFaultier wires an optional Faultier glitcher so faultier_* handlers
// do not short-circuit with "not connected" in MCP mode.
func (s *Server) SetFaultier(f *faultier.Client) { s.faultier = f }

// SetBusPirate wires an optional Bus Pirate 5 so buspirate_* handlers do
// not short-circuit with "not connected" in MCP mode.
func (s *Server) SetBusPirate(bp *buspirate.Client) { s.busPirate = bp }

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

// ResourceNames returns the list of registered MCP resource URIs.
func (s *Server) ResourceNames() []string {
	out := make([]string, len(s.resources))
	copy(out, s.resources)
	return out
}

// ServeStdio starts the server on the process's stdin/stdout pair. Blocks
// until the client disconnects or the process is signalled.
func (s *Server) ServeStdio() error {
	// Surface the risk-consent policy on startup so it's never implicit.
	// High/Critical tools are refused by default; operators opt in via env.
	fmt.Fprintln(os.Stderr, "\x1b[33m●\x1b[0m MCP mode: risk≥High tools refused by default — set PROMPTZERO_MCP_ALLOW_HIGH=1 / PROMPTZERO_MCP_ALLOW_CRITICAL=1 to permit (all calls are audited)")
	return mcpserver.ServeStdio(s.srv)
}

// add registers a tool against the underlying MCP server. The handler is
// wrapped with argument unmarshalling, required-field validation, risk
// consent gating, and risk-based MCP annotations.
//
// Risk consent gate: tools at risk.High are refused unless
// PROMPTZERO_MCP_ALLOW_HIGH=1; tools at risk.Critical are refused unless
// PROMPTZERO_MCP_ALLOW_CRITICAL=1. Denied calls are still audited.
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

	// Capture loop variables for the closure.
	capturedLevel := level
	capturedName := name

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

		levelStr := capturedLevel.String()

		// Risk consent gate: refuse risk≥High unless the operator has
		// opted in via environment variable. Always audit the attempt.
		if capturedLevel == risk.Critical && os.Getenv("PROMPTZERO_MCP_ALLOW_CRITICAL") != "1" {
			if s.audit != nil {
				s.audit.RecordCtx(ctx, capturedName, args, "", levelStr, audit.LevelAction, 0, false)
			}
			return mcp.NewToolResultError(
				"tool requires consent — set PROMPTZERO_MCP_ALLOW_CRITICAL=1 to allow critical-risk MCP calls (audit will still record)",
			), nil
		}
		if capturedLevel == risk.High && os.Getenv("PROMPTZERO_MCP_ALLOW_HIGH") != "1" {
			if s.audit != nil {
				s.audit.RecordCtx(ctx, capturedName, args, "", levelStr, audit.LevelAction, 0, false)
			}
			return mcp.NewToolResultError(
				"tool requires consent — set PROMPTZERO_MCP_ALLOW_HIGH=1 to allow high-risk MCP calls (audit will still record)",
			), nil
		}

		start := time.Now()
		result, herr := handler(ctx, args)
		dur := time.Since(start)

		success := herr == nil
		output := result
		if herr != nil {
			output = herr.Error()
		}
		if s.audit != nil {
			s.audit.RecordCtx(ctx, capturedName, args, output, levelStr, audit.LevelAction, dur, success)
		}

		if herr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("error: %v", herr)), nil
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

// --- Registration: built-in wordlist resources ---

// registerWordlistResources exposes the embedded wordlists as MCP resources
// under the promptzero://wordlists/ scheme. MCP clients can read these
// resources to inspect available word lists before invoking
// hash_crack_dictionary or http_enum_common with the built-in wordlists.
//
// Registered resources:
//   - promptzero://wordlists/common.txt   — HTTP common-paths wordlist (CC0)
//   - promptzero://wordlists/passwords.txt — common-password wordlist (CC0)
func (s *Server) registerWordlistResources() {
	type entry struct {
		uri     string
		name    string
		desc    string
		content func() string
	}

	entries := []entry{
		{
			uri:  "promptzero://wordlists/common.txt",
			name: "common.txt",
			desc: "Built-in HTTP common-paths wordlist (~500 entries, CC0-1.0). " +
				"Pass 'promptzero://wordlists/common.txt' as the wordlist argument " +
				"to http_enum_common to use this list.",
			content: wordlists.CommonRaw,
		},
		{
			uri:  "promptzero://wordlists/passwords.txt",
			name: "passwords.txt",
			desc: "Built-in common-password wordlist (~100 entries, CC0-1.0). " +
				"Pass 'promptzero://wordlists/passwords.txt' as the wordlist argument " +
				"to hash_crack_dictionary to use this list.",
			content: wordlists.PasswordsRaw,
		},
	}

	for _, e := range entries {
		e := e // capture loop variable
		resource := mcp.NewResource(
			e.uri,
			e.name,
			mcp.WithResourceDescription(e.desc),
			mcp.WithMIMEType("text/plain"),
		)
		s.srv.AddResource(resource, func(_ context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			return []mcp.ResourceContents{
				mcp.TextResourceContents{
					URI:      req.Params.URI,
					MIMEType: "text/plain",
					Text:     e.content(),
				},
			}, nil
		})
		s.resources = append(s.resources, e.uri)
	}
}

// --- Registry adapter ---

// registerFromRegistry wires every non-AgentOnly Spec from the central
// tool registry into the MCP server. This is the sole registration path
// after Wave 5 — all legacy s.add() calls were removed during the
// migration waves.
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

// deps returns a Deps bag populated with the transports the MCP server
// has access to. LLM-specific fields (Generator, Vision, RAG, etc.) are
// nil — only non-AgentOnly handlers are called through this path, so
// they must degrade gracefully on nil fields.
func (s *Server) deps() *toolsreg.Deps {
	return &toolsreg.Deps{
		Flipper:         s.flipper,
		Marauder:        s.marauder,
		Bruce:           s.bruce,
		Faultier:        s.faultier,
		BusPirate:       s.busPirate,
		Audit:           s.audit,
		Snapshot:        s.snapshot,
		WorkflowConfirm: s.workflowConfirm,
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
