package mcp

import (
	"bytes"
	"context"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/xunholy/promptzero/internal/testmocks"
)

// newTestHarness builds a Server against mocked devices and wires its
// stdio transport to an in-memory MCP client. Caller gets back the
// initialised client and the Server for introspection.
func newTestHarness(t *testing.T, withMarauder bool, flipperOpts ...testmocks.MockFlipperOption) (*client.Client, *Server) {
	t.Helper()

	flip := testmocks.NewMockFlipper(t, flipperOpts...)

	var s *Server
	if withMarauder {
		s = NewServer(flip, testmocks.NewMockMarauder(t))
	} else {
		s = NewServer(flip, nil)
	}

	serverIn, clientOut := io.Pipe()
	clientIn, serverOut := io.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	stdio := mcpserver.NewStdioServer(s.MCPServer())
	stdio.SetErrorLogger(log.New(&bytes.Buffer{}, "", 0))

	go func() {
		_ = stdio.Listen(ctx, serverIn, serverOut)
	}()

	trans := transport.NewIO(clientIn, clientOut, io.NopCloser(bytes.NewReader(nil)))
	if err := trans.Start(ctx); err != nil {
		t.Fatalf("transport start: %v", err)
	}
	t.Cleanup(func() { _ = trans.Close() })

	c := client.NewClient(trans)

	initCtx, initCancel := context.WithTimeout(ctx, 5*time.Second)
	defer initCancel()
	var init mcplib.InitializeRequest
	init.Params.ProtocolVersion = mcplib.LATEST_PROTOCOL_VERSION
	init.Params.ClientInfo = mcplib.Implementation{Name: "mcp-test", Version: "0"}
	if _, err := c.Initialize(initCtx, init); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	return c, s
}

func TestServer_ListTools_AdvertisesFullSurface(t *testing.T) {
	c, s := newTestHarness(t, true)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.ListTools(ctx, mcplib.ListToolsRequest{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	got := map[string]mcplib.Tool{}
	for _, tl := range resp.Tools {
		got[tl.Name] = tl
	}

	// Check a representative slice: one per major category. If any of
	// these go missing the tool surface has regressed — the catalogue
	// shouldn't shrink silently.
	mustHave := []string{
		// Core Flipper primitives
		"device_info",
		"nfc_detect",
		"subghz_receive",
		"storage_list",
		"ir_decode_file", // Phase-1 primitive
		"storage_copy",   // Phase-1 primitive
		"js_run",         // Phase-1 primitive, fork-gated
		// File-format + validator (Phase-5)
		"fileformat_read",
		"badusb_validate",
		// Workflow (Phase-3)
		"workflow_hw_recon_blackbox_device",
		// Marauder tool, only present when --wifi is active
		"wifi_scan_ap",
	}

	for _, name := range mustHave {
		if _, ok := got[name]; !ok {
			t.Errorf("tools/list missing required tool %q", name)
		}
	}

	// Confirm the Server's internal toolNames matches what the client sees.
	if len(s.ToolNames()) != len(resp.Tools) {
		t.Errorf("ToolNames() len=%d, ListTools returned %d", len(s.ToolNames()), len(resp.Tools))
	}
}

func TestServer_ToolAnnotations_FlagRiskLevel(t *testing.T) {
	c, _ := newTestHarness(t, false)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.ListTools(ctx, mcplib.ListToolsRequest{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	idx := map[string]mcplib.Tool{}
	for _, tl := range resp.Tools {
		idx[tl.Name] = tl
	}

	// Low-risk read-only: device_info should be marked readOnly, not
	// destructive.
	if tl, ok := idx["device_info"]; ok {
		if tl.Annotations.ReadOnlyHint == nil || !*tl.Annotations.ReadOnlyHint {
			t.Errorf("device_info: expected readOnlyHint=true, got %+v", tl.Annotations)
		}
		if tl.Annotations.DestructiveHint != nil && *tl.Annotations.DestructiveHint {
			t.Errorf("device_info: expected destructiveHint=false")
		}
	} else {
		t.Fatal("device_info missing from tools/list")
	}

	// High-risk destructive: subghz_transmit actively RFs.
	if tl, ok := idx["subghz_transmit"]; ok {
		if tl.Annotations.DestructiveHint == nil || !*tl.Annotations.DestructiveHint {
			t.Errorf("subghz_transmit: expected destructiveHint=true")
		}
		if tl.Annotations.ReadOnlyHint != nil && *tl.Annotations.ReadOnlyHint {
			t.Errorf("subghz_transmit: expected readOnlyHint=false")
		}
	} else {
		t.Fatal("subghz_transmit missing from tools/list")
	}

	// Critical destructive: flipper_raw_cli is an unrestricted passthrough.
	if tl, ok := idx["flipper_raw_cli"]; ok {
		if tl.Annotations.DestructiveHint == nil || !*tl.Annotations.DestructiveHint {
			t.Errorf("flipper_raw_cli: expected destructiveHint=true")
		}
	} else {
		t.Fatal("flipper_raw_cli missing from tools/list")
	}

	// Title annotation embeds the classified risk level so the MCP client
	// picker can show it at a glance.
	if tl, ok := idx["subghz_transmit"]; ok {
		if !strings.Contains(tl.Annotations.Title, "high") {
			t.Errorf("subghz_transmit title should contain risk level, got %q", tl.Annotations.Title)
		}
	}
}

func TestServer_CallTool_DeviceInfo(t *testing.T) {
	c, _ := newTestHarness(t, false)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var req mcplib.CallToolRequest
	req.Params.Name = "device_info"

	res, err := c.CallTool(ctx, req)
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("device_info returned IsError=true: %+v", res.Content)
	}
	text := firstText(t, res)
	if !strings.Contains(text, "Flipper Zero") {
		t.Errorf("device_info output should contain the mock's banner, got %q", text)
	}
}

func TestServer_CallTool_MissingRequiredArg(t *testing.T) {
	c, _ := newTestHarness(t, false)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// storage_list requires a "path" argument. Call it with none and
	// assert we get a structured error result back (not a transport
	// crash).
	var req mcplib.CallToolRequest
	req.Params.Name = "storage_list"
	req.Params.Arguments = map[string]any{}

	res, err := c.CallTool(ctx, req)
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected IsError=true for missing path arg, got %+v", res.Content)
	}
	text := firstText(t, res)
	if !strings.Contains(text, "missing required argument") || !strings.Contains(text, "path") {
		t.Errorf("expected missing-required-argument error naming 'path', got %q", text)
	}
}

func TestServer_CallTool_HighRiskSubGHzReceive(t *testing.T) {
	// Risk-High call path: subghz_receive (wait, receive is Medium).
	// Pick subghz_transmit which is unambiguously High. Under MCP the
	// server currently auto-executes every call — the startup banner on
	// stderr tells operators to trust their client. This test pins that
	// behaviour: destructive tools execute, but the destructiveHint
	// annotation stays surfaced so the MCP client can gate client-side.
	c, _ := newTestHarness(t, false, testmocks.WithFlipperHandler("subghz", func(args []string) string {
		return "tx complete"
	}))
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var req mcplib.CallToolRequest
	req.Params.Name = "subghz_transmit"
	req.Params.Arguments = map[string]any{"file": "/ext/subghz/test.sub"}

	res, err := c.CallTool(ctx, req)
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("subghz_transmit returned IsError=true: %+v", res.Content)
	}
	text := firstText(t, res)
	if !strings.Contains(text, "tx complete") {
		t.Errorf("expected tx handler output, got %q", text)
	}
}

func TestServer_CallTool_UnknownTool(t *testing.T) {
	c, _ := newTestHarness(t, false)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var req mcplib.CallToolRequest
	req.Params.Name = "does_not_exist"

	res, err := c.CallTool(ctx, req)
	// mcp-go returns the error via the CallToolResult (IsError=true), not
	// the top-level error. Accept either shape so this test survives a
	// library change.
	if err == nil && res != nil && !res.IsError {
		t.Fatalf("expected error for unknown tool, got success %+v", res)
	}
}

func TestServer_ListPrompts_PersonasAdvertised(t *testing.T) {
	c, _ := newTestHarness(t, false)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.ListPrompts(ctx, mcplib.ListPromptsRequest{})
	if err != nil {
		t.Fatalf("ListPrompts: %v", err)
	}

	wantSubstrs := []string{"persona_default", "persona_rf-recon", "persona_badge-cloner"}
	names := make([]string, 0, len(resp.Prompts))
	for _, p := range resp.Prompts {
		names = append(names, p.Name)
	}
	for _, want := range wantSubstrs {
		found := false
		for _, got := range names {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("prompt %q missing from prompts/list (got %v)", want, names)
		}
	}
}

func TestServer_GetPrompt_ReturnsSystemPrompt(t *testing.T) {
	c, _ := newTestHarness(t, false)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var req mcplib.GetPromptRequest
	req.Params.Name = "persona_rf-recon"
	res, err := c.GetPrompt(ctx, req)
	if err != nil {
		t.Fatalf("GetPrompt: %v", err)
	}
	if len(res.Messages) == 0 {
		t.Fatalf("expected at least one prompt message, got none")
	}
	txt, ok := mcplib.AsTextContent(res.Messages[0].Content)
	if !ok {
		t.Fatalf("expected TextContent, got %T", res.Messages[0].Content)
	}
	if !strings.Contains(txt.Text, "RF-RECON") {
		t.Errorf("rf-recon persona prompt should mention the mode name, got %q", txt.Text)
	}
}

// firstText extracts the first TextContent from a CallToolResult. Fails
// the test if no text content is present.
func firstText(t *testing.T, res *mcplib.CallToolResult) string {
	t.Helper()
	for _, c := range res.Content {
		if tc, ok := mcplib.AsTextContent(c); ok {
			return tc.Text
		}
	}
	t.Fatalf("no text content in result: %+v", res.Content)
	return ""
}
