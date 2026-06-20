package mcpfed

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/tools"
)

// fakeRegistrar captures Specs registered by the federation so tests can
// assert against the result without touching the global tools registry.
type fakeRegistrar struct {
	mu    sync.Mutex
	specs []tools.Spec
}

func (f *fakeRegistrar) Register(s tools.Spec) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.specs = append(f.specs, s)
}

func (f *fakeRegistrar) ByName(name string) (tools.Spec, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.specs {
		if s.Name == name {
			return s, true
		}
	}
	return tools.Spec{}, false
}

// startMCPServer brings up an in-process MCP server with the given tools and
// returns a builder that hands a connected in-process client back to mcpfed.
// The cleanup func tears down the server when the test ends.
func startMCPServer(t *testing.T, tools ...server.ServerTool) (ClientBuilder, func()) {
	t.Helper()
	srv := server.NewMCPServer("test-mcpfed", "1.0", server.WithToolCapabilities(false))
	srv.SetTools(tools...)

	builder := func(_ ClientConfig) (*mcpclient.Client, error) {
		return mcpclient.NewInProcessClient(srv)
	}
	return builder, func() {}
}

// helloTool is a simple read-only tool that echoes its `name` argument.
func helloTool() server.ServerTool {
	tool := mcp.Tool{
		Name:        "hello",
		Description: "Say hello",
		InputSchema: mcp.ToolInputSchema{
			Type:       "object",
			Properties: map[string]any{"name": map[string]any{"type": "string"}},
			Required:   []string{"name"},
		},
		Annotations: mcp.ToolAnnotation{ReadOnlyHint: boolPtr(true)},
	}
	return server.ServerTool{
		Tool: tool,
		Handler: func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			name, _ := req.Params.Arguments.(map[string]any)["name"].(string)
			return &mcp.CallToolResult{
				Content: []mcp.Content{mcp.TextContent{Type: "text", Text: "hello " + name}},
			}, nil
		},
	}
}

// destructiveTool is annotated DestructiveHint=true so mcpfed should
// classify it as Critical regardless of RiskDefault.
func destructiveTool() server.ServerTool {
	tool := mcp.Tool{
		Name:        "drop_db",
		Description: "Wipe a database",
		InputSchema: mcp.ToolInputSchema{Type: "object"},
		Annotations: mcp.ToolAnnotation{DestructiveHint: boolPtr(true)},
	}
	return server.ServerTool{
		Tool: tool,
		Handler: func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{
				Content: []mcp.Content{mcp.TextContent{Type: "text", Text: "ok"}},
			}, nil
		},
	}
}

// erroringTool returns IsError=true so mcpfed should surface this as a Go error.
func erroringTool() server.ServerTool {
	tool := mcp.Tool{
		Name:        "always_fail",
		Description: "Always returns isError",
		InputSchema: mcp.ToolInputSchema{Type: "object"},
	}
	return server.ServerTool{
		Tool: tool,
		Handler: func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{mcp.TextContent{Type: "text", Text: "synthetic failure"}},
			}, nil
		},
	}
}

func TestFederation_StartRegistersTools(t *testing.T) {
	builder, cleanup := startMCPServer(t, helloTool(), destructiveTool())
	defer cleanup()

	reg := &fakeRegistrar{}
	captured := map[string]risk.Level{}
	var rmu sync.Mutex
	risks := func(name string, lvl risk.Level) {
		rmu.Lock()
		captured[name] = lvl
		rmu.Unlock()
	}

	fed := New(Options{
		SpecRegistrar: reg.Register,
		RiskRegistrar: risks,
		ClientBuilder: builder,
	})
	defer fed.Close()

	cfg := FederationConfig{
		Clients: []ClientConfig{
			{Prefix: "test", Transport: "stdio", Command: "ignored", RiskDefault: "high"},
		},
	}
	if err := fed.Start(context.Background(), cfg); err != nil {
		t.Fatalf("Start: %v", err)
	}

	hello, ok := reg.ByName("test__hello")
	if !ok {
		t.Fatalf("hello tool not registered. specs=%v", names(reg.specs))
	}
	if hello.Risk != risk.Low {
		t.Errorf("hello risk = %v, want Low (ReadOnlyHint=true)", hello.Risk)
	}
	if !strings.Contains(hello.Description, "[mcpfed:test]") {
		t.Errorf("hello description missing prefix tag: %q", hello.Description)
	}
	if len(hello.Required) != 1 || hello.Required[0] != "name" {
		t.Errorf("hello required = %v, want [name]", hello.Required)
	}

	drop, ok := reg.ByName("test__drop_db")
	if !ok {
		t.Fatalf("drop_db not registered")
	}
	if drop.Risk != risk.Critical {
		t.Errorf("drop_db risk = %v, want Critical (DestructiveHint=true)", drop.Risk)
	}

	rmu.Lock()
	if captured["test__hello"] != risk.Low {
		t.Errorf("risks captured for hello = %v, want Low", captured["test__hello"])
	}
	if captured["test__drop_db"] != risk.Critical {
		t.Errorf("risks captured for drop_db = %v, want Critical", captured["test__drop_db"])
	}
	rmu.Unlock()
}

func TestFederation_HandlerCallsRemote(t *testing.T) {
	builder, cleanup := startMCPServer(t, helloTool())
	defer cleanup()

	reg := &fakeRegistrar{}
	fed := New(Options{
		SpecRegistrar: reg.Register,
		RiskRegistrar: func(string, risk.Level) {},
		ClientBuilder: builder,
	})
	defer fed.Close()

	cfg := FederationConfig{Clients: []ClientConfig{
		{Prefix: "test", Transport: "stdio", Command: "x"},
	}}
	if err := fed.Start(context.Background(), cfg); err != nil {
		t.Fatalf("Start: %v", err)
	}

	spec, ok := reg.ByName("test__hello")
	if !ok {
		t.Fatalf("hello not registered")
	}

	out, err := spec.Handler(context.Background(), nil, map[string]any{"name": "world"})
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if out != "hello world" {
		t.Errorf("handler output = %q, want %q", out, "hello world")
	}
}

func TestFederation_HandlerSurfacesIsError(t *testing.T) {
	builder, cleanup := startMCPServer(t, erroringTool())
	defer cleanup()

	reg := &fakeRegistrar{}
	fed := New(Options{
		SpecRegistrar: reg.Register,
		RiskRegistrar: func(string, risk.Level) {},
		ClientBuilder: builder,
	})
	defer fed.Close()

	cfg := FederationConfig{Clients: []ClientConfig{
		{Prefix: "test", Transport: "stdio", Command: "x"},
	}}
	if err := fed.Start(context.Background(), cfg); err != nil {
		t.Fatalf("Start: %v", err)
	}

	spec, ok := reg.ByName("test__always_fail")
	if !ok {
		t.Fatalf("always_fail not registered")
	}

	_, err := spec.Handler(context.Background(), nil, nil)
	if err == nil {
		t.Fatalf("expected error from IsError tool")
	}
	if !strings.Contains(err.Error(), "synthetic failure") {
		t.Errorf("error did not include body: %v", err)
	}
}

func TestFederation_DuplicatePrefixRejected(t *testing.T) {
	builder, cleanup := startMCPServer(t, helloTool())
	defer cleanup()

	reg := &fakeRegistrar{}
	fed := New(Options{
		SpecRegistrar: reg.Register,
		RiskRegistrar: func(string, risk.Level) {},
		ClientBuilder: builder,
	})
	defer fed.Close()

	cfg := FederationConfig{Clients: []ClientConfig{
		{Prefix: "test", Transport: "stdio", Command: "x"},
		{Prefix: "test", Transport: "stdio", Command: "x"},
	}}
	err := fed.Start(context.Background(), cfg)
	if err == nil {
		t.Fatalf("expected error for duplicate prefix")
	}
	if !strings.Contains(err.Error(), "already registered") {
		t.Errorf("err = %v, want 'already registered'", err)
	}
}

func TestFederation_DisabledSkipped(t *testing.T) {
	builder, cleanup := startMCPServer(t, helloTool())
	defer cleanup()

	reg := &fakeRegistrar{}
	fed := New(Options{
		SpecRegistrar: reg.Register,
		RiskRegistrar: func(string, risk.Level) {},
		ClientBuilder: builder,
	})
	defer fed.Close()

	cfg := FederationConfig{Clients: []ClientConfig{
		{Prefix: "test", Transport: "stdio", Command: "x", Disabled: true},
	}}
	if err := fed.Start(context.Background(), cfg); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if len(reg.specs) != 0 {
		t.Errorf("disabled entry registered specs anyway: %v", names(reg.specs))
	}
}

func TestFederation_InvalidPrefixDropped(t *testing.T) {
	builder, cleanup := startMCPServer(t, helloTool())
	defer cleanup()

	reg := &fakeRegistrar{}
	fed := New(Options{
		SpecRegistrar: reg.Register,
		RiskRegistrar: func(string, risk.Level) {},
		ClientBuilder: builder,
	})
	defer fed.Close()

	cfg := FederationConfig{Clients: []ClientConfig{
		{Prefix: "BAD", Transport: "stdio", Command: "x"},
	}}
	err := fed.Start(context.Background(), cfg)
	if err == nil {
		t.Fatalf("expected validation error")
	}
}

func TestFederation_CloseStopsHealth(t *testing.T) {
	builder, cleanup := startMCPServer(t, helloTool())
	defer cleanup()

	reg := &fakeRegistrar{}
	fed := New(Options{
		SpecRegistrar: reg.Register,
		RiskRegistrar: func(string, risk.Level) {},
		ClientBuilder: builder,
	})

	cfg := FederationConfig{Clients: []ClientConfig{
		{Prefix: "test", Transport: "stdio", Command: "x", HealthInterval: 10 * time.Millisecond},
	}}
	if err := fed.Start(context.Background(), cfg); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Sleep longer than 1 health tick so the loop has run at least once.
	time.Sleep(50 * time.Millisecond)
	if !fed.Healthy("test") {
		t.Errorf("expected healthy=true after successful initial dial")
	}

	if err := fed.Close(); err != nil {
		t.Errorf("Close error: %v", err)
	}
	// Second close is a no-op.
	if err := fed.Close(); err != nil {
		t.Errorf("second Close error: %v", err)
	}
}

func TestFederation_BuilderError(t *testing.T) {
	reg := &fakeRegistrar{}
	fed := New(Options{
		SpecRegistrar: reg.Register,
		RiskRegistrar: func(string, risk.Level) {},
		ClientBuilder: func(_ ClientConfig) (*mcpclient.Client, error) {
			return nil, errors.New("forced builder failure")
		},
	})
	defer fed.Close()

	cfg := FederationConfig{Clients: []ClientConfig{
		{Prefix: "test", Transport: "stdio", Command: "x"},
	}}
	err := fed.Start(context.Background(), cfg)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "forced builder failure") {
		t.Errorf("err = %v, want propagated builder error", err)
	}
}

func TestValidateName(t *testing.T) {
	cases := map[string]bool{ // input -> wantValid
		"":                                false,
		"ok":                              true,
		"with-dash":                       true,
		"with_underscore":                 true,
		"prefix__remote":                  true,
		"contains.dot":                    false,
		"contains space":                  false,
		strings.Repeat("a", MaxNameLen):   true,
		strings.Repeat("a", MaxNameLen+1): false,
	}
	for name, wantValid := range cases {
		err := validateName(name)
		if wantValid && err != nil {
			t.Errorf("validateName(%q) = %v, want valid", name, err)
		}
		if !wantValid && err == nil {
			t.Errorf("validateName(%q) = nil, want error", name)
		}
	}
}

func names(ss []tools.Spec) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = s.Name
	}
	return out
}

// hangingTool blocks until its call context is cancelled — a stand-in for a
// remote server that initialised fine but stalls on a specific tool call.
func hangingTool() server.ServerTool {
	tool := mcp.Tool{
		Name:        "hang",
		Description: "Blocks until the call context is cancelled",
		InputSchema: mcp.ToolInputSchema{Type: "object"},
	}
	return server.ServerTool{
		Tool: tool,
		Handler: func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
}

// TestManagedClient_CallTimeout pins the per-call timeout: a federated tool
// call to a stalled remote must return an error promptly (bounded by
// CallTimeout) instead of hanging the agent turn for as long as the caller's
// context allows.
func TestManagedClient_CallTimeout(t *testing.T) {
	builder, cleanup := startMCPServer(t, hangingTool())
	defer cleanup()

	m := newManaged(ClientConfig{Prefix: "t", CallTimeout: 100 * time.Millisecond})
	m.builder = builder
	if err := m.dial(context.Background()); err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = m.close() }()

	start := time.Now()
	_, err := m.callTool(context.Background(), "hang", map[string]any{})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("callTool to a stalled remote returned nil — expected a timeout error")
	}
	if elapsed > 5*time.Second {
		t.Errorf("callTool took %s — the 100ms CallTimeout was not enforced (it hung)", elapsed)
	}
}
