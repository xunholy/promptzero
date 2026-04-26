package mcpfed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/tools"
)

// ClientBuilder is the constructor signature for a managed client's
// underlying connection. The default implementation routes by
// ClientConfig.Transport (stdio/http/sse). Tests inject custom builders
// to bypass subprocess spawning — see Options.ClientBuilder.
type ClientBuilder func(cfg ClientConfig) (*mcpclient.Client, error)

// MaxNameLen is Anthropic's tool-name length cap. Anthropic enforces
// `^[a-zA-Z0-9_-]{1,64}$`; mcpfed pre-filters longer names rather than
// letting the API reject them at first use.
const MaxNameLen = 64

// NameSeparator joins prefix and remote name, e.g. `secsec__nmap_scan`.
const NameSeparator = "__"

// SpecRegistrar is the surface mcpfed needs from the tools registry. The
// production implementation is tools.Register — a function value type lets
// tests inject a recording fake without resetting the global registry.
type SpecRegistrar func(tools.Spec)

// RiskRegistrar mirrors risk.Register; the same indirection rationale
// applies — keep the package free of init-order side effects on the global
// risk map during tests.
type RiskRegistrar func(toolName string, level risk.Level)

// Options configures a Federation. Zero value is valid: production wiring
// (tools.Register + risk.Register) is selected when fields are nil.
type Options struct {
	// SpecRegistrar overrides the function used to register a Spec.
	// Nil means use tools.Register.
	SpecRegistrar SpecRegistrar

	// RiskRegistrar overrides the function used to publish a tool's
	// risk level. Nil means use risk.Register.
	RiskRegistrar RiskRegistrar

	// Logger is called with informational messages. Nil silences them.
	Logger func(format string, args ...any)

	// ClientBuilder overrides the default transport-routed constructor.
	// Tests inject this to attach an in-process client (mcptest server)
	// without spawning a subprocess. Production wiring leaves it nil.
	ClientBuilder ClientBuilder
}

// Federation owns one or more managed external MCP servers and surfaces
// their tools as native PromptZero Specs.
type Federation struct {
	opts Options

	mu       sync.RWMutex
	clients  map[string]*managedClient // prefix → client
	healthCx context.Context
	healthCn context.CancelFunc
	healthWG sync.WaitGroup
	closed   bool
}

// New returns an empty Federation. Call Start to bring it up.
func New(opts Options) *Federation {
	if opts.SpecRegistrar == nil {
		opts.SpecRegistrar = tools.Register
	}
	if opts.RiskRegistrar == nil {
		opts.RiskRegistrar = risk.Register
	}
	if opts.Logger == nil {
		opts.Logger = func(string, ...any) {}
	}
	if opts.ClientBuilder == nil {
		opts.ClientBuilder = buildClient
	}
	return &Federation{
		opts:    opts,
		clients: map[string]*managedClient{},
	}
}

// Start dials every non-disabled client in cfg, registers their remote
// tools as Specs, and starts background health probes. Failure on a single
// client is non-fatal — the error returned is a multi-error joining every
// client that failed; clients that succeeded are kept and registered.
//
// Start is idempotent in the sense that calling it twice with disjoint
// configs adds the second batch. Calling it twice with overlapping
// prefixes returns an error for the conflicting entries.
func (f *Federation) Start(ctx context.Context, cfg FederationConfig) error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return errors.New("mcpfed: federation closed")
	}
	if f.healthCx == nil {
		f.healthCx, f.healthCn = context.WithCancel(context.Background())
	}
	f.mu.Unlock()

	var errs []error
	for _, c := range cfg.Clients {
		if c.Disabled {
			f.opts.Logger("mcpfed[%s]: disabled, skipping", c.Prefix)
			continue
		}
		if err := c.Validate(); err != nil {
			errs = append(errs, err)
			continue
		}

		f.mu.Lock()
		_, dup := f.clients[c.Prefix]
		f.mu.Unlock()
		if dup {
			errs = append(errs, fmt.Errorf("mcpfed[%s]: prefix already registered", c.Prefix))
			continue
		}

		mc := newManaged(c)
		mc.builder = f.opts.ClientBuilder
		if err := mc.dial(ctx); err != nil {
			errs = append(errs, err)
			_ = mc.close()
			continue
		}

		registered, regErrs := f.registerTools(c, mc)
		if len(regErrs) > 0 {
			errs = append(errs, regErrs...)
		}
		f.opts.Logger("mcpfed[%s]: registered %d/%d tools", c.Prefix, registered, len(mc.remoteTools()))

		f.mu.Lock()
		f.clients[c.Prefix] = mc
		f.mu.Unlock()

		f.healthWG.Add(1)
		go func() {
			defer f.healthWG.Done()
			mc.runHealthLoop(f.healthCx)
		}()
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// Close tears down every managed client and stops health loops. Safe to
// call multiple times. After Close the federation cannot be reused.
func (f *Federation) Close() error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.closed = true
	clients := make([]*managedClient, 0, len(f.clients))
	for _, mc := range f.clients {
		clients = append(clients, mc)
	}
	if f.healthCn != nil {
		f.healthCn()
	}
	f.mu.Unlock()

	f.healthWG.Wait()

	var errs []error
	for _, mc := range clients {
		if err := mc.close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Healthy returns whether the most recent ping for prefix succeeded. False
// for unknown prefixes.
func (f *Federation) Healthy(prefix string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	mc, ok := f.clients[prefix]
	return ok && mc.isHealthy()
}

// Prefixes returns the registered prefixes in undefined order.
func (f *Federation) Prefixes() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]string, 0, len(f.clients))
	for p := range f.clients {
		out = append(out, p)
	}
	return out
}

// registerTools turns each remote mcp.Tool into a tools.Spec and pushes it
// through the configured SpecRegistrar / RiskRegistrar. Returns the number
// successfully registered and any per-tool errors.
func (f *Federation) registerTools(cfg ClientConfig, mc *managedClient) (int, []error) {
	defaultRisk := parseDefaultRisk(cfg.RiskDefault)
	var registered int
	var errs []error
	for _, t := range mc.remoteTools() {
		fullName := cfg.Prefix + NameSeparator + t.Name
		if err := validateName(fullName); err != nil {
			errs = append(errs, fmt.Errorf("mcpfed[%s]: skip tool %q: %w", cfg.Prefix, t.Name, err))
			continue
		}

		level := classify(t, defaultRisk)
		schema := normaliseSchema(t)

		spec := tools.Spec{
			Name:        fullName,
			Description: federatedDescription(cfg.Prefix, t),
			Schema:      schema,
			Required:    extractRequired(t),
			Risk:        level,
			Group:       tools.GroupMetaUtil,
			AgentOnly:   false,
			Handler:     buildHandler(mc, t.Name),
		}

		// tools.Register panics on duplicates — guard with recover so
		// one duplicate (e.g. accidentally federating the same server
		// twice on different prefixes that collide because of a long
		// remote name being truncated) does not take the process out.
		err := safeRegister(f.opts.SpecRegistrar, spec)
		if err != nil {
			errs = append(errs, fmt.Errorf("mcpfed[%s]: register %q: %w", cfg.Prefix, fullName, err))
			continue
		}
		f.opts.RiskRegistrar(fullName, level)
		registered++
	}
	return registered, errs
}

// buildHandler closes over the managedClient to produce the tools.Handler
// that the agent dispatch path will call.
func buildHandler(mc *managedClient, remoteName string) tools.Handler {
	return func(ctx context.Context, _ *tools.Deps, args map[string]any) (string, error) {
		res, err := mc.callTool(ctx, remoteName, args)
		if err != nil {
			return "", err
		}
		return extractText(res)
	}
}

// validateName enforces Anthropic's tool-name shape and length cap before
// the dispatcher ever sees it.
func validateName(s string) error {
	if len(s) == 0 {
		return errors.New("empty tool name")
	}
	if len(s) > MaxNameLen {
		return fmt.Errorf("name %q exceeds %d-char limit", s, MaxNameLen)
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '_', r == '-':
			// ok
		default:
			return fmt.Errorf("name %q contains invalid character %q", s, r)
		}
	}
	return nil
}

// normaliseSchema returns a JSON-encoded copy of the remote tool's input
// schema. Prefers RawInputSchema when populated (preserves arbitrary JSON
// schema features), otherwise marshals the typed InputSchema.
//
// On marshal failure (should not happen for well-formed servers) returns
// a permissive empty-object schema so the spec still registers and can be
// invoked — the server itself is the authoritative validator.
func normaliseSchema(t mcp.Tool) json.RawMessage {
	if len(t.RawInputSchema) > 0 {
		// Copy to keep the registry independent of the remote slice.
		out := make(json.RawMessage, len(t.RawInputSchema))
		copy(out, t.RawInputSchema)
		return out
	}
	if b, err := json.Marshal(t.InputSchema); err == nil {
		return b
	}
	return json.RawMessage(`{"type":"object"}`)
}

// extractRequired pulls the "required" string array out of the input
// schema. Best-effort — agents tolerate a missing or partial required list
// because the registered Schema is the canonical contract.
func extractRequired(t mcp.Tool) []string {
	if len(t.InputSchema.Required) > 0 {
		out := make([]string, len(t.InputSchema.Required))
		copy(out, t.InputSchema.Required)
		return out
	}
	if len(t.RawInputSchema) > 0 {
		var probe struct {
			Required []string `json:"required"`
		}
		if err := json.Unmarshal(t.RawInputSchema, &probe); err == nil {
			return probe.Required
		}
	}
	return nil
}

// federatedDescription renders the tool description with a `[mcpfed:<prefix>]`
// hint so the agent's prompt cache can distinguish federated tools from
// native ones at a glance.
func federatedDescription(prefix string, t mcp.Tool) string {
	desc := strings.TrimSpace(t.Description)
	if desc == "" {
		return fmt.Sprintf("[mcpfed:%s] %s", prefix, t.Name)
	}
	return fmt.Sprintf("[mcpfed:%s] %s", prefix, desc)
}

// safeRegister catches the panic that tools.Register raises on duplicates
// and converts it into an error.
func safeRegister(reg SpecRegistrar, spec tools.Spec) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	reg(spec)
	return nil
}
