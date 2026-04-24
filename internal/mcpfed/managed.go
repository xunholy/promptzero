package mcpfed

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	mcpclient "github.com/mark3labs/mcp-go/client"
	mcptransport "github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
)

// managedClient wraps an mcp-go *Client with respawn semantics. Each
// federated MCP server gets one managedClient owned by the [Federation].
//
// The wrapper centralises:
//
//   - lazy lifecycle (client may be nil between dial attempts)
//   - one-shot retry on transport failures during CallTool
//   - background health pings + observable healthy() state
//   - clean shutdown that interrupts in-flight calls cleanly
type managedClient struct {
	cfg ClientConfig

	// builder constructs the underlying client. nil means use the
	// package-level buildClient. Tests override this to attach an
	// in-process client.
	builder func(ClientConfig) (*mcpclient.Client, error)

	mu     sync.Mutex
	client *mcpclient.Client // nil when not connected
	tools  []mcp.Tool        // captured at last successful Initialize

	healthy atomic.Bool
	stopCh  chan struct{}
	stopped atomic.Bool
}

func newManaged(cfg ClientConfig) *managedClient {
	return &managedClient{cfg: cfg, stopCh: make(chan struct{})}
}

// dial spawns the underlying client, runs Initialize, and captures the
// remote tool list. Idempotent: redialing while connected first closes
// the existing client.
func (m *managedClient) dial(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dialLocked(ctx)
}

func (m *managedClient) dialLocked(ctx context.Context) error {
	if m.stopped.Load() {
		return errors.New("mcpfed: client is closed")
	}

	// Tear down any prior client first — dialLocked is also called by
	// the call-path retry, where the existing client has already
	// errored and must not leak.
	if m.client != nil {
		_ = m.client.Close()
		m.client = nil
	}

	build := m.builder
	if build == nil {
		build = buildClient
	}
	cli, err := build(m.cfg)
	if err != nil {
		m.healthy.Store(false)
		return fmt.Errorf("mcpfed[%s]: build client: %w", m.cfg.Prefix, err)
	}

	initCtx, cancel := context.WithTimeout(ctx, m.cfg.initTimeout())
	defer cancel()

	if err := cli.Start(initCtx); err != nil {
		_ = cli.Close()
		m.healthy.Store(false)
		return fmt.Errorf("mcpfed[%s]: start: %w", m.cfg.Prefix, err)
	}

	initReq := mcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcp.Implementation{
		Name:    "promptzero-mcpfed",
		Version: "0",
	}
	if _, err := cli.Initialize(initCtx, initReq); err != nil {
		_ = cli.Close()
		m.healthy.Store(false)
		return fmt.Errorf("mcpfed[%s]: initialize: %w", m.cfg.Prefix, err)
	}

	listRes, err := cli.ListTools(initCtx, mcp.ListToolsRequest{})
	if err != nil {
		_ = cli.Close()
		m.healthy.Store(false)
		return fmt.Errorf("mcpfed[%s]: list tools: %w", m.cfg.Prefix, err)
	}

	m.client = cli
	m.tools = listRes.Tools
	m.healthy.Store(true)
	return nil
}

// callTool invokes the named remote tool with one transparent retry on
// transport failure (subprocess died, HTTP closed, etc.). The retry pays
// the dial cost only on actual loss — happy-path latency is unchanged.
func (m *managedClient) callTool(ctx context.Context, name string, args map[string]any) (*mcp.CallToolResult, error) {
	res, err := m.callOnce(ctx, name, args)
	if err == nil {
		return res, nil
	}
	if !isTransportClosed(err) {
		return nil, err
	}

	// Transport closed mid-call. Redial and retry once.
	m.healthy.Store(false)
	if rerr := m.dial(ctx); rerr != nil {
		return nil, fmt.Errorf("mcpfed[%s]: call %q: redial after transport-closed: %w (original: %v)",
			m.cfg.Prefix, name, rerr, err)
	}
	res, err = m.callOnce(ctx, name, args)
	if err != nil {
		return nil, fmt.Errorf("mcpfed[%s]: call %q: retry after transport-closed: %w", m.cfg.Prefix, name, err)
	}
	return res, nil
}

func (m *managedClient) callOnce(ctx context.Context, name string, args map[string]any) (*mcp.CallToolResult, error) {
	m.mu.Lock()
	cli := m.client
	m.mu.Unlock()
	if cli == nil {
		return nil, errors.New("mcpfed: client not connected")
	}
	req := mcp.CallToolRequest{}
	req.Params.Name = name
	req.Params.Arguments = args
	return cli.CallTool(ctx, req)
}

// runHealthLoop pings the remote server on the configured cadence, marking
// the client unhealthy on a failed ping but not respawning — the next
// callTool will redial via the transport-closed retry path.
func (m *managedClient) runHealthLoop(ctx context.Context) {
	cadence, enabled := m.cfg.healthInterval()
	if !enabled {
		return
	}
	t := time.NewTicker(cadence)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-t.C:
			m.mu.Lock()
			cli := m.client
			m.mu.Unlock()
			if cli == nil {
				m.healthy.Store(false)
				continue
			}
			pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := cli.Ping(pingCtx)
			cancel()
			if err != nil {
				m.healthy.Store(false)
			} else {
				m.healthy.Store(true)
			}
		}
	}
}

func (m *managedClient) close() error {
	if !m.stopped.CompareAndSwap(false, true) {
		return nil
	}
	close(m.stopCh)

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.client == nil {
		return nil
	}
	err := m.client.Close()
	m.client = nil
	m.healthy.Store(false)
	return err
}

// isHealthy reports whether the most recent dial / ping succeeded.
func (m *managedClient) isHealthy() bool { return m.healthy.Load() }

// remoteTools returns a copy of the tool list captured at last dial.
func (m *managedClient) remoteTools() []mcp.Tool {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]mcp.Tool, len(m.tools))
	copy(out, m.tools)
	return out
}

// buildClient constructs the appropriate mcp-go client per transport.
//
// nolint:cyclop // routes by transport, naturally three branches.
func buildClient(cfg ClientConfig) (*mcpclient.Client, error) {
	switch cfg.Transport {
	case "stdio":
		// transport.WithCommandFunc lets us wrap exec.Cmd construction
		// for sandboxing. The mcp-go API requires us to also pass the
		// command name and args at construction time even when a
		// custom CommandFunc handles spawning — under the hood it's
		// the CommandFunc that actually shapes the *exec.Cmd.
		opts := []mcptransport.StdioOption{
			mcptransport.WithCommandFunc(commandFunc(cfg.normSandbox())),
		}
		return mcpclient.NewStdioMCPClientWithOptions(
			cfg.Command, cfg.resolveEnv(), cfg.Args, opts...,
		)

	case "http":
		var opts []mcptransport.StreamableHTTPCOption
		if len(cfg.Headers) > 0 {
			opts = append(opts, mcptransport.WithHTTPHeaders(cfg.Headers))
		}
		return mcpclient.NewStreamableHttpClient(cfg.URL, opts...)

	case "sse":
		var opts []mcptransport.ClientOption
		if len(cfg.Headers) > 0 {
			opts = append(opts, mcptransport.WithHeaders(cfg.Headers))
		}
		return mcpclient.NewSSEMCPClient(cfg.URL, opts...)

	default:
		return nil, fmt.Errorf("mcpfed: unsupported transport %q", cfg.Transport)
	}
}

// isTransportClosed identifies errors that warrant a redial on the call
// path. mcp-go does not export a dedicated sentinel for "the underlying
// pipe died"; the closest signal is transport.ErrTransportClosed (when
// the SendRequest path observes a closed connection). Heuristic textual
// matches catch a few looser variants: stdio EOF, broken pipe, and the
// HTTP transport's "use of closed network connection".
func isTransportClosed(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, mcptransport.ErrTransportClosed) {
		return true
	}
	s := err.Error()
	for _, marker := range []string{
		"transport closed",
		"connection closed",
		"broken pipe",
		"use of closed network connection",
		"EOF",
	} {
		if containsFold(s, marker) {
			return true
		}
	}
	return false
}

func containsFold(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if equalFoldFast(haystack[i:i+len(needle)], needle) {
			return true
		}
	}
	return false
}

func equalFoldFast(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
