package mcpfed

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// ClientConfig describes one external MCP server to federate.
//
// Required fields per transport:
//
//   - stdio: Prefix, Transport="stdio", Command [, Args, Env]
//   - http:  Prefix, Transport="http", URL [, Headers]
//   - sse:   Prefix, Transport="sse",  URL [, Headers]
//
// Env values prefixed with `$` are resolved from the parent process's
// environment at federation startup. A missing `$VAR` is left empty (the
// child server may treat unset as a hard error — that is the server's
// concern).
type ClientConfig struct {
	// Prefix is the tool-name namespace. Lower-case alphanumeric +
	// hyphens, must start with a letter. Required.
	Prefix string `yaml:"prefix"`

	// Transport is "stdio" | "http" | "sse". Required.
	Transport string `yaml:"transport"`

	// Command is the stdio command (e.g. "docker", "python", "uvx").
	Command string `yaml:"command,omitempty"`

	// Args are stdio command-line arguments.
	Args []string `yaml:"args,omitempty"`

	// Env is the stdio child process environment. Values may contain
	// `$VAR` to copy from the parent's env at startup.
	Env map[string]string `yaml:"env,omitempty"`

	// URL is the http/sse base URL.
	URL string `yaml:"url,omitempty"`

	// Headers are static HTTP headers injected by the http/sse client.
	Headers map[string]string `yaml:"headers,omitempty"`

	// Sandbox picks an exec wrapper for stdio transports. Empty defaults
	// to "none". Must be "none" for http/sse.
	Sandbox string `yaml:"sandbox,omitempty"`

	// RiskDefault is the per-tool risk level used when a federated tool
	// carries no MCP annotations to derive from. Empty defaults to
	// "high". One of "low" | "medium" | "high" | "critical".
	RiskDefault string `yaml:"risk_default,omitempty"`

	// InitTimeout caps the time spent on Initialize + ListTools at
	// startup. Zero defaults to 30s.
	InitTimeout time.Duration `yaml:"init_timeout,omitempty"`

	// HealthInterval sets the Ping cadence. Zero defaults to 30s.
	// Negative disables health checks entirely (rely on call-path
	// failure detection only).
	HealthInterval time.Duration `yaml:"health_interval,omitempty"`

	// Disabled skips this entry without removing it from config.
	Disabled bool `yaml:"disabled,omitempty"`
}

// FederationConfig groups multiple federated server entries. Mirrors the
// shape of `mcp_clients:` in the operator's config.yaml.
type FederationConfig struct {
	Clients []ClientConfig `yaml:"mcp_clients,omitempty"`
}

var prefixRe = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// Validate returns an error if the config would not bring up cleanly. Run at
// startup so misconfigurations fail loud before any client spawns.
func (c ClientConfig) Validate() error {
	if c.Prefix == "" {
		return fmt.Errorf("mcpfed: empty prefix")
	}
	if !prefixRe.MatchString(c.Prefix) {
		return fmt.Errorf("mcpfed: invalid prefix %q (must match %s)", c.Prefix, prefixRe.String())
	}

	switch c.Transport {
	case "stdio":
		if c.Command == "" {
			return fmt.Errorf("mcpfed[%s]: stdio transport requires command", c.Prefix)
		}
		if c.URL != "" {
			return fmt.Errorf("mcpfed[%s]: stdio transport must not set url", c.Prefix)
		}
	case "http", "sse":
		if c.URL == "" {
			return fmt.Errorf("mcpfed[%s]: %s transport requires url", c.Prefix, c.Transport)
		}
		if c.Command != "" || len(c.Args) > 0 {
			return fmt.Errorf("mcpfed[%s]: %s transport must not set command/args", c.Prefix, c.Transport)
		}
		if sb := c.normSandbox(); sb != SandboxNone {
			return fmt.Errorf("mcpfed[%s]: %s transport requires sandbox=none, got %q", c.Prefix, c.Transport, sb)
		}
	case "":
		return fmt.Errorf("mcpfed[%s]: missing transport (stdio | http | sse)", c.Prefix)
	default:
		return fmt.Errorf("mcpfed[%s]: unknown transport %q", c.Prefix, c.Transport)
	}

	switch c.normSandbox() {
	case SandboxNone, SandboxDocker, SandboxBwrap, SandboxFirejail:
		// ok
	default:
		return fmt.Errorf("mcpfed[%s]: unknown sandbox %q (allowed: none, docker, bwrap, firejail)",
			c.Prefix, c.Sandbox)
	}

	if r := strings.ToLower(strings.TrimSpace(c.RiskDefault)); r != "" {
		switch r {
		case "low", "medium", "high", "critical":
		default:
			return fmt.Errorf("mcpfed[%s]: invalid risk_default %q (allowed: low, medium, high, critical)",
				c.Prefix, c.RiskDefault)
		}
	}

	return nil
}

// normSandbox returns the parsed Sandbox value, defaulting to SandboxNone.
func (c ClientConfig) normSandbox() Sandbox {
	switch strings.ToLower(strings.TrimSpace(c.Sandbox)) {
	case "", "none":
		return SandboxNone
	case "docker":
		return SandboxDocker
	case "bwrap":
		return SandboxBwrap
	case "firejail":
		return SandboxFirejail
	default:
		// Unknown — return a sentinel that fails Validate. Callers
		// MUST go through Validate before calling normSandbox.
		return Sandbox(-1)
	}
}

// resolveEnv returns the child env in `KEY=VAL` form, expanding `$VAR`
// references against the parent process environment. Variables not present
// in the parent become empty values rather than skipped entries — keeps the
// child's view stable even when an optional secret is missing.
func (c ClientConfig) resolveEnv() []string {
	if len(c.Env) == 0 {
		return nil
	}
	out := make([]string, 0, len(c.Env))
	for k, v := range c.Env {
		if strings.HasPrefix(v, "$") {
			v = os.Getenv(strings.TrimPrefix(v, "$"))
		}
		out = append(out, k+"="+v)
	}
	return out
}

// initTimeout returns the effective initialization timeout, applying the
// 30s default when the field is unset.
func (c ClientConfig) initTimeout() time.Duration {
	if c.InitTimeout <= 0 {
		return 30 * time.Second
	}
	return c.InitTimeout
}

// healthInterval returns (cadence, enabled). A zero field defaults to 30s;
// a negative field disables health checks.
func (c ClientConfig) healthInterval() (time.Duration, bool) {
	switch {
	case c.HealthInterval == 0:
		return 30 * time.Second, true
	case c.HealthInterval < 0:
		return 0, false
	default:
		return c.HealthInterval, true
	}
}
