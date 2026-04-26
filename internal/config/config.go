package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// redactKey masks a secret key for display. It shows the last 4 characters
// prefixed with "...". Keys shorter than 8 characters are replaced entirely
// with "redacted" so we never leak a short secret verbatim.
func redactKey(k string) string {
	if len(k) < 8 {
		return "redacted"
	}
	return "..." + k[len(k)-4:]
}

// String implements fmt.Stringer so that %v and %s formatting never prints
// APIKey or OpenAIKey in plaintext.
func (c Config) String() string {
	apiKey := "(unset)"
	if c.APIKey != "" {
		apiKey = redactKey(c.APIKey)
	}
	openAIKey := "(unset)"
	if c.OpenAIKey != "" {
		openAIKey = redactKey(c.OpenAIKey)
	}
	return fmt.Sprintf("Config{APIKey:%s OpenAIKey:%s Model:%s}", apiKey, openAIKey, c.Model)
}

// GoString implements fmt.GoStringer so that %#v formatting never prints
// APIKey or OpenAIKey in plaintext.
func (c Config) GoString() string {
	return c.String()
}

type Config struct {
	APIKey        string              `yaml:"api_key"`
	OpenAIKey     string              `yaml:"openai_api_key"`
	Model         string              `yaml:"model"`
	Serial        SerialConfig        `yaml:"serial"`
	Marauder      MarauderConfig      `yaml:"marauder"`
	Bruce         BruceConfig         `yaml:"bruce,omitempty"`
	Faultier      FaultierConfig      `yaml:"faultier,omitempty"`
	BusPirate     BusPirateConfig     `yaml:"buspirate,omitempty"`
	Companion     CompanionConfig     `yaml:"companion,omitempty"`
	Flipper       FlipperConfig       `yaml:"flipper,omitempty"`
	Agent         AgentConfig         `yaml:"agent,omitempty"`
	Web           WebConfig           `yaml:"web"`
	Devices       map[string]Device   `yaml:"devices"`
	ConfirmRisk   string              `yaml:"confirm_risk,omitempty"`
	Persona       string              `yaml:"persona,omitempty"`
	Watch         WatchConfig         `yaml:"watch,omitempty"`
	Webhooks      []WebhookConfig     `yaml:"webhooks,omitempty"`
	Observability ObservabilityConfig `yaml:"observability,omitempty"`
	Validator     ValidatorConfig     `yaml:"validator,omitempty"`
	Rules         []RuleConfig        `yaml:"rules,omitempty"`
	Cost          CostConfig          `yaml:"cost,omitempty"`

	// MCPClients is the raw YAML for outbound MCP federation entries
	// (internal/mcpfed). Stored as []yaml.Node so config.go has no
	// dependency on the mcpfed package — mcpfed.ParseClientConfigs
	// decodes each node into its own ClientConfig type.
	MCPClients []yaml.Node `yaml:"mcp_clients,omitempty"`
}

// BruceConfig configures the optional Bruce ESP32 backend
// (BruceDevices/firmware — Cardputer/M5Stick/T-Display/CYD/ESP32-C5).
// Empty Port disables the backend; the agent runs Flipper-only.
type BruceConfig struct {
	Port      string `yaml:"port,omitempty"`        // /dev/ttyACM1, COM4, etc.
	Baud      int    `yaml:"baud,omitempty"`        // default 115200
	BoardType string `yaml:"board_type,omitempty"`  // hint: cardputer | m5stick | tdisplay | cyd | c5
}

// FaultierConfig configures the optional hextreeio Faultier USB
// voltage-glitcher.
type FaultierConfig struct {
	Port string `yaml:"port,omitempty"`
	Baud int    `yaml:"baud,omitempty"`  // default 115200
}

// BusPirateConfig configures the optional Bus Pirate 5 universal-bus
// probe (DangerousPrototypes/BusPirate5-firmware).
type BusPirateConfig struct {
	Port string `yaml:"port,omitempty"`
	Baud int    `yaml:"baud,omitempty"`  // default 115200
}

// CompanionConfig configures the optional on-device PromptZero
// Companion FAP integration. The host writes status events to a
// JSON file on the Flipper SD card; the FAP reads and renders them
// so the operator sees what the agent is doing without looking at
// the laptop.
//
// Defaults are auto: when Enabled is nil, the host probes the SD
// card for the FAP at startup and wires the sink only if found.
// Setting Enabled=true with no FAP installed produces a warning;
// Enabled=false skips the probe entirely.
type CompanionConfig struct {
	// Enabled overrides the auto-detect default. nil = auto-detect
	// (preferred). true = require the FAP and warn if missing.
	// false = disable even if the FAP is installed.
	Enabled *bool `yaml:"enabled,omitempty"`
	// StatusPath overrides the SD-card path where the status file
	// is written. Empty uses companion.DefaultStatusPath.
	StatusPath string `yaml:"status_path,omitempty"`
	// AutoIdleAfter is how long after the last tool finish to push
	// an Idle event so the FAP returns to a "ready" header. Zero
	// uses 1.5s. Set to a negative value to disable auto-idle (the
	// FAP keeps showing the last Done state until the next turn).
	AutoIdleAfter time.Duration `yaml:"auto_idle_after,omitempty"`
}

// FlipperConfig holds per-operation timeout overrides for the Flipper
// serial layer. Zero values fall back to the hard-coded defaults (10s).
type FlipperConfig struct {
	// ExecTimeout overrides the 10 s per-command read deadline in ExecCtx.
	ExecTimeout time.Duration `yaml:"exec_timeout,omitempty"`
	// WriteFileTimeout overrides the 10 s post-payload read deadline in
	// WriteFileCtx.
	WriteFileTimeout time.Duration `yaml:"write_file_timeout,omitempty"`
}

// AgentConfig holds agent-level tunables that can be overridden via the
// config file. Zero values fall back to the hard-coded defaults.
type AgentConfig struct {
	// ConfirmIdleTimeout overrides the 5 m idle-confirmation timeout. When
	// the operator walks away without answering a confirmation prompt the
	// agent treats silence as a deny after this duration.
	ConfirmIdleTimeout time.Duration `yaml:"confirm_idle_timeout,omitempty"`
}

// ObservabilityConfig tunes the slog handler and Prometheus /metrics
// endpoint. LogFile, when non-empty, is opened append-mode alongside the
// stderr handler so operators keep local tailing while landing a log on
// disk. MetricsEnabled + MetricsPath control the /metrics route on the
// web server — note the surface is not auth-gated, same as the rest of
// the web UI.
type ObservabilityConfig struct {
	LogLevel       string `yaml:"log_level,omitempty"`
	LogFormat      string `yaml:"log_format,omitempty"`
	LogFile        string `yaml:"log_file,omitempty"`
	MetricsEnabled bool   `yaml:"metrics_enabled,omitempty"`
	MetricsPath    string `yaml:"metrics_path,omitempty"`
}

// ValidatorConfig gates the BadUSB sandbox validator. Disable with
// Enabled=false to run scripts unchecked (not recommended). AllowCritical
// lets critical findings through after logging — mainly for operators
// who know what they're doing and accept the risk. WarnAction picks
// between "warn" (log + run) and "block" (refuse) when warn findings
// surface.
type ValidatorConfig struct {
	BadUSB BadUSBValidatorConfig `yaml:"badusb,omitempty"`
}

// BadUSBValidatorConfig is the per-validator knob set for DuckyScript
// static analysis.
type BadUSBValidatorConfig struct {
	Enabled       *bool  `yaml:"enabled,omitempty"`
	AllowCritical bool   `yaml:"allow_critical,omitempty"`
	WarnAction    string `yaml:"warn_action,omitempty"`
}

// RuleConfig is the YAML round-trip shape for one reactive rule. See
// internal/rules for the runtime surface. Cooldown uses the standard
// Go duration format ("30s", "1m", "2h"); empty means no cooldown.
type RuleConfig struct {
	Name        string             `yaml:"name"`
	Description string             `yaml:"description,omitempty"`
	When        RuleMatchConfig    `yaml:"when"`
	Then        []RuleActionConfig `yaml:"then"`
	Cooldown    string             `yaml:"cooldown,omitempty"`
	Enabled     *bool              `yaml:"enabled,omitempty"`
}

// RuleMatchConfig defines audit-entry matching. Non-empty fields are
// ANDed; empty fields are wildcards. Tool supports a trailing "*" glob
// ("workflow_*") as a common convenience.
type RuleMatchConfig struct {
	Tool           string `yaml:"tool,omitempty"`
	Risk           string `yaml:"risk,omitempty"`
	Level          string `yaml:"level,omitempty"`
	OutputContains string `yaml:"output_contains,omitempty"`
}

// RuleActionConfig is one step in a rule's Then list. Type picks the
// handler; the other fields are consumed depending on the type.
type RuleActionConfig struct {
	Type    string                 `yaml:"type"`
	Tool    string                 `yaml:"tool,omitempty"`
	Params  map[string]interface{} `yaml:"params,omitempty"`
	Webhook string                 `yaml:"webhook,omitempty"`
}

// CostConfig lets operators override the built-in per-model USD rate
// table. Missing entries fall back to the package defaults in
// internal/cost; entries present here shadow those.
type CostConfig struct {
	Rates map[string]CostRateConfig `yaml:"rates,omitempty"`
}

// CostRateConfig is one pricing entry. InputPerMTok and OutputPerMTok
// are USD per million tokens.
type CostRateConfig struct {
	Input  float64 `yaml:"input"`
	Output float64 `yaml:"output"`
}

// WebhookConfig is one HTTP webhook subscription. Empty Events means "all
// events". Secret, when non-empty, enables HMAC-SHA256 body signing via
// the X-PromptZero-Signature header. See internal/webhook for the runtime
// surface this feeds.
type WebhookConfig struct {
	Name    string            `yaml:"name"`
	URL     string            `yaml:"url"`
	Events  []string          `yaml:"events,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty"`
	Secret  string            `yaml:"secret,omitempty"`
}

// WatchConfig configures the --watch filesystem-trigger mode. Paths is the
// list of directories (or specific files) to observe. Rules describe how
// individual files within those paths map to prompts fed into the agent.
type WatchConfig struct {
	Enabled bool        `yaml:"enabled,omitempty"`
	Paths   []string    `yaml:"paths,omitempty"`
	Rules   []WatchRule `yaml:"rules,omitempty"`
}

// WatchRule is a single pattern -> prompt mapping. Pattern uses
// filepath.Match syntax ("*.sub", "*.png", etc.) matched against the file's
// basename. Prompt is templated with {{path}}, {{dir}}, {{name}}, {{ext}}
// at fire time. Persona, when set, overrides the active persona for the
// duration of the FS-triggered turn.
type WatchRule struct {
	Pattern string `yaml:"pattern"`
	Prompt  string `yaml:"prompt"`
	Persona string `yaml:"persona,omitempty"`
}

// SerialConfig carries the legacy serial-port connection fields. When
// TransportURL is non-empty it wins, so the port/baud fields become
// dead — kept here because existing config files still populate them
// and removing the keys would break loading.
type SerialConfig struct {
	Port     string `yaml:"port"`
	BaudRate int    `yaml:"baud_rate"`

	// TransportURL overrides Port + BaudRate when set. Accepts any
	// scheme registered with internal/flipper/transport:
	//
	//   serial:///dev/ttyACM0?baud=230400   — explicit serial
	//   mock:///dev/pts/5                   — test harness pty slave
	//   ble://AA:BB:CC:DD:EE:FF             — reserved (Phase-B)
	//
	// Empty = default behaviour (build a serial URL from Port +
	// BaudRate). This field is also settable via the --transport CLI
	// flag, which overrides whatever the config file specifies.
	TransportURL string `yaml:"transport_url,omitempty"`
}

type MarauderConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Port     string `yaml:"port"`
	BaudRate int    `yaml:"baud_rate"`
}

type WebConfig struct {
	// Host is the interface to bind the web UI to. Empty defaults to
	// "127.0.0.1" (loopback). Set to "0.0.0.0" to accept connections
	// from any interface — pair with a non-empty Token when you do.
	Host string `yaml:"host"`
	Port int    `yaml:"port"`

	// Token, when non-empty, gates every /api and /ws request behind a
	// bearer-token check. HTTP callers send `Authorization: Bearer <token>`;
	// browsers negotiate the WebSocket with `Sec-WebSocket-Protocol: bearer,
	// <token>` (the server echoes `bearer` back on success). Leave empty
	// for local-only deployments — the server prints a loud warning when
	// it's bound non-loopback without a token set.
	// PROMPTZERO_WEB_TOKEN env var overrides this field when set.
	Token string `yaml:"token,omitempty"`

	// CORSOrigins is the list of origins allowed to connect the WebSocket
	// and call /api cross-origin. Empty (default) means same-origin only.
	// Entries match the browser's `Origin` header verbatim
	// (e.g. "https://cockpit.lan"). A literal "*" is refused at Start —
	// set AllowAnyOrigin instead.
	CORSOrigins []string `yaml:"cors_origins,omitempty"`

	// AllowAnyOrigin opts in to wildcard Origin matching for cross-origin
	// WebSocket connections. Must be paired with removing "*" from
	// CORSOrigins — the indirection is intentional so a stray "*" in a
	// copy-pasted config can't silently disable Origin enforcement.
	AllowAnyOrigin bool `yaml:"allow_any_origin,omitempty"`

	// AllowUnauthedPublic, when true, falls back to the pre-fix warn-and-continue
	// behaviour when the server is bound non-loopback without a token. By default
	// (false) the server refuses to start in that configuration. Set this only in
	// controlled environments where you accept the open-access risk.
	AllowUnauthedPublic bool `yaml:"allow_unauthed_public,omitempty"`
}

type Device struct {
	Type     string            `yaml:"type"`
	File     string            `yaml:"file"`
	Commands map[string]string `yaml:"commands,omitempty"`
}

func Load(path string) (*Config, error) {
	cfg := &Config{
		Model: "claude-opus-4-7",
		Serial: SerialConfig{
			Port:     "/dev/ttyACM0",
			BaudRate: 230400,
		},
		Marauder: MarauderConfig{
			Port:     "/dev/ttyACM1",
			BaudRate: 115200,
		},
		Web: WebConfig{
			Port: 8080,
		},
		Observability: ObservabilityConfig{
			LogLevel:       "info",
			LogFormat:      "text",
			MetricsEnabled: true,
			MetricsPath:    "/metrics",
		},
		Validator: ValidatorConfig{
			BadUSB: BadUSBValidatorConfig{
				WarnAction: "warn",
			},
		},
	}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// Fall back to ~/.promptzero/config.yaml when the requested path
		// isn't present. This is the standard per-user location so users
		// who run promptzero from anywhere still pick up their config.
		if home, herr := os.UserHomeDir(); herr == nil {
			fallback := filepath.Join(home, ".promptzero", "config.yaml")
			if fdata, ferr := os.ReadFile(fallback); ferr == nil {
				data, err = fdata, nil
			}
		}
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading config from %q: %w", path, err)
	}

	if err == nil && len(data) > 0 {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing config from %q: %w", path, err)
		}
	}

	// Environment variables override config file
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		cfg.APIKey = key
	}
	if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		cfg.OpenAIKey = key
	}
	if tok := os.Getenv("PROMPTZERO_WEB_TOKEN"); tok != "" {
		cfg.Web.Token = tok
	}

	return cfg, nil
}

// RequireAPIKey reports an error when the Anthropic API key is missing.
// Modes that drive Claude (REPL, --web, --voice) call this after Load.
// --mcp does not — the host MCP client supplies the LLM, so requiring a
// key here would block the documented "plug into Claude Desktop" flow.
func (c *Config) RequireAPIKey() error {
	if c.APIKey == "" {
		return fmt.Errorf("API key required: set api_key in config or ANTHROPIC_API_KEY env var")
	}
	return nil
}
