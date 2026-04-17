package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	APIKey        string               `yaml:"api_key"`
	OpenAIKey     string               `yaml:"openai_api_key"`
	Model         string               `yaml:"model"`
	Serial        SerialConfig         `yaml:"serial"`
	Marauder      MarauderConfig       `yaml:"marauder"`
	Web           WebConfig            `yaml:"web"`
	Devices       map[string]Device    `yaml:"devices"`
	ConfirmRisk   string               `yaml:"confirm_risk,omitempty"`
	Persona       string               `yaml:"persona,omitempty"`
	Watch         WatchConfig          `yaml:"watch,omitempty"`
	Webhooks      []WebhookConfig      `yaml:"webhooks,omitempty"`
	MQTT          MQTTConfig           `yaml:"mqtt,omitempty"`
	Observability ObservabilityConfig  `yaml:"observability,omitempty"`
	Validator     ValidatorConfig      `yaml:"validator,omitempty"`
	Rules         []RuleConfig         `yaml:"rules,omitempty"`
	Cost          CostConfig           `yaml:"cost,omitempty"`
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
	Enabled        *bool  `yaml:"enabled,omitempty"`
	AllowCritical  bool   `yaml:"allow_critical,omitempty"`
	WarnAction     string `yaml:"warn_action,omitempty"`
}

// RuleConfig is the YAML round-trip shape for one reactive rule. See
// internal/rules for the runtime surface. Cooldown uses the standard
// Go duration format ("30s", "1m", "2h"); empty means no cooldown.
type RuleConfig struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description,omitempty"`
	When        RuleMatchConfig   `yaml:"when"`
	Then        []RuleActionConfig `yaml:"then"`
	Cooldown    string            `yaml:"cooldown,omitempty"`
	Enabled     *bool             `yaml:"enabled,omitempty"`
}

// RuleMatchConfig defines audit-entry matching. Non-empty fields are
// ANDed; empty fields are wildcards. Tool supports a trailing "*" glob
// ("workflow_*") as a common convenience.
type RuleMatchConfig struct {
	Tool            string `yaml:"tool,omitempty"`
	Risk            string `yaml:"risk,omitempty"`
	Level           string `yaml:"level,omitempty"`
	OutputContains  string `yaml:"output_contains,omitempty"`
}

// RuleActionConfig is one step in a rule's Then list. Type picks the
// handler; the other fields are consumed depending on the type.
type RuleActionConfig struct {
	Type    string                 `yaml:"type"`
	Tool    string                 `yaml:"tool,omitempty"`
	Params  map[string]interface{} `yaml:"params,omitempty"`
	Webhook string                 `yaml:"webhook,omitempty"`
	Topic   string                 `yaml:"topic,omitempty"`
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

// MQTTConfig configures the optional outbound MQTT bridge. Password is
// overridden by env var MQTT_PASSWORD when the config field is empty.
// Leave Enabled=false (or the whole block absent) to skip. BasePath
// defaults to "promptzero" when empty.
type MQTTConfig struct {
	Enabled  bool   `yaml:"enabled,omitempty"`
	Broker   string `yaml:"broker,omitempty"`
	ClientID string `yaml:"client_id,omitempty"`
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
	BasePath string `yaml:"base_path,omitempty"`
	QoS      byte   `yaml:"qos,omitempty"`
	Retained bool   `yaml:"retained,omitempty"`
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

type SerialConfig struct {
	Port     string `yaml:"port"`
	BaudRate int    `yaml:"baud_rate"`
}

type MarauderConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Port     string `yaml:"port"`
	BaudRate int    `yaml:"baud_rate"`
}

type WebConfig struct {
	// Host is the interface to bind the web UI to. Empty defaults to
	// "127.0.0.1" (loopback) — the web UI has no authentication, so
	// binding publicly must be an explicit choice. Set to "0.0.0.0" to
	// accept connections from any interface.
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type Device struct {
	Type     string            `yaml:"type"`
	File     string            `yaml:"file"`
	Commands map[string]string `yaml:"commands,omitempty"`
}

func Load(path string) (*Config, error) {
	cfg := &Config{
		Model: "claude-sonnet-4-6",
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
		return nil, fmt.Errorf("reading config: %w", err)
	}

	if err == nil && len(data) > 0 {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing config: %w", err)
		}
	}

	// Environment variables override config file
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		cfg.APIKey = key
	}
	if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		cfg.OpenAIKey = key
	}
	if pw := os.Getenv("MQTT_PASSWORD"); pw != "" && cfg.MQTT.Password == "" {
		cfg.MQTT.Password = pw
	}

	if cfg.APIKey == "" {
		return nil, fmt.Errorf("API key required: set api_key in config or ANTHROPIC_API_KEY env var")
	}

	return cfg, nil
}
