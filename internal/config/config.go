package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	APIKey      string            `yaml:"api_key"`
	OpenAIKey   string            `yaml:"openai_api_key"`
	Model       string            `yaml:"model"`
	Serial      SerialConfig      `yaml:"serial"`
	Marauder    MarauderConfig    `yaml:"marauder"`
	Web         WebConfig         `yaml:"web"`
	Devices     map[string]Device `yaml:"devices"`
	ConfirmRisk string            `yaml:"confirm_risk,omitempty"`
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

	if cfg.APIKey == "" {
		return nil, fmt.Errorf("API key required: set api_key in config or ANTHROPIC_API_KEY env var")
	}

	return cfg, nil
}
