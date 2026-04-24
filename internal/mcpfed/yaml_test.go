package mcpfed

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestParseClientConfigs_Empty(t *testing.T) {
	got, err := ParseClientConfigs(nil)
	if err != nil {
		t.Fatalf("nil input: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("nil input → %d entries, want 0", len(got))
	}
}

func TestParseClientConfigs_Valid(t *testing.T) {
	src := `
- prefix: secsec
  transport: stdio
  command: docker
  args: [run, --rm, -i, ghcr.io/fuzzinglabs/security-hub:latest]
  sandbox: docker
  risk_default: high

- prefix: pm3
  transport: http
  url: http://localhost:8080/mcp
  headers:
    Authorization: Bearer abc
`
	var nodes []yaml.Node
	if err := yaml.Unmarshal([]byte(src), &nodes); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}

	clients, err := ParseClientConfigs(nodes)
	if err != nil {
		t.Fatalf("ParseClientConfigs: %v", err)
	}
	if len(clients) != 2 {
		t.Fatalf("got %d clients, want 2", len(clients))
	}
	if clients[0].Prefix != "secsec" || clients[0].Transport != "stdio" {
		t.Errorf("clients[0] = %+v", clients[0])
	}
	if clients[1].Prefix != "pm3" || clients[1].Transport != "http" {
		t.Errorf("clients[1] = %+v", clients[1])
	}
	if v := clients[1].Headers["Authorization"]; v != "Bearer abc" {
		t.Errorf("headers[Authorization] = %q", v)
	}
}

func TestParseClientConfigs_InvalidJoined(t *testing.T) {
	src := `
- prefix: ok
  transport: stdio
  command: x

- prefix: BAD
  transport: stdio
  command: x

- prefix: also
  transport: udp
  command: y
`
	var nodes []yaml.Node
	if err := yaml.Unmarshal([]byte(src), &nodes); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	got, err := ParseClientConfigs(nodes)
	if err == nil {
		t.Fatalf("expected aggregated error")
	}
	if !strings.Contains(err.Error(), "BAD") {
		t.Errorf("error missing prefix-validation message: %v", err)
	}
	if !strings.Contains(err.Error(), "udp") {
		t.Errorf("error missing transport-validation message: %v", err)
	}
	if len(got) != 1 || got[0].Prefix != "ok" {
		t.Errorf("expected the one valid entry to come through; got=%v", got)
	}
}
