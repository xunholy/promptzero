package mcpfed

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// ParseClientConfigs decodes the raw yaml.Node entries from
// config.Config.MCPClients into typed ClientConfig values, validates
// each one, and returns the result. Invalid entries return an error
// joined with all collected validation problems so the operator sees
// every misconfiguration at once.
//
// Lives in mcpfed (not config) so config has no dependency on mcpfed —
// the package boundary lets future federations be optional at the
// config layer without forcing every consumer to pull in the federation
// runtime.
func ParseClientConfigs(nodes []yaml.Node) ([]ClientConfig, error) {
	if len(nodes) == 0 {
		return nil, nil
	}
	out := make([]ClientConfig, 0, len(nodes))
	var errs []error
	for i, n := range nodes {
		var c ClientConfig
		if err := n.Decode(&c); err != nil {
			errs = append(errs, fmt.Errorf("mcp_clients[%d]: decode: %w", i, err))
			continue
		}
		if err := c.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("mcp_clients[%d]: %w", i, err))
			continue
		}
		out = append(out, c)
	}
	if len(errs) > 0 {
		return out, joinErrs(errs)
	}
	return out, nil
}

func joinErrs(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	if len(errs) == 1 {
		return errs[0]
	}
	msg := "mcpfed: multiple config errors:"
	for _, e := range errs {
		msg += "\n  - " + e.Error()
	}
	return fmt.Errorf("%s", msg)
}
