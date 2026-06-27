package agent

import "github.com/xunholy/promptzero/internal/quarantine"

// The prompt-injection quarantine moved to internal/quarantine so the MCP
// server can apply the identical countermeasure to tool output it returns to
// external MCP hosts (see internal/mcp). The agent dispatch path keeps these
// thin in-package forwarders so existing callers and tests are unchanged; the
// policy and logic live in one shared place.

// quarantineOutput sanitises and wraps a tool's output for the agent loop.
// See quarantine.Output.
func quarantineOutput(toolName, output string, isErr bool) string {
	return quarantine.Output(toolName, output, isErr)
}

// QuarantineOutput is the exported entry point retained for the cross-package
// adversarial corpus (test/adversarial, P3-30).
func QuarantineOutput(toolName, output string, isErr bool) string {
	return quarantine.Output(toolName, output, isErr)
}

// sanitizeControlChars strips ANSI/control bytes from a string. Used by the
// tool-error excerpt path (toolerror.go) as well as quarantineOutput.
func sanitizeControlChars(s string) string {
	return quarantine.SanitizeControlChars(s)
}

// isUntrustedHardwareOutput reports whether a tool gets the hardware wrapper.
func isUntrustedHardwareOutput(toolName string) bool {
	return quarantine.IsUntrustedHardwareOutput(toolName)
}
