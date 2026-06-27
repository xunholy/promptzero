// Package mcpfed federates external Model Context Protocol (MCP) servers as
// native PromptZero tools. It is the outbound counterpart to internal/mcp,
// which exposes PromptZero's own tool surface as an MCP server.
//
// # Why this exists
//
// Many high-leverage capabilities (Proxmark3, Hashcat, Burp, BloodHound,
// Ghidra, Metasploit, the FuzzingLabs security hub) are already published as
// MCP servers. Rather than re-implementing each one, mcpfed connects to them
// at startup, lists their tools, and registers each remote tool as a
// [internal/tools.Spec] under a prefixed name (e.g. secsec__nmap_scan). The
// agent's normal dispatch path then invokes the federated tool exactly like a
// native one — risk gating, audit logging, and confirm callbacks all apply
// uniformly.
//
// # Tool name layout
//
// Federated tools are namespaced as `<prefix>__<remoteName>` (double
// underscore separator). The prefix is operator-chosen at config time, must
// match `^[a-z][a-z0-9-]*$`, and is reserved per-Federation. Anthropic's
// tool-name rule caps total length at 64 chars; mcpfed validates this before
// registration and rejects servers with names that would overflow.
//
// # Risk classification
//
// MCP advertises optional behaviour hints on each tool via
// `mcp.ToolAnnotation` (ReadOnlyHint, DestructiveHint, IdempotentHint,
// OpenWorldHint). These hints come from the untrusted federated server, so
// mcpfed honours them only in the cautious direction — a hint may raise risk
// but never lower it below the operator's configured floor:
//
//   - DestructiveHint=true        → Critical
//   - OpenWorldHint=true          → +1 tier vs. the floor (capped at Critical)
//   - ReadOnlyHint=true           → the floor (ClientConfig.RiskDefault); it
//     is treated as "no escalation needed", never as a reduction below it
//   - no annotations              → the floor (ClientConfig.RiskDefault,
//     or High if unset)
//
// The mapping is conservative: every federated tool is at least the operator's
// configured default (High by default). A server cannot mark a destructive
// tool read-only to drop to Low and slip past the confirm / audit /
// read-only-mode gates — to lower a server's tools, the operator must lower
// that server's RiskDefault deliberately.
//
// # Sandboxing
//
// STDIO transports launch arbitrary child processes. mcpfed wires a
// configurable sandbox via mcp-go's `transport.WithCommandFunc` hook so the
// command's `*exec.Cmd` is wrapped before spawn. Supported profiles:
//
//   - "none"     — bare exec, intended for trusted local tools.
//   - "docker"   — `docker run --rm -i --network=none <image>`. The
//     ClientConfig.Command is rewritten so the original command
//     becomes the docker image; original args become the
//     containerised process args.
//   - "bwrap"    — bubblewrap with read-only rootfs, tmpfs /tmp, no net.
//   - "firejail" — firejail with --net=none --private (WSL-friendly fallback).
//
// http and sse transports do not spawn processes; their sandbox value must be
// "none" and is otherwise rejected at validation.
//
// # Lifecycle
//
// One [Federation] per process. Created with [New], populated by
// [Federation.Start] (reads config, spawns each ClientConfig in parallel,
// registers tools), torn down with [Federation.Close]. Closed federations
// cannot be restarted — create a new one. The federation owns each
// managedClient for its lifetime; clients are long-lived (subprocess
// initialisation overhead is too high to spawn-per-call).
//
// # Reconnect
//
// mcp-go does not auto-reconnect. mcpfed wraps each Handler with one retry:
// if CallTool returns an error matching transport-closed semantics, the
// client is closed, respawned, re-Initialized, and the call retried once.
// A second failure surfaces to the caller. Failed health-pings (every 30s by
// default) mark a client unhealthy and trigger a respawn on the next call.
package mcpfed
