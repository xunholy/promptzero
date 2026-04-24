package mcpfed

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/mark3labs/mcp-go/client/transport"
)

// Sandbox identifies an exec-wrapping profile for stdio transports.
type Sandbox int

const (
	// SandboxNone runs the configured command directly. Suitable only
	// for trusted local tools (e.g. operator-installed CLIs).
	SandboxNone Sandbox = iota

	// SandboxDocker wraps the command as
	// `docker run --rm -i --network=none --read-only <image> [args...]`.
	// The original ClientConfig.Command becomes the image name; args
	// become the container's process args. Env is passed via -e flags.
	SandboxDocker

	// SandboxBwrap uses bubblewrap to isolate filesystem and namespaces:
	// `bwrap --ro-bind / / --tmpfs /tmp --unshare-all --share-net <cmd>`.
	// Network is shared (federated MCP servers typically need it).
	SandboxBwrap

	// SandboxFirejail uses firejail's lightweight sandbox:
	// `firejail --net=none --private <cmd>`. Works inside WSL where
	// bubblewrap and full Docker may be unavailable.
	SandboxFirejail
)

func (s Sandbox) String() string {
	switch s {
	case SandboxNone:
		return "none"
	case SandboxDocker:
		return "docker"
	case SandboxBwrap:
		return "bwrap"
	case SandboxFirejail:
		return "firejail"
	default:
		return fmt.Sprintf("sandbox(%d)", int(s))
	}
}

// commandFunc returns a transport.CommandFunc that wraps the configured
// command according to the sandbox profile. The returned func is suitable
// for transport.WithCommandFunc.
//
// nolint:cyclop // wrap-by-sandbox is naturally a small switch
func commandFunc(sb Sandbox) transport.CommandFunc {
	return func(ctx context.Context, command string, env []string, args []string) (*exec.Cmd, error) {
		switch sb {
		case SandboxNone:
			cmd := exec.CommandContext(ctx, command, args...)
			cmd.Env = append(cmd.Env, env...)
			return cmd, nil

		case SandboxDocker:
			// command = image, args = entrypoint args. Env passed
			// via -e KEY (the value is already set on this process,
			// so docker propagates it through).
			dockerArgs := []string{"run", "--rm", "-i", "--network=none"}
			for _, kv := range env {
				// kv = "KEY=VAL". docker -e KEY copies from the
				// host env, but we want VAL to actually arrive,
				// so use --env KEY=VAL form.
				dockerArgs = append(dockerArgs, "--env", kv)
			}
			dockerArgs = append(dockerArgs, command)
			dockerArgs = append(dockerArgs, args...)
			return exec.CommandContext(ctx, "docker", dockerArgs...), nil

		case SandboxBwrap:
			bwrapArgs := []string{
				"--ro-bind", "/", "/",
				"--tmpfs", "/tmp",
				"--unshare-all",
				"--share-net",
				"--die-with-parent",
				command,
			}
			bwrapArgs = append(bwrapArgs, args...)
			cmd := exec.CommandContext(ctx, "bwrap", bwrapArgs...)
			cmd.Env = append(cmd.Env, env...)
			return cmd, nil

		case SandboxFirejail:
			// `firejail --net=none --private <cmd> <args...>`.
			fjArgs := []string{"--net=none", "--private", "--quiet", command}
			fjArgs = append(fjArgs, args...)
			cmd := exec.CommandContext(ctx, "firejail", fjArgs...)
			cmd.Env = append(cmd.Env, env...)
			return cmd, nil

		default:
			return nil, fmt.Errorf("mcpfed: unsupported sandbox %v", sb)
		}
	}
}
