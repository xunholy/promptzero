package containerbridge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

// Mount declares one host-path → container-path bind mount.
type Mount struct {
	HostPath      string
	ContainerPath string
	ReadOnly      bool
}

// Config describes one containerised invocation.
//
// All fields are optional except Image. Stdin is delivered via the
// container's stdin pipe; large inputs are fine (the bridge does not
// buffer the input — it streams). Output is captured into a byte buffer
// to make it convenient for the calling Spec; if the tool generates
// hundreds of MB the caller should switch to volume-mounted output paths
// rather than stdout capture.
type Config struct {
	// Image is the docker image reference (e.g. "ghcr.io/onekey-sec/unblob:latest").
	// Required.
	Image string

	// Args are the entrypoint arguments passed to the container.
	Args []string

	// Env is the environment exposed to the container.
	Env map[string]string

	// Mounts are bind mounts from the host into the container.
	Mounts []Mount

	// Stdin streams into the container's stdin. Nil means no stdin.
	Stdin io.Reader

	// Network controls --network. Empty defaults to "none" — most tool
	// runs do not need network and the safe default avoids data
	// exfiltration risk.
	Network string

	// Timeout caps the entire run. Zero defaults to 5 minutes.
	Timeout time.Duration

	// User runs the container as a specific UID:GID. Empty leaves it
	// at the image's default. Set to e.g. "1000:1000" to match the
	// host operator and simplify volume-mounted output.
	User string

	// WorkDir sets the container working directory.
	WorkDir string

	// Sandbox extras — read-only rootfs, drop capabilities. Set true
	// for tools that don't need to mutate the rootfs (most parsers).
	ReadOnlyRootfs bool

	// AllocateTTY forces -t. Generally not needed — only set true for
	// tools that misbehave without one.
	AllocateTTY bool
}

// RunResult captures the stdout/stderr of a containerised invocation.
type RunResult struct {
	Stdout []byte
	Stderr []byte

	// ExitCode is 0 when the tool exited successfully, non-zero
	// otherwise. Always populated, even on RunError.
	ExitCode int

	// Duration is the wall-clock time the container ran.
	Duration time.Duration
}

// RunError wraps a non-zero exit. errors.As works as expected.
type RunError struct {
	ExitCode int
	Stderr   string
}

func (e *RunError) Error() string {
	if e.Stderr != "" {
		return fmt.Sprintf("container exited %d: %s", e.ExitCode, strings.TrimSpace(e.Stderr))
	}
	return fmt.Sprintf("container exited %d", e.ExitCode)
}

// ErrDockerUnavailable is returned when the docker binary cannot be
// invoked. Distinct from a tool-level error so callers can surface a
// helpful "install Docker" hint rather than a generic exec failure.
var ErrDockerUnavailable = errors.New("containerbridge: docker binary not found on PATH")

// Available reports whether the docker CLI is reachable. Cached after
// first call for the lifetime of the process — Docker's presence does
// not change at runtime.
func Available() bool { return availableDockerOnce() }

// Run executes one container according to cfg.
func Run(ctx context.Context, cfg Config) (RunResult, error) {
	if cfg.Image == "" {
		return RunResult{}, errors.New("containerbridge: empty image")
	}
	if !Available() {
		return RunResult{}, ErrDockerUnavailable
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := []string{"run", "--rm", "-i"}

	network := cfg.Network
	if network == "" {
		network = "none"
	}
	args = append(args, "--network", network)

	if cfg.ReadOnlyRootfs {
		args = append(args, "--read-only", "--tmpfs", "/tmp:rw,exec")
	}
	if cfg.User != "" {
		args = append(args, "--user", cfg.User)
	}
	if cfg.WorkDir != "" {
		args = append(args, "--workdir", cfg.WorkDir)
	}
	if cfg.AllocateTTY {
		args = append(args, "-t")
	}
	for _, m := range cfg.Mounts {
		spec := m.HostPath + ":" + m.ContainerPath
		if m.ReadOnly {
			spec += ":ro"
		}
		args = append(args, "-v", spec)
	}
	for k, v := range cfg.Env {
		args = append(args, "-e", k+"="+v)
	}
	args = append(args, cfg.Image)
	args = append(args, cfg.Args...)

	cmd := exec.CommandContext(runCtx, "docker", args...)
	if cfg.Stdin != nil {
		cmd.Stdin = cfg.Stdin
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err := cmd.Run()
	dur := time.Since(start)

	res := RunResult{
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		Duration: dur,
	}

	var exitErr *exec.ExitError
	switch {
	case err == nil:
		res.ExitCode = 0
		return res, nil
	case errors.As(err, &exitErr):
		res.ExitCode = exitErr.ExitCode()
		return res, &RunError{ExitCode: res.ExitCode, Stderr: stderr.String()}
	case errors.Is(err, context.DeadlineExceeded):
		res.ExitCode = -1
		return res, fmt.Errorf("containerbridge: timeout after %v: %w", timeout, err)
	default:
		res.ExitCode = -1
		return res, fmt.Errorf("containerbridge: docker run: %w", err)
	}
}

// availableDockerOnce caches the docker-binary lookup. Defined as a
// closure so tests can shadow it via a build tag — see runner_test.go's
// FakeDocker shim.
var availableDockerOnce = func() func() bool {
	var checked bool
	var ok bool
	return func() bool {
		if checked {
			return ok
		}
		checked = true
		_, err := exec.LookPath("docker")
		ok = err == nil
		return ok
	}
}()
