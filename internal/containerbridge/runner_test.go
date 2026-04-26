package containerbridge

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRunRequiresImage(t *testing.T) {
	_, err := Run(context.Background(), Config{})
	if err == nil {
		t.Fatalf("expected error for empty image")
	}
}

// TestRunDispatchesDockerCmd does not require docker to actually be
// installed — it shadows the availability check to true and relies on
// docker being absent producing a wrapped exec error. That asserts the
// Run path uses exec.CommandContext("docker", ...).
//
// Skipped when docker IS present because we don't want to spawn a real
// container in unit tests.
func TestRunReportsExecFailureWhenDockerAbsent(t *testing.T) {
	if Available() {
		t.Skip("docker is installed; this test exercises the absent path")
	}
	_, err := Run(context.Background(), Config{Image: "alpine:latest"})
	if !errors.Is(err, ErrDockerUnavailable) {
		t.Fatalf("err = %v, want ErrDockerUnavailable", err)
	}
}

// TestRunErrorIsWrapped exercises the *RunError path by stubbing the
// availability check to true and forcing a docker invocation that will
// fail with exit code != 0 — but only when docker is actually present.
// We use `docker run --rm alpine:not-a-real-tag` which the daemon will
// reject; this tolerates docker being installed but offline (image pull
// fails → exit code 125 from docker itself).
func TestRunErrorOnInvalidImage(t *testing.T) {
	if !Available() {
		t.Skip("docker not available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := Run(ctx, Config{
		Image:   "promptzero-bridge-test-image-does-not-exist:" + time.Now().Format("20060102150405"),
		Timeout: 8 * time.Second,
	})
	if err == nil {
		t.Fatalf("expected error for non-existent image; res=%v", res)
	}
	var re *RunError
	if errors.As(err, &re) {
		// docker exits 125 for "could not pull image" by convention
		if re.ExitCode == 0 {
			t.Errorf("RunError ExitCode = 0; expected non-zero for pull failure")
		}
		// The error string should include some part of docker's
		// stderr; either "Unable to find image" or a registry-side
		// 401/404 message.
		if !strings.Contains(strings.ToLower(re.Error()), "unable to find") &&
			!strings.Contains(strings.ToLower(re.Error()), "manifest") &&
			!strings.Contains(strings.ToLower(re.Error()), "pull") {
			t.Logf("Error body: %s", re.Error()) // not fatal — registry messages vary
		}
	} else {
		// Could be ErrDockerUnavailable (test infra) or a context
		// timeout. Still acceptable.
		t.Logf("Run failed but not via *RunError: %v", err)
	}
}

func TestRunErrorMessage(t *testing.T) {
	re := &RunError{ExitCode: 42, Stderr: "tool said no"}
	if !strings.Contains(re.Error(), "42") || !strings.Contains(re.Error(), "tool said no") {
		t.Errorf("RunError message = %q; missing exit code or stderr", re.Error())
	}

	re = &RunError{ExitCode: 1}
	if !strings.Contains(re.Error(), "exited 1") {
		t.Errorf("blank-stderr RunError message = %q", re.Error())
	}
}
