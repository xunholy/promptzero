package mcpfed

import (
	"context"
	"testing"
)

func TestCommandFunc_None(t *testing.T) {
	fn := commandFunc(SandboxNone)
	cmd, err := fn(context.Background(), "echo", []string{"FOO=bar"}, []string{"hello"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.Path == "" {
		t.Errorf("Path empty")
	}
	if got := cmd.Args[0]; got != "echo" && !endsWithEcho(got) {
		t.Errorf("Args[0] = %q, want echo or path/to/echo", got)
	}
	if !contains(cmd.Args, "hello") {
		t.Errorf("missing arg 'hello': %v", cmd.Args)
	}
	if !contains(cmd.Env, "FOO=bar") {
		t.Errorf("missing env entry: %v", cmd.Env)
	}
}

func TestCommandFunc_Docker(t *testing.T) {
	fn := commandFunc(SandboxDocker)
	cmd, err := fn(context.Background(), "myimage:tag", []string{"KEY=VAL"}, []string{"--flag", "x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !endsWithDocker(cmd.Args[0]) {
		t.Errorf("expected docker exec, got %q", cmd.Args[0])
	}
	mustHave := []string{"run", "--rm", "-i", "--network=none", "--env", "KEY=VAL", "myimage:tag", "--flag", "x"}
	for _, m := range mustHave {
		if !contains(cmd.Args, m) {
			t.Errorf("docker args missing %q (full: %v)", m, cmd.Args)
		}
	}
}

func TestCommandFunc_Bwrap(t *testing.T) {
	fn := commandFunc(SandboxBwrap)
	cmd, err := fn(context.Background(), "/usr/bin/python3", []string{"FOO=bar"}, []string{"-m", "x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !endsWithBwrap(cmd.Args[0]) {
		t.Errorf("expected bwrap exec, got %q", cmd.Args[0])
	}
	for _, m := range []string{"--ro-bind", "/", "--unshare-all", "--share-net", "/usr/bin/python3", "-m", "x"} {
		if !contains(cmd.Args, m) {
			t.Errorf("bwrap args missing %q (full: %v)", m, cmd.Args)
		}
	}
}

func TestCommandFunc_Firejail(t *testing.T) {
	fn := commandFunc(SandboxFirejail)
	cmd, err := fn(context.Background(), "/usr/bin/python3", nil, []string{"-m", "x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !endsWithFirejail(cmd.Args[0]) {
		t.Errorf("expected firejail exec, got %q", cmd.Args[0])
	}
	for _, m := range []string{"--net=none", "--private", "/usr/bin/python3", "-m", "x"} {
		if !contains(cmd.Args, m) {
			t.Errorf("firejail args missing %q (full: %v)", m, cmd.Args)
		}
	}
}

func TestCommandFunc_Unknown(t *testing.T) {
	fn := commandFunc(Sandbox(99))
	_, err := fn(context.Background(), "x", nil, nil)
	if err == nil {
		t.Errorf("expected error for unknown sandbox")
	}
}

func TestSandboxString(t *testing.T) {
	cases := map[Sandbox]string{
		SandboxNone:     "none",
		SandboxDocker:   "docker",
		SandboxBwrap:    "bwrap",
		SandboxFirejail: "firejail",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("%v.String() = %q, want %q", int(s), got, want)
		}
	}
}

// helpers

func contains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

func endsWithEcho(s string) bool     { return endsWith(s, "echo") }
func endsWithDocker(s string) bool   { return endsWith(s, "docker") }
func endsWithBwrap(s string) bool    { return endsWith(s, "bwrap") }
func endsWithFirejail(s string) bool { return endsWith(s, "firejail") }

func endsWith(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
