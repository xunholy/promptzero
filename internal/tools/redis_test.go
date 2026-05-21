package tools

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func redisArr(args ...string) []byte {
	out := fmt.Sprintf("*%d\r\n", len(args))
	for _, a := range args {
		out += fmt.Sprintf("$%d\r\n%s\r\n", len(a), a)
	}
	return []byte(out)
}

// TestRedisDecodeHandler_AUTHCleartext pins the canonical Redis
// credential-disclosure shape.
func TestRedisDecodeHandler_AUTHCleartext(t *testing.T) {
	out, err := redisDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(
			redisArr("AUTH", "hunter2"))})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"command": "AUTH"`,
		`"is_auth_command": true`,
		`"is_dangerous_command": true`,
		`"password_bytes": 7`,
		`CLEARTEXT`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestRedisDecodeHandler_AUTHWithUser pins the Redis 6 ACL two-
// argument AUTH shape.
func TestRedisDecodeHandler_AUTHWithUser(t *testing.T) {
	out, err := redisDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(
			redisArr("AUTH", "admin", "password123"))})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"auth_username": "admin"`,
		`"password_bytes": 11`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestRedisDecodeHandler_CONFIGSETRCE pins the canonical Redis-
// to-shell attack signal.
func TestRedisDecodeHandler_CONFIGSETRCE(t *testing.T) {
	out, err := redisDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(
			redisArr("CONFIG", "SET", "dir", "/root/.ssh"))})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"is_dangerous_command": true`,
		`RCE primitive`,
		`authorized_keys`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestRedisDecodeHandler_MODULELOAD pins the direct-RCE
// primitive.
func TestRedisDecodeHandler_MODULELOAD(t *testing.T) {
	out, err := redisDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(
			redisArr("MODULE", "LOAD", "/tmp/evil.so"))})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, "direct native-code RCE") {
		t.Errorf("MODULE LOAD should flag direct native-code RCE:\n%s",
			out)
	}
}

// TestRedisDecodeHandler_EVALCVE pins the Lua sandbox escape
// classification.
func TestRedisDecodeHandler_EVALCVE(t *testing.T) {
	out, err := redisDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(
			redisArr("EVAL", "return 1", "0"))})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, "CVE-2022-0543") {
		t.Errorf("EVAL should reference CVE-2022-0543:\n%s", out)
	}
}

// TestRedisDecodeHandler_ErrorNOAUTH pins the pre-auth signal.
func TestRedisDecodeHandler_ErrorNOAUTH(t *testing.T) {
	out, err := redisDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(
			[]byte("-NOAUTH Authentication required.\r\n"))})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"is_error": true`,
		`pre-auth signal`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestRedisDecodeHandler_ErrorWRONGPASS pins the brute-force
// feedback signal.
func TestRedisDecodeHandler_ErrorWRONGPASS(t *testing.T) {
	out, err := redisDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(
			[]byte("-WRONGPASS invalid username-password pair or user is disabled.\r\n"))})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, "brute-force feedback") {
		t.Errorf("WRONGPASS should flag brute-force feedback:\n%s", out)
	}
}

// TestRedisDecodeHandler_BenignGET pins that ordinary commands
// aren't flagged dangerous.
func TestRedisDecodeHandler_BenignGET(t *testing.T) {
	out, err := redisDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(
			redisArr("GET", "users:42"))})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"command": "GET"`,
		`"is_dangerous_command": false`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestRedisDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := redisDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
