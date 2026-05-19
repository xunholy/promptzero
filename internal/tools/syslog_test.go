package tools

import (
	"context"
	"strings"
	"testing"
)

// TestSyslogMessageDecodeHandler_RFC5424 pins the canonical
// RFC 5424 example message through the Spec handler.
func TestSyslogMessageDecodeHandler_RFC5424(t *testing.T) {
	out, err := syslogMessageDecodeHandler(context.Background(), nil, map[string]any{
		"line": `<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 ` +
			`[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]` +
			` BOMAn application event log entry...`,
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"format": "RFC 5424 (IETF)"`) {
		t.Errorf("expected RFC 5424 format:\n%s", out)
	}
	if !strings.Contains(out, `"facility": 20`) {
		t.Errorf("expected facility 20 (local4):\n%s", out)
	}
	if !strings.Contains(out, `"id": "exampleSDID@32473"`) {
		t.Errorf("expected SD-ID:\n%s", out)
	}
	if !strings.Contains(out, `"eventSource": "Application"`) {
		t.Errorf("expected SD parameter eventSource:\n%s", out)
	}
}

// TestSyslogMessageDecodeHandler_RFC3164 pins a classic BSD
// log line through the handler.
func TestSyslogMessageDecodeHandler_RFC3164(t *testing.T) {
	out, err := syslogMessageDecodeHandler(context.Background(), nil, map[string]any{
		"line": `<13>Sep 29 06:55:01 server cron[1234]: (root) CMD (run-parts /etc/cron.hourly)`,
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"format": "RFC 3164 (BSD)"`) {
		t.Errorf("expected RFC 3164 format:\n%s", out)
	}
	if !strings.Contains(out, `"tag": "cron"`) {
		t.Errorf("expected tag cron:\n%s", out)
	}
	if !strings.Contains(out, `"proc_id": "1234"`) {
		t.Errorf("expected proc_id 1234:\n%s", out)
	}
}

func TestSyslogMessageDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := syslogMessageDecodeHandler(context.Background(), nil, map[string]any{"line": ""})
	if err == nil {
		t.Fatal("want error for empty line")
	}
}

func TestSyslogMessageDecodeHandler_RejectsMalformed(t *testing.T) {
	_, err := syslogMessageDecodeHandler(context.Background(), nil, map[string]any{"line": "no pri"})
	if err == nil {
		t.Fatal("want error for missing PRI")
	}
}
