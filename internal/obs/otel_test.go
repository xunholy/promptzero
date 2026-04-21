package obs

import (
	"context"
	"testing"
)

func TestInitOTel_NoEndpointReturnsNoop(t *testing.T) {
	// Ensure a clean slate — no endpoint means noop path.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")

	shutdown, err := InitOTel(context.Background())
	if err != nil {
		t.Fatalf("InitOTel in noop mode should never error: %v", err)
	}
	if shutdown == nil {
		t.Fatalf("shutdown func must be non-nil even in noop mode")
	}
	// Shutdown must be idempotent + a no-op.
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("noop shutdown returned error: %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("noop shutdown second call errored: %v", err)
	}
}

func TestStartAgentTurn_NoopTracerStillReturnsSpan(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	_, _ = InitOTel(context.Background())

	ctx, span := StartAgentTurn(context.Background(), "claude-sonnet-4-6", 42)
	if span == nil {
		t.Fatal("StartAgentTurn returned nil span")
	}
	// Attribute and End calls must be safe on the noop path.
	RecordUsage(span, 100, 50, 200, 10)
	RecordFinishReason(span, "end_turn")
	span.End()

	// SpanFromCtx on a context that carried a (noop) span is safe.
	if got := SpanFromCtx(ctx); got == nil {
		t.Error("SpanFromCtx returned nil, want a span")
	}
}

func TestStartToolCall_ChildSpan(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	_, _ = InitOTel(context.Background())

	turnCtx, turn := StartAgentTurn(context.Background(), "claude-sonnet-4-6", 10)
	defer turn.End()

	callCtx, call := StartToolCall(turnCtx, "wifi_scan_ap", "toolu_123", `{"duration_seconds":15}`)
	if call == nil {
		t.Fatal("StartToolCall returned nil")
	}
	RecordToolResult(call, 1024, false)
	call.End()

	// Context from the child call must still resolve a span.
	if sp := SpanFromCtx(callCtx); sp == nil {
		t.Error("SpanFromCtx on child ctx returned nil")
	}
}

func TestRecordUsage_AcceptsZeros(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	_, _ = InitOTel(context.Background())

	_, span := StartAgentTurn(context.Background(), "x", 0)
	// A fresh session has all-zero counters — must not panic / error.
	RecordUsage(span, 0, 0, 0, 0)
	RecordFinishReason(span, "")
	span.End()
}
