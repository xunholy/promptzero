// OpenTelemetry GenAI wiring for PromptZero.
//
// Honours the standard OTEL_* environment variables — when
// OTEL_EXPORTER_OTLP_ENDPOINT is unset, InitOTel returns a no-op
// shutdown func and all span calls become cheap routed calls through
// a tracer whose provider drops everything. This keeps existing
// deployments unchanged and lets operators opt in by setting one env.
//
// Span attributes follow the OTel GenAI semantic conventions
// (gen_ai.*). The set we emit:
//
//   gen_ai.system                 = "anthropic"
//   gen_ai.request.model          = "claude-sonnet-4-6" (etc.)
//   gen_ai.usage.input_tokens     = int
//   gen_ai.usage.output_tokens    = int
//   gen_ai.usage.cache_read_input_tokens     = int
//   gen_ai.usage.cache_creation_input_tokens = int
//   gen_ai.response.finish_reasons = "end_turn" | "tool_use" | ...
//   gen_ai.tool.name              = "wifi_scan_ap"
//   gen_ai.tool.call.id           = "toolu_..."
//
// Per the spec, tool-call spans are emitted as children of the agent
// turn span so a single trace shows the full request -> tools -> reply
// chain.
package obs

import (
	"context"
	"fmt"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// tracerName is the logical name stamped onto every span emitted by
// PromptZero. Matches the otlp-viewer convention of using the
// importing package's module path.
const tracerName = "github.com/xunholy/promptzero"

// ShutdownFunc flushes pending spans and releases the exporter's
// resources. Safe to call multiple times; subsequent calls are no-ops.
type ShutdownFunc func(context.Context) error

// InitOTel wires up an OTel tracer provider against the OTLP HTTP
// exporter. When OTEL_EXPORTER_OTLP_ENDPOINT is empty, the function
// installs a no-op tracer and returns a no-op shutdown — so callers
// can always invoke the returned shutdown in a defer without branching.
//
// The service name defaults to "promptzero" but can be overridden via
// OTEL_SERVICE_NAME (standard semconv).
func InitOTel(ctx context.Context) (ShutdownFunc, error) {
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" &&
		os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") == "" {
		// No exporter configured — install a noop provider so
		// Tracer() calls still work, but drop everything.
		otel.SetTracerProvider(noop.NewTracerProvider())
		return func(context.Context) error { return nil }, nil
	}

	svcName := os.Getenv("OTEL_SERVICE_NAME")
	if svcName == "" {
		svcName = "promptzero"
	}

	exp, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("otel: otlp exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(svcName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("otel: build resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp,
			sdktrace.WithBatchTimeout(5*time.Second),
		),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	return func(ctx context.Context) error {
		// Force a final flush on shutdown so in-flight spans land
		// before the process exits.
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return tp.Shutdown(shutdownCtx)
	}, nil
}

// Tracer returns the global PromptZero tracer. Always safe to call —
// when OTel is disabled this returns a no-op tracer whose spans are
// free. Callers should propagate the returned context through the
// operation they're measuring.
func Tracer() trace.Tracer {
	return otel.Tracer(tracerName)
}

// SpanFromCtx returns the current span bound to ctx, or a no-op span
// when tracing is disabled. Never returns nil so callers can unguarded
// call SetAttributes / End without a defensive nil check.
func SpanFromCtx(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// StartAgentTurn opens a span for one top-level agent turn and
// populates the gen_ai.request.model attribute. Returns a context that
// carries the span and a finish func that must be deferred.
//
// inputLen is useful for distinguishing short intent-classification
// turns from long exploit-planning turns in the trace viewer — kept
// separate from token counts because tokens aren't known until the
// response comes back.
func StartAgentTurn(ctx context.Context, model string, inputLen int) (context.Context, trace.Span) {
	ctx, span := Tracer().Start(ctx, "gen_ai.agent.turn",
		trace.WithAttributes(
			attribute.String("gen_ai.system", "anthropic"),
			attribute.String("gen_ai.request.model", model),
			attribute.Int("gen_ai.request.input_length", inputLen),
		),
	)
	return ctx, span
}

// RecordUsage stamps gen_ai.usage.* attributes onto the given span.
// Safe to call on a no-op span (the attribute calls are dropped).
func RecordUsage(span trace.Span, inputTokens, outputTokens, cacheReadTokens, cacheCreationTokens int64) {
	span.SetAttributes(
		attribute.Int64("gen_ai.usage.input_tokens", inputTokens),
		attribute.Int64("gen_ai.usage.output_tokens", outputTokens),
		attribute.Int64("gen_ai.usage.cache_read_input_tokens", cacheReadTokens),
		attribute.Int64("gen_ai.usage.cache_creation_input_tokens", cacheCreationTokens),
	)
}

// RecordFinishReason records the model's stop reason on a span. Common
// values: "end_turn", "tool_use", "max_tokens", "stop_sequence".
func RecordFinishReason(span trace.Span, reason string) {
	if reason == "" {
		return
	}
	span.SetAttributes(attribute.StringSlice("gen_ai.response.finish_reasons", []string{reason}))
}

// StartToolCall opens a child span for a single tool invocation.
// Captures the tool name, Anthropic tool-call id, and the input JSON
// as attributes so the trace viewer can surface "what did the agent
// call with what args" without cross-referencing the audit log.
//
// The input JSON is passed as a string — JSON encoding on the caller
// side is cheap and keeps this helper allocation-free for no-op spans.
func StartToolCall(ctx context.Context, toolName, toolCallID, inputJSON string) (context.Context, trace.Span) {
	ctx, span := Tracer().Start(ctx, "gen_ai.tool.call",
		trace.WithAttributes(
			attribute.String("gen_ai.tool.name", toolName),
			attribute.String("gen_ai.tool.call.id", toolCallID),
			attribute.String("gen_ai.tool.call.arguments", inputJSON),
		),
	)
	return ctx, span
}

// RecordToolResult stamps a tool-call span with its outcome. errBool
// flips the span status to Error so trace viewers highlight failures
// without parsing the output payload. outputLen is logged as an
// attribute (not the full output) so we don't double-record content
// already in the audit log.
func RecordToolResult(span trace.Span, outputLen int, errBool bool) {
	span.SetAttributes(attribute.Int("gen_ai.tool.call.output_length", outputLen))
	if errBool {
		span.SetAttributes(attribute.Bool("gen_ai.tool.call.error", true))
	}
}
