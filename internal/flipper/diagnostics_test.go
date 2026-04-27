package flipper

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestConnectionReport_EmptyState(t *testing.T) {
	r := NewConnectionReport()

	if r.PassedCount() != 0 {
		t.Errorf("PassedCount empty = %d, want 0", r.PassedCount())
	}
	if r.WarningCount() != 0 {
		t.Errorf("WarningCount empty = %d, want 0", r.WarningCount())
	}
	if r.FailedCount() != 0 {
		t.Errorf("FailedCount empty = %d, want 0", r.FailedCount())
	}
	if r.SkippedCount() != 0 {
		t.Errorf("SkippedCount empty = %d, want 0", r.SkippedCount())
	}
	if got := r.Summary(); got != "no checks recorded" {
		t.Errorf("Summary empty = %q, want %q", got, "no checks recorded")
	}

	if got := len(r.Checks()); got != 0 {
		t.Errorf("Checks() len = %d, want 0", got)
	}

	// Duration on a started-but-not-completed report must be > 0 once a
	// non-trivial period passes (we only want to assert non-negative;
	// real wall-clock probes are flaky).
	if r.Duration() < 0 {
		t.Errorf("Duration on running report = %v, want >= 0", r.Duration())
	}

	// A nil report must answer everything cleanly.
	var nr *ConnectionReport
	if nr.Summary() != "no checks recorded" {
		t.Errorf("nil report Summary = %q", nr.Summary())
	}
	if nr.PassedCount() != 0 || nr.WarningCount() != 0 || nr.FailedCount() != 0 || nr.SkippedCount() != 0 {
		t.Errorf("nil report counts not all zero")
	}
	if nr.Duration() != 0 {
		t.Errorf("nil report Duration = %v, want 0", nr.Duration())
	}
	if got := nr.Checks(); got != nil {
		t.Errorf("nil report Checks = %v, want nil", got)
	}
}

func TestConnectionReport_AddAggregateCounts(t *testing.T) {
	r := NewConnectionReport()
	r.Add(Check{Name: "transport.open", Level: LevelPass, Detail: "serial://x", Elapsed: 1 * time.Millisecond})
	r.Add(Check{Name: "transport.dial", Level: LevelPass, Detail: "/dev/ttyACM0", Elapsed: 5 * time.Millisecond})
	r.Add(Check{Name: "handshake", Level: LevelWarn, Detail: "retry-1", Elapsed: 12 * time.Millisecond})
	r.Add(Check{Name: "detect_capabilities", Level: LevelFail, Detail: "boom", Elapsed: 7 * time.Millisecond})
	r.Add(Check{Name: "rpc.open", Level: LevelSkipped, Detail: "non-ble"})

	if got, want := r.PassedCount(), 2; got != want {
		t.Errorf("PassedCount = %d, want %d", got, want)
	}
	if got, want := r.WarningCount(), 1; got != want {
		t.Errorf("WarningCount = %d, want %d", got, want)
	}
	if got, want := r.FailedCount(), 1; got != want {
		t.Errorf("FailedCount = %d, want %d", got, want)
	}
	if got, want := r.SkippedCount(), 1; got != want {
		t.Errorf("SkippedCount = %d, want %d", got, want)
	}

	checks := r.Checks()
	if len(checks) != 5 {
		t.Fatalf("Checks() len = %d, want 5", len(checks))
	}
	if checks[0].Name != "transport.open" || checks[3].Name != "detect_capabilities" {
		t.Errorf("Checks() lost insertion order: %+v", checks)
	}

	// Mutating the returned slice must not affect the report.
	checks[0].Level = LevelFail
	if r.Checks()[0].Level != LevelPass {
		t.Errorf("Checks() returned a live slice; mutation leaked into the report")
	}

	r.Complete()
	if r.CompletedAt.IsZero() {
		t.Errorf("Complete() did not stamp CompletedAt")
	}
	if r.Duration() <= 0 {
		t.Errorf("Duration after Complete = %v, want > 0", r.Duration())
	}
}

func TestConnectionReport_Summary(t *testing.T) {
	tests := []struct {
		name   string
		checks []Check
		want   string
	}{
		{
			name:   "no checks",
			checks: nil,
			want:   "no checks recorded",
		},
		{
			name: "all pass",
			checks: []Check{
				{Name: "a", Level: LevelPass},
				{Name: "b", Level: LevelPass},
				{Name: "c", Level: LevelPass},
			},
			want: "3 passed",
		},
		{
			name: "has warnings",
			checks: []Check{
				{Name: "a", Level: LevelPass},
				{Name: "b", Level: LevelPass},
				{Name: "c", Level: LevelWarn},
			},
			want: "2 passed, 1 warning",
		},
		{
			name: "has failures",
			checks: []Check{
				{Name: "a", Level: LevelPass},
				{Name: "b", Level: LevelWarn},
				{Name: "c", Level: LevelWarn},
				{Name: "d", Level: LevelFail},
				{Name: "e", Level: LevelSkipped},
			},
			want: "1 passed, 2 warnings, 1 failed, 1 skipped",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewConnectionReport()
			for _, c := range tt.checks {
				r.Add(c)
			}
			if got := r.Summary(); got != tt.want {
				t.Errorf("Summary = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConnectionReport_MarshalJSONShape(t *testing.T) {
	r := NewConnectionReport()
	r.Add(Check{Name: "transport.open", Level: LevelPass, Detail: "serial://acm0"})
	r.Add(Check{Name: "transport.dial", Level: LevelPass, Detail: "/dev/ttyACM0", Elapsed: 5 * time.Millisecond})
	r.Add(Check{Name: "handshake", Level: LevelFail, Detail: "no prompt", Elapsed: 10 * time.Millisecond})
	r.Complete()

	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal: %v: %s", err, b)
	}

	// The keys below are operator-facing — jq pipelines and the cockpit
	// frontend read them by name. Renames here are breaking changes.
	wantKeys := []string{
		"started_at", "completed_at", "duration_ns", "summary",
		"passed_count", "warning_count", "failed_count", "skipped_count",
		"checks",
	}
	for _, k := range wantKeys {
		if _, ok := got[k]; !ok {
			t.Errorf("missing top-level key %q in %v", k, keys(got))
		}
	}

	if got["passed_count"].(float64) != 2 {
		t.Errorf("passed_count = %v, want 2", got["passed_count"])
	}
	if got["failed_count"].(float64) != 1 {
		t.Errorf("failed_count = %v, want 1", got["failed_count"])
	}

	checks, ok := got["checks"].([]any)
	if !ok {
		t.Fatalf("checks not an array: %T", got["checks"])
	}
	if len(checks) != 3 {
		t.Fatalf("checks len = %d, want 3", len(checks))
	}
	first := checks[0].(map[string]any)
	for _, k := range []string{"name", "level", "detail", "elapsed_ns"} {
		if _, ok := first[k]; !ok {
			t.Errorf("first check missing key %q in %v", k, keys(first))
		}
	}
	if first["name"] != "transport.open" {
		t.Errorf("first check name = %v, want transport.open", first["name"])
	}
	if first["level"] != string(LevelPass) {
		t.Errorf("first check level = %v, want %s", first["level"], LevelPass)
	}

	// Summary is preserved verbatim — the frontend renders it as the
	// banner subtitle without re-deriving from counts.
	if !strings.Contains(got["summary"].(string), "passed") {
		t.Errorf("summary = %q, want a 'passed' phrase", got["summary"])
	}
}

func TestConnectionReport_MarshalJSON_Nil(t *testing.T) {
	var r *ConnectionReport
	b, err := r.MarshalJSON()
	if err != nil {
		t.Fatalf("nil MarshalJSON: %v", err)
	}
	if string(b) != "null" {
		t.Errorf("nil MarshalJSON = %q, want null", b)
	}

	if r.ToJSON() != nil {
		t.Errorf("nil ToJSON should return nil")
	}
}

func TestConnectionReport_ToJSON(t *testing.T) {
	r := NewConnectionReport()
	r.Add(Check{Name: "transport.open", Level: LevelPass})
	r.Complete()

	out := r.ToJSON()
	m, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("ToJSON returned %T, want map[string]any", out)
	}
	if _, ok := m["checks"]; !ok {
		t.Errorf("ToJSON map missing checks key: %v", keys(m))
	}
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
