package audit

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/risk"
)

// openTestLog constructs an audit log backed by a temp-file DB. Pure
// in-memory (":memory:") would be faster but modernc sqlite doesn't share
// connections across goroutines well with that URI, and the test already
// runs under 2s with a real file.
func openTestLog(t *testing.T) *Log {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	log, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { log.Close() })
	return log
}

// seed inserts a small mixed batch. Returns the timestamps actually written
// so tests can reason about "since"/"until" windows without depending on
// whatever time.Now was at insert.
func seed(t *testing.T, log *Log) {
	t.Helper()
	// Fixed sessions so session filtering has something deterministic to
	// separate. The production Record path uses log.sessionID, so we swap
	// it in-place per insert.
	entries := []struct {
		sess    string
		tool    string
		risk    string
		level   Level
		input   string
		output  string
		success bool
	}{
		{"s1", "rfid_read", "medium", LevelAction, `{"mode":"lf"}`, "uid: 1234", true},
		{"s1", "rfid_emulate", "high", LevelAction, `{"protocol":"em4100"}`, "emulating", true},
		{"s1", "nfc_detect", "medium", LevelAction, `{}`, "bank card detected", true},
		{"s2", "subghz_transmit", "high", LevelAction, `{"file":"a.sub"}`, "transmit failed", false},
		{"s2", "storage_read", "low", LevelAction, `{"path":"/ext/x"}`, "ok", true},
	}
	for _, e := range entries {
		log.sessionID = e.sess
		log.Record(e.tool, map[string]string{"raw": e.input}, e.output, e.risk, e.level, 10*time.Millisecond, e.success)
	}
}

func TestQueryFilteredByTool(t *testing.T) {
	log := openTestLog(t)
	seed(t, log)
	got, err := log.QueryFiltered(Filter{Tool: "rfid"})
	if err != nil {
		t.Fatalf("QueryFiltered: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 rfid rows, got %d", len(got))
	}
	for _, e := range got {
		if !contains(e.Tool, "rfid") {
			t.Errorf("unexpected tool %q in rfid filter", e.Tool)
		}
	}
}

func TestQueryFilteredByRisk(t *testing.T) {
	log := openTestLog(t)
	seed(t, log)
	got, err := log.QueryFiltered(Filter{Risk: "high"})
	if err != nil {
		t.Fatalf("QueryFiltered: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 high-risk rows, got %d", len(got))
	}
}

func TestQueryFilteredBySession(t *testing.T) {
	log := openTestLog(t)
	seed(t, log)
	got, err := log.QueryFiltered(Filter{Session: "s2"})
	if err != nil {
		t.Fatalf("QueryFiltered: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 s2 rows, got %d (%+v)", len(got), got)
	}
}

func TestQueryFilteredContains(t *testing.T) {
	log := openTestLog(t)
	seed(t, log)
	got, err := log.QueryFiltered(Filter{Contains: "bank card"})
	if err != nil {
		t.Fatalf("QueryFiltered: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 row matching 'bank card', got %d", len(got))
	}
	if got[0].Tool != "nfc_detect" {
		t.Errorf("unexpected row %+v", got[0])
	}
}

func TestQueryFilteredSuccess(t *testing.T) {
	log := openTestLog(t)
	seed(t, log)
	f := false
	got, err := log.QueryFiltered(Filter{Success: &f})
	if err != nil {
		t.Fatalf("QueryFiltered: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 failed row, got %d", len(got))
	}
	if got[0].Success {
		t.Error("expected Success=false")
	}
}

func TestQueryFilteredSinceUntil(t *testing.T) {
	log := openTestLog(t)
	// Hand-insert rows with explicit timestamps so the window test is
	// deterministic regardless of execution speed.
	ts := []time.Time{
		time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 3, 2, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 3, 3, 12, 0, 0, 0, time.UTC),
	}
	for i, at := range ts {
		if _, err := log.db.Exec(`INSERT INTO audit_log (timestamp, tool, input, output, risk, level, session_id, duration_ms, success)
			VALUES (?, ?, '{}', '', 'low', 'action', 's', 1, 1)`,
			at.Format(time.RFC3339), "t"+itoa(i)); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	got, err := log.QueryFiltered(Filter{
		Since: time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC),
		Until: time.Date(2026, 3, 2, 23, 59, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("QueryFiltered: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 row in window, got %d", len(got))
	}
	if got[0].Tool != "t1" {
		t.Errorf("wrong row in window: %+v", got[0])
	}
}

func TestQueryFilteredCombined(t *testing.T) {
	log := openTestLog(t)
	seed(t, log)
	tr := true
	got, err := log.QueryFiltered(Filter{Tool: "rfid", Risk: "medium", Success: &tr})
	if err != nil {
		t.Fatalf("QueryFiltered: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 combined row, got %d", len(got))
	}
	if got[0].Tool != "rfid_read" {
		t.Errorf("combined filter returned %+v", got[0])
	}
}

func TestQueryFilteredLimitOffset(t *testing.T) {
	log := openTestLog(t)
	// Insert 5 rows of the same tool so limit/offset has something to pin.
	for i := 0; i < 5; i++ {
		log.Record("nfc_detect", map[string]int{"i": i}, "ok", "medium", LevelAction, 0, true)
	}
	page1, err := log.QueryFiltered(Filter{Tool: "nfc_detect", Limit: 2})
	if err != nil || len(page1) != 2 {
		t.Fatalf("page1: len=%d err=%v", len(page1), err)
	}
	page2, err := log.QueryFiltered(Filter{Tool: "nfc_detect", Limit: 2, Offset: 2})
	if err != nil || len(page2) != 2 {
		t.Fatalf("page2: len=%d err=%v", len(page2), err)
	}
	if page1[0].ID == page2[0].ID {
		t.Errorf("offset did not advance (page1.ID=%d page2.ID=%d)", page1[0].ID, page2[0].ID)
	}
}

// TestRecordUnmarshallableInput verifies that when the caller passes input
// that fails to JSON-marshal (e.g. contains a channel), Record still writes
// a row with a marshal-error placeholder rather than swallowing the failure
// and emitting an empty input field.
func TestRecordUnmarshallableInput(t *testing.T) {
	log := openTestLog(t)
	bad := map[string]any{"ch": make(chan int)}
	log.Record("test_tool", bad, "ok", "low", LevelInfo, 0, true)
	got, err := log.QueryFiltered(Filter{Tool: "test_tool"})
	if err != nil {
		t.Fatalf("QueryFiltered: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	if got[0].Input == "" {
		t.Errorf("Input is empty; want marshal-error placeholder")
	}
	if !strings.Contains(got[0].Input, "_marshal_error") {
		t.Errorf("Input = %q; want substring _marshal_error", got[0].Input)
	}
}

func TestExistingAPIsUnchanged(t *testing.T) {
	// Regression gate: the new DSL must not break Query/QueryBySession/Stats.
	log := openTestLog(t)
	seed(t, log)
	if _, err := log.Query(10); err != nil {
		t.Errorf("Query: %v", err)
	}
	if _, err := log.QueryBySession("s1"); err != nil {
		t.Errorf("QueryBySession: %v", err)
	}
	if _, err := log.Stats(); err != nil {
		t.Errorf("Stats: %v", err)
	}
}

func TestTopToolsAndRisks(t *testing.T) {
	log := openTestLog(t)
	seed(t, log)
	tools, err := log.TopTools(time.Time{}, 5)
	if err != nil {
		t.Fatalf("TopTools: %v", err)
	}
	if len(tools) == 0 {
		t.Fatalf("TopTools returned empty")
	}
	risks, err := log.TopRisks(time.Time{})
	if err != nil {
		t.Fatalf("TopRisks: %v", err)
	}
	if len(risks) == 0 {
		t.Fatalf("TopRisks returned empty")
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [12]byte
	n := len(buf)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		n--
		buf[n] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		n--
		buf[n] = '-'
	}
	return string(buf[n:])
}

func TestRequireOpen(t *testing.T) {
	log := openTestLog(t)

	cases := []struct {
		name    string
		log     *Log
		level   risk.Level
		wantErr bool
	}{
		{"nil+low", nil, risk.Low, false},
		{"nil+medium", nil, risk.Medium, false},
		{"nil+high", nil, risk.High, true},
		{"nil+critical", nil, risk.Critical, true},
		{"open+low", log, risk.Low, false},
		{"open+high", log, risk.High, false},
		{"open+critical", log, risk.Critical, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := RequireOpen(tc.log, tc.level)
			if tc.wantErr && err == nil {
				t.Errorf("RequireOpen(%v, %v): want error, got nil", tc.log == nil, tc.level)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("RequireOpen(%v, %v): want nil, got %v", tc.log == nil, tc.level, err)
			}
		})
	}
}

// TestObserverPanicDoesNotCrashRecord pins the deferred-recover guard
// inside notify(): a buggy observer that panics must not propagate
// the panic up through Record and crash the agent's tool-dispatch
// goroutine. Wires two observers — one panics, one runs after — and
// confirms the second still fires when the first goes off.
func TestObserverPanicDoesNotCrashRecord(t *testing.T) {
	log := openTestLog(t)
	var afterPanicRan bool
	log.AddObserver(func(_ Entry) {
		panic("test-observer-panic-marker")
	})
	log.AddObserver(func(_ Entry) {
		afterPanicRan = true
	})
	// If notify lets the panic escape, this Record call panics the
	// goroutine and the test fails with "test panicked".
	log.Record("panic_test", map[string]string{"x": "y"}, "ok", "low", LevelInfo, 0, true)
	if !afterPanicRan {
		t.Error("observer registered after a panicking observer should still run")
	}
}
