package audit

import (
	"path/filepath"
	"testing"
	"time"
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
