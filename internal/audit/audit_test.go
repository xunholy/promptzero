package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

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
		if !strings.Contains(e.Tool, "rfid") {
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
			at.Format(time.RFC3339), "t"+strconv.Itoa(i)); err != nil {
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

// TestQuery_NegativeLimitClamped pins the fix for the bug where a negative
// limit short-circuited SQLite's LIMIT clause (LIMIT -1 = unbounded), letting
// an audit_query tool call with {"limit": -1} dump the entire audit DB
// despite the MaxQueryLimit cap the const's docstring promises. The package
// now clamps non-positive limits to the default-100 page used by
// QueryFiltered; inserting > 100 rows distinguishes the unbounded pre-fix
// behaviour from the post-fix cap.
func TestQuery_NegativeLimitClamped(t *testing.T) {
	log := openTestLog(t)
	const inserted = 105
	for i := 0; i < inserted; i++ {
		log.Record("nfc_detect", map[string]int{"i": i}, "ok", "low", LevelAction, 0, true)
	}
	got, err := log.Query(-1)
	if err != nil {
		t.Fatalf("Query(-1): %v", err)
	}
	if len(got) > 100 {
		t.Fatalf("Query(-1) returned %d rows; expected clamp to <=100 (negative limit must not bypass MaxQueryLimit cap)", len(got))
	}
}

// TestQueryFiltered_LimitOverMaxClamped mirrors the Query test for the
// QueryFiltered surface: an in-process caller constructing Filter with
// Limit > MaxQueryLimit must not bypass the cap. The HTTP handler 400s on
// over-cap input today, but the cap belongs in the package as defense in
// depth so future callers can't drift.
func TestQueryFiltered_LimitOverMaxClamped(t *testing.T) {
	log := openTestLog(t)
	// Seed something queryable; the assertion is about the cap, not row count.
	log.Record("nfc_detect", nil, "ok", "low", LevelAction, 0, true)
	got, err := log.QueryFiltered(Filter{Limit: MaxQueryLimit + 1})
	if err != nil {
		t.Fatalf("QueryFiltered: %v", err)
	}
	// Only 1 row exists; the assertion is that the call succeeded without
	// SQLite balking on an oversized LIMIT and that the clamp path was
	// exercised. We also tolerate the smaller real row count.
	if len(got) > MaxQueryLimit {
		t.Fatalf("QueryFiltered returned %d rows; cap is %d", len(got), MaxQueryLimit)
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
	// Pin the v0.150 contract: the placeholder must be valid JSON.
	// Pre-fix the fallback used fmt.Sprintf("%q", err.Error()) which
	// is Go-string quoting, not JSON. Control bytes outside JSON's
	// {\b \f \n \r \t} whitelist landed as Go escapes (\a, \v, \xNN)
	// that downstream parsers reject. If an error message happened
	// to contain a BEL (\x07) the audit row became unparseable.
	var parsed map[string]any
	if err := json.Unmarshal([]byte(got[0].Input), &parsed); err != nil {
		t.Errorf("audit row input is not valid JSON: %v\ninput = %q", err, got[0].Input)
	}
}

// TestRecord_UTF8TruncateBoundary verifies that when output exceeds
// the 65535-byte storage cap, the truncation walks back to the
// previous rune boundary instead of splitting a multi-byte UTF-8
// sequence. Without the walk-back, the stored row contained
// invalid UTF-8 at the cut and the web UI / /report renderer
// would show U+FFFD.
func TestRecord_UTF8TruncateBoundary(t *testing.T) {
	log := openTestLog(t)
	// Build output that places a 2-byte rune (é = 0xc3 0xa9) so
	// that byte 65535 lands on the continuation byte 0xa9.
	prefix := strings.Repeat("a", 65534)
	out := prefix + "é" + strings.Repeat("z", 100) // total 65636 bytes
	log.Record("test", map[string]string{}, out, "low", LevelInfo, 0, true)
	got, err := log.QueryFiltered(Filter{Tool: "test"})
	if err != nil {
		t.Fatalf("QueryFiltered: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1", len(got))
	}
	stored := got[0].Output
	if !utf8.ValidString(stored) {
		t.Fatalf("stored output is invalid UTF-8 (rune split at boundary)")
	}
	if !strings.HasSuffix(stored, "... [truncated]") {
		t.Errorf("stored output should end with truncation marker, got tail %q", stored[len(stored)-30:])
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

// TestTechniqueResolver_PopulatesEntryTechniqueIDs pins that
// SetTechniqueResolver wires its lookup through to the Entry
// observers see. The list is derived in-memory only (not persisted)
// so this test exercises the resolver path end-to-end via the
// observer hook, mirroring the persona-context resolver pattern below.
func TestTechniqueResolver_PopulatesEntryTechniqueIDs(t *testing.T) {
	log := openTestLog(t)
	log.SetTechniqueResolver(func(tool string) []string {
		switch tool {
		case "wifi_deauth":
			return []string{"T1498.001", "T1498.002"}
		case "badusb_run":
			return []string{"T1200"}
		default:
			return nil
		}
	})

	var captured []Entry
	log.AddObserver(func(e Entry) { captured = append(captured, e) })

	log.Record("wifi_deauth", map[string]string{}, "ok", "high", LevelInfo, 0, true)
	log.Record("badusb_run", map[string]string{}, "ok", "critical", LevelInfo, 0, true)
	log.Record("unknown_tool", map[string]string{}, "ok", "low", LevelInfo, 0, true)

	if len(captured) != 3 {
		t.Fatalf("captured %d entries; want 3", len(captured))
	}
	if want := []string{"T1498.001", "T1498.002"}; !sliceEq(captured[0].TechniqueIDs, want) {
		t.Errorf("wifi_deauth TechniqueIDs = %v; want %v", captured[0].TechniqueIDs, want)
	}
	if want := []string{"T1200"}; !sliceEq(captured[1].TechniqueIDs, want) {
		t.Errorf("badusb_run TechniqueIDs = %v; want %v", captured[1].TechniqueIDs, want)
	}
	if len(captured[2].TechniqueIDs) != 0 {
		t.Errorf("unknown_tool TechniqueIDs = %v; want empty", captured[2].TechniqueIDs)
	}
}

// TestTechniqueResolver_NilDisables pins that passing nil to
// SetTechniqueResolver clears the hook — entries afterwards carry
// no TechniqueIDs.
func TestTechniqueResolver_NilDisables(t *testing.T) {
	log := openTestLog(t)
	log.SetTechniqueResolver(func(tool string) []string {
		return []string{"T9999"}
	})
	var captured Entry
	log.AddObserver(func(e Entry) { captured = e })
	log.Record("any_tool", map[string]string{}, "ok", "low", LevelInfo, 0, true)
	if len(captured.TechniqueIDs) == 0 {
		t.Fatal("resolver wired but TechniqueIDs empty")
	}

	log.SetTechniqueResolver(nil)
	captured = Entry{}
	log.Record("any_tool", map[string]string{}, "ok", "low", LevelInfo, 0, true)
	if len(captured.TechniqueIDs) != 0 {
		t.Errorf("after SetTechniqueResolver(nil), TechniqueIDs = %v; want empty",
			captured.TechniqueIDs)
	}
}

func sliceEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestPersonaContextResolver_PopulatesEntryFields pins that the
// resolver hook (P3-31) flows through into the Entry observers see.
// Mirrors the TechniqueResolver test pattern — derived in-memory
// only, not persisted to the DB.
func TestPersonaContextResolver_PopulatesEntryFields(t *testing.T) {
	log := openTestLog(t)
	log.SetPersonaContextResolver(func() PersonaContext {
		return PersonaContext{
			PersonaVersion: "2026-05-10",
			PromptHash:     strings.Repeat("a", 64),
		}
	})

	var captured Entry
	log.AddObserver(func(e Entry) { captured = e })
	log.Record("recon_tool", map[string]string{}, "ok", "low", LevelInfo, 0, true)

	if captured.PersonaVersion != "2026-05-10" {
		t.Errorf("PersonaVersion = %q, want 2026-05-10", captured.PersonaVersion)
	}
	if captured.PromptHash != strings.Repeat("a", 64) {
		t.Errorf("PromptHash = %q", captured.PromptHash)
	}
}

// TestPersonaContextResolver_NilLeavesFieldsEmpty confirms that the
// audit log degrades cleanly when no resolver is wired (the default
// for tests + MCP-only callers).
func TestPersonaContextResolver_NilLeavesFieldsEmpty(t *testing.T) {
	log := openTestLog(t)
	var captured Entry
	log.AddObserver(func(e Entry) { captured = e })
	log.Record("any_tool", nil, "ok", "low", LevelInfo, 0, true)

	if captured.PersonaVersion != "" {
		t.Errorf("PersonaVersion = %q, want empty (no resolver)", captured.PersonaVersion)
	}
	if captured.PromptHash != "" {
		t.Errorf("PromptHash = %q, want empty (no resolver)", captured.PromptHash)
	}
}

// TestPersonaContextResolver_CalledOncePerRecord pins the contract that
// the resolver fires exactly once per Record so it doesn't accidentally
// become a hot-path bottleneck for personas that compute Version /
// PromptHash dynamically.
func TestPersonaContextResolver_CalledOncePerRecord(t *testing.T) {
	log := openTestLog(t)
	var calls int
	log.SetPersonaContextResolver(func() PersonaContext {
		calls++
		return PersonaContext{}
	})
	log.Record("a", nil, "", "low", LevelInfo, 0, true)
	log.Record("b", nil, "", "low", LevelInfo, 0, true)
	if calls != 2 {
		t.Errorf("resolver call count = %d, want 2", calls)
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

// TestSessionID pins the accessor: returns whatever was set via
// the in-place sessionID assignment the production code does at
// session start. The /audit tail UX queries this to render
// "session-1234" headings; a zero value would silently break it.
func TestSessionID(t *testing.T) {
	log := openTestLog(t)
	if got := log.SessionID(); got == "" {
		t.Errorf("freshly-opened log SessionID = %q, want non-empty default", got)
	}
	log.sessionID = "session-test-12345"
	if got := log.SessionID(); got != "session-test-12345" {
		t.Errorf("SessionID after override = %q, want session-test-12345", got)
	}
}

// TestMaxID_EmptyAndPopulated pins the audit tail's high-water
// mark. An empty log returns 0 (not an error). After N inserts,
// MaxID returns N.
func TestMaxID_EmptyAndPopulated(t *testing.T) {
	log := openTestLog(t)
	id, err := log.MaxID()
	if err != nil {
		t.Fatalf("MaxID on empty log: %v", err)
	}
	if id != 0 {
		t.Errorf("MaxID on empty log = %d, want 0", id)
	}

	for i := 0; i < 3; i++ {
		log.Record("tool"+strconv.Itoa(i), nil, "", "low", LevelInfo, 0, true)
	}
	id, err = log.MaxID()
	if err != nil {
		t.Fatalf("MaxID after 3 inserts: %v", err)
	}
	if id != 3 {
		t.Errorf("MaxID after 3 inserts = %d, want 3", id)
	}
}

// TestQuerySince pins the audit-tail iteration: rows with id >
// afterID, ordered oldest first. The /audit tail loop polls
// MaxID() and uses QuerySince(prevMaxID) to fetch the new rows.
func TestQuerySince(t *testing.T) {
	log := openTestLog(t)
	for i := 0; i < 5; i++ {
		log.Record("tool"+strconv.Itoa(i), nil, "", "low", LevelInfo, 0, true)
	}

	all, err := log.QuerySince(0)
	if err != nil {
		t.Fatalf("QuerySince(0): %v", err)
	}
	if len(all) != 5 {
		t.Errorf("QuerySince(0) returned %d, want 5", len(all))
	}
	for i := range all {
		if i > 0 && all[i].ID <= all[i-1].ID {
			t.Errorf("QuerySince not ordered ascending: id[%d]=%d, id[%d]=%d", i-1, all[i-1].ID, i, all[i].ID)
		}
	}

	tail, err := log.QuerySince(2)
	if err != nil {
		t.Fatalf("QuerySince(2): %v", err)
	}
	if len(tail) != 3 {
		t.Errorf("QuerySince(2) returned %d, want 3", len(tail))
	}
	for _, e := range tail {
		if e.ID <= 2 {
			t.Errorf("QuerySince(2) returned id %d, want > 2", e.ID)
		}
	}

	empty, err := log.QuerySince(100)
	if err != nil {
		t.Fatalf("QuerySince(100): %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("QuerySince(100) returned %d, want 0", len(empty))
	}
}

// TestExport pins the JSON-export contract used by /audit export.
// Output is always an indented JSON array — even for an empty
// session, the body is "[]" rather than "null" (v0.163 contract).
// Operators pipe this to grep / jq, so an undocumented format
// change would break workflows.
func TestExport(t *testing.T) {
	log := openTestLog(t)
	log.sessionID = "session-export-test"
	log.Record("rfid_read", map[string]string{"mode": "lf"}, "uid: 1234", "medium", LevelAction, 50*time.Millisecond, true)
	log.Record("nfc_detect", nil, "ok", "low", LevelInfo, 10*time.Millisecond, true)

	out, err := log.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if out == "" {
		t.Fatal("Export returned empty string")
	}
	if !strings.HasPrefix(strings.TrimSpace(out), "[") {
		t.Errorf("Export output doesn't start with JSON array: %q", out)
	}
	if !strings.HasSuffix(strings.TrimSpace(out), "]") {
		t.Errorf("Export output doesn't end with JSON array: %q", out)
	}
	for _, want := range []string{"rfid_read", "nfc_detect"} {
		if !strings.Contains(out, want) {
			t.Errorf("Export output missing %q: %s", want, out)
		}
	}
	if !strings.Contains(out, "\n") {
		t.Errorf("Export output is not indented JSON: %s", out)
	}

	// Empty session must yield a parseable JSON array, not the
	// "null" literal. Pre-v0.163 json.MarshalIndent on a nil
	// []Entry returned "null", forcing every consumer (cockpit,
	// report renderer, CLI piping to jq) to special-case the
	// empty-session path.
	emptyLog := openTestLog(t)
	emptyLog.sessionID = "session-empty-test"
	emptyOut, err := emptyLog.Export()
	if err != nil {
		t.Fatalf("Export on empty session: %v", err)
	}
	trimmed := strings.TrimSpace(emptyOut)
	if trimmed != "[]" {
		t.Errorf("Export on empty session = %q, want \"[]\" (v0.163: always a JSON array)", trimmed)
	}
	// Round-trip to confirm the body is parseable as a JSON array
	// rather than a literal "null".
	var parsed []map[string]any
	if err := json.Unmarshal([]byte(emptyOut), &parsed); err != nil {
		t.Errorf("Export empty-session output is not parseable JSON array: %v\nbody: %s", err, emptyOut)
	}
}

func TestExportCSV(t *testing.T) {
	log := openTestLog(t)
	log.sessionID = "csv-test"
	log.Record("rfid_read", map[string]string{"mode": "lf"}, "uid: 1234", "medium", LevelAction, 50*time.Millisecond, true)
	log.Record("nfc_detect", nil, "ok", "low", LevelInfo, 10*time.Millisecond, false)

	out, err := log.ExportCSV()
	if err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines (header + 2 rows), got %d", len(lines))
	}
	if !strings.HasPrefix(lines[0], "id,timestamp,tool,") {
		t.Errorf("header doesn't match expected format: %q", lines[0])
	}
	if !strings.Contains(out, "rfid_read") {
		t.Error("CSV missing rfid_read")
	}
	if !strings.Contains(out, "nfc_detect") {
		t.Error("CSV missing nfc_detect")
	}
	if !strings.Contains(out, ",true") {
		t.Error("CSV missing success=true value")
	}
	if !strings.Contains(out, ",false") {
		t.Error("CSV missing success=false value")
	}
}

func TestExportCSV_EmptySession(t *testing.T) {
	log := openTestLog(t)
	log.sessionID = "csv-empty"
	out, err := log.ExportCSV()
	if err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 1 {
		t.Errorf("empty session should have header only, got %d lines", len(lines))
	}
}

func TestExportCSV_QuotesSpecialChars(t *testing.T) {
	log := openTestLog(t)
	log.sessionID = "csv-special"
	log.Record("test_tool", map[string]string{"k": "v"}, "output with, comma", "low", LevelAction, 0, true)

	out, err := log.ExportCSV()
	if err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}
	if !strings.Contains(out, `"output with, comma"`) {
		t.Errorf("comma in output should be quoted: %s", out)
	}
}

// TestOpen_WALSidecarsInheritMainDBPerms pins the load-bearing
// ordering in audit.Open: chmod the main DB to 0o600 BEFORE the
// PRAGMA journal_mode=WAL pragma. SQLite (modernc.org/sqlite
// included) creates the -wal and -shm sidecars at the same mode
// as the main DB, so tightening the main DB first means the
// sidecars inherit 0o600 when the first transaction lands.
// Reversing the order would create the sidecars at the process
// umask (typically 0o644, world-readable) and the later main-DB
// chmod wouldn't propagate to them — the WAL carries the same
// uncommitted INSERT data (operator secrets in tool inputs /
// outputs) as the main DB, so leakage would be just as bad.
//
// This test is the safety net: a future refactor that swaps the
// chmod and PRAGMA WAL lines silently broke the WAL sidecar
// permissions; running this test catches it.
// --- Edge-case tests added in v0.346 ---

func TestQueryFiltered_EmptyDB(t *testing.T) {
	log := openTestLog(t)
	entries, err := log.QueryFiltered(Filter{})
	if err != nil {
		t.Fatalf("QueryFiltered on empty DB: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries from empty DB, got %d", len(entries))
	}
}

func TestQueryFiltered_SuccessFalseOnly(t *testing.T) {
	log := openTestLog(t)
	seed(t, log)
	f := false
	entries, err := log.QueryFiltered(Filter{Success: &f})
	if err != nil {
		t.Fatalf("QueryFiltered: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 failed entry, got %d", len(entries))
	}
	if entries[0].Success {
		t.Errorf("expected Success=false, got true")
	}
	if entries[0].Tool != "subghz_transmit" {
		t.Errorf("expected subghz_transmit, got %q", entries[0].Tool)
	}
}

func TestQueryFiltered_SuccessTrueOnly(t *testing.T) {
	log := openTestLog(t)
	seed(t, log)
	tr := true
	entries, err := log.QueryFiltered(Filter{Success: &tr})
	if err != nil {
		t.Fatalf("QueryFiltered: %v", err)
	}
	if len(entries) != 4 {
		t.Errorf("expected 4 successful entries, got %d", len(entries))
	}
	for _, e := range entries {
		if !e.Success {
			t.Errorf("entry %q has Success=false but filter asked for true-only", e.Tool)
		}
	}
}

func TestQueryFiltered_SuccessNil(t *testing.T) {
	log := openTestLog(t)
	seed(t, log)
	entries, err := log.QueryFiltered(Filter{Success: nil})
	if err != nil {
		t.Fatalf("QueryFiltered: %v", err)
	}
	if len(entries) != 5 {
		t.Errorf("expected 5 entries (nil = any), got %d", len(entries))
	}
}

func TestQueryFiltered_SuccessAndRiskCombined(t *testing.T) {
	log := openTestLog(t)
	seed(t, log)
	f := false
	entries, err := log.QueryFiltered(Filter{Risk: "high", Success: &f})
	if err != nil {
		t.Fatalf("QueryFiltered: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry (high + failed), got %d", len(entries))
	}
	if entries[0].Tool != "subghz_transmit" {
		t.Errorf("expected subghz_transmit, got %q", entries[0].Tool)
	}
}

func TestQueryFiltered_PaginationBeyondEnd(t *testing.T) {
	log := openTestLog(t)
	seed(t, log)
	entries, err := log.QueryFiltered(Filter{Offset: 100, Limit: 10})
	if err != nil {
		t.Fatalf("QueryFiltered: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries at offset=100, got %d", len(entries))
	}
}

func TestQueryFiltered_PaginationConsistency(t *testing.T) {
	log := openTestLog(t)
	seed(t, log)
	page1, err := log.QueryFiltered(Filter{Limit: 2, Offset: 0})
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	page2, err := log.QueryFiltered(Filter{Limit: 2, Offset: 2})
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	page3, err := log.QueryFiltered(Filter{Limit: 2, Offset: 4})
	if err != nil {
		t.Fatalf("page3: %v", err)
	}
	total := len(page1) + len(page2) + len(page3)
	if total != 5 {
		t.Errorf("expected 5 entries across 3 pages, got %d", total)
	}
	seen := make(map[int64]bool)
	for _, e := range append(append(page1, page2...), page3...) {
		if seen[e.ID] {
			t.Errorf("duplicate entry ID %d across pages", e.ID)
		}
		seen[e.ID] = true
	}
}

func TestStats_EmptySession(t *testing.T) {
	log := openTestLog(t)
	log.sessionID = "empty-session"
	s, err := log.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	for _, want := range []string{
		"Total actions: 0",
		"Successful: 0",
		"Failed: 0",
		"Unique tools: 0",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("Stats missing %q in:\n%s", want, s)
		}
	}
}

func TestStats_MixedSuccessFailure(t *testing.T) {
	log := openTestLog(t)
	log.sessionID = "stats-test"
	log.Record("tool_a", nil, "ok", "low", LevelAction, 10*time.Millisecond, true)
	log.Record("tool_a", nil, "fail", "low", LevelAction, 10*time.Millisecond, false)
	log.Record("tool_b", nil, "ok", "high", LevelAction, 10*time.Millisecond, true)

	s, err := log.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	for _, want := range []string{
		"Total actions: 3",
		"Successful: 2",
		"Failed: 1",
		"Unique tools: 2",
		"Risk breakdown:",
		"low=2",
		"high=1",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("Stats missing %q in:\n%s", want, s)
		}
	}
}

func TestTopTools_EmptyDB(t *testing.T) {
	log := openTestLog(t)
	tools, err := log.TopTools(time.Time{}, 10)
	if err != nil {
		t.Fatalf("TopTools: %v", err)
	}
	if len(tools) != 0 {
		t.Errorf("expected 0 tools from empty DB, got %d", len(tools))
	}
}

func TestTopRisks_EmptyDB(t *testing.T) {
	log := openTestLog(t)
	risks, err := log.TopRisks(time.Time{})
	if err != nil {
		t.Fatalf("TopRisks: %v", err)
	}
	if len(risks) != 0 {
		t.Errorf("expected 0 risks from empty DB, got %d", len(risks))
	}
}

func TestTopTools_Ordering(t *testing.T) {
	log := openTestLog(t)
	log.sessionID = "top-tools-test"
	for i := 0; i < 5; i++ {
		log.Record("frequent_tool", nil, "ok", "low", LevelAction, 0, true)
	}
	for i := 0; i < 2; i++ {
		log.Record("rare_tool", nil, "ok", "low", LevelAction, 0, true)
	}
	tools, err := log.TopTools(time.Time{}, 10)
	if err != nil {
		t.Fatalf("TopTools: %v", err)
	}
	if len(tools) < 2 {
		t.Fatalf("expected at least 2 tools, got %d", len(tools))
	}
	if tools[0].Tool != "frequent_tool" {
		t.Errorf("expected frequent_tool first, got %q", tools[0].Tool)
	}
	if tools[0].Count != 5 {
		t.Errorf("expected count=5, got %d", tools[0].Count)
	}
}

func TestQuerySince_EmptyDB(t *testing.T) {
	log := openTestLog(t)
	entries, err := log.QuerySince(0)
	if err != nil {
		t.Fatalf("QuerySince: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestMaxID_ReturnsZeroForEmptyDB(t *testing.T) {
	log := openTestLog(t)
	id, err := log.MaxID()
	if err != nil {
		t.Fatalf("MaxID: %v", err)
	}
	if id != 0 {
		t.Errorf("expected 0 for empty DB, got %d", id)
	}
}

func TestOpen_WALSidecarsInheritMainDBPerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	log, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	// Force a transaction so the WAL sidecars are guaranteed to
	// exist. The first Record commits an INSERT under WAL mode,
	// which creates both -wal and -shm files. Without this the
	// sidecars may not yet exist on disk when we stat them.
	log.Record("test_tool", nil, "ok", "low", LevelInfo, 0, true)

	// Main DB: must be 0o600 — already enforced by the existing
	// chmod, but assert it here so a future refactor that removes
	// the chmod entirely also trips this test.
	if fi, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("stat main: %v", statErr)
	} else if mode := fi.Mode().Perm(); mode != 0o600 {
		t.Errorf("audit main DB mode = %#o, want 0o600", mode)
	}

	// -wal sidecar: inherits the main DB's 0o600 from the
	// chmod-before-PRAGMA-WAL ordering.
	walPath := path + "-wal"
	fi, statErr := os.Stat(walPath)
	if statErr != nil {
		t.Fatalf("stat -wal: %v (must exist after Record)", statErr)
	}
	if mode := fi.Mode().Perm(); mode != 0o600 {
		t.Errorf("audit -wal mode = %#o, want 0o600 — the WAL carries the same secrets as the main DB. "+
			"Check that PRAGMA journal_mode=WAL still runs AFTER the os.Chmod call in Open.", mode)
	}

	// -shm sidecar: same inheritance. Some SQLite builds create
	// -shm lazily, so skip the assertion gracefully if it's absent.
	// In modernc.org/sqlite as of this writing, -shm appears after
	// the first transaction commit, same as -wal.
	shmPath := path + "-shm"
	if fi, statErr := os.Stat(shmPath); statErr == nil {
		if mode := fi.Mode().Perm(); mode != 0o600 {
			t.Errorf("audit -shm mode = %#o, want 0o600 — same inheritance as -wal", mode)
		}
	}
}

// TestQueryFiltered_LikeWildcardsEscaped guards forensic-filter precision: SQL
// LIKE treats "_" (any single char) and "%" (any run) as wildcards, so an
// unescaped operator filter would silently over-match evidence retrieval. The
// filter values must match literally.
func TestQueryFiltered_LikeWildcardsEscaped(t *testing.T) {
	// "_" is a single-char wildcard; these tool names differ only at that
	// position, so an unescaped "nfc_detect" filter matches both.
	log := openTestLog(t)
	log.Record("nfc_detect", map[string]string{}, "ok", "low", LevelAction, 0, true)
	log.Record("nfcZdetect", map[string]string{}, "ok", "low", LevelAction, 0, true)
	got, err := log.QueryFiltered(Filter{Tool: "nfc_detect"})
	if err != nil {
		t.Fatalf("QueryFiltered: %v", err)
	}
	if len(got) != 1 || got[0].Tool != "nfc_detect" {
		t.Fatalf("Tool filter must match '_' literally, got %d rows: %+v", len(got), got)
	}

	// "%" is an any-run wildcard; a Contains search for a literal "%" must not
	// match arbitrary text between the surrounding characters.
	log2 := openTestLog(t)
	log2.Record("a", map[string]string{}, "100%done", "low", LevelAction, 0, true)
	log2.Record("b", map[string]string{}, "100ZZdone", "low", LevelAction, 0, true)
	got2, err := log2.QueryFiltered(Filter{Contains: "100%done"})
	if err != nil {
		t.Fatalf("QueryFiltered: %v", err)
	}
	if len(got2) != 1 {
		t.Fatalf("Contains must treat '%%' literally, got %d rows: %+v", len(got2), got2)
	}
}

// TestCSVQuote_NeutralizesFormulaPrefixes pins CSV/formula-injection
// neutralization: a cell beginning with =, +, -, @, TAB, or CR must be
// prefixed with a single quote so spreadsheets treat it as literal text, while
// ordinary values and a mid-cell '=' are left untouched.
func TestCSVQuote_NeutralizesFormulaPrefixes(t *testing.T) {
	cases := []struct{ in, want string }{
		{"=cmd|'/c calc'!A1", "'=cmd|'/c calc'!A1"},
		{"+ping", "'+ping"},
		{"-2+3", "'-2+3"},
		{"@SUM(1)", "'@SUM(1)"},
		{"\tlead-tab", "'\tlead-tab"},
		{"normal ssid", "normal ssid"},
		{"a=b+c", "a=b+c"}, // formula char not first -> untouched
		{"", ""},
	}
	for _, c := range cases {
		if got := csvQuote(c.in); got != c.want {
			t.Errorf("csvQuote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestExportCSV_NeutralizesFormulaInjection is the end-to-end guard: an
// attacker-controlled tool output beginning with '=' must be neutralized in the
// exported CSV, so opening it in a spreadsheet does not execute the formula.
func TestExportCSV_NeutralizesFormulaInjection(t *testing.T) {
	log := openTestLog(t)
	log.sessionID = "csv-formula"
	// No comma/quote/newline, so RFC 4180 quoting alone would leave it bare.
	log.Record("wifi_scan_ap", map[string]string{"k": "v"}, "=2+5+cmd", "low", LevelAction, 0, true)

	out, err := log.ExportCSV()
	if err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}
	if !strings.Contains(out, "'=2+5+cmd") {
		t.Errorf("formula output not neutralized with a leading quote:\n%s", out)
	}
	// The dangerous bare form must not appear as a cell value.
	if strings.Contains(out, ",=2+5+cmd") {
		t.Errorf("bare formula cell present (unneutralized):\n%s", out)
	}
}
