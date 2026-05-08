package eval

import (
	"errors"
	"strings"
	"testing"
)

// TestDefaultSuiteAllPass is the main CI gate — every scenario in
// the Default suite must pass. A regression shows up here loudly,
// with a specific scenario name and error message.
func TestDefaultSuiteAllPass(t *testing.T) {
	r := NewRunner().RegisterAll(Default(t)...)
	results := r.Run()
	if len(results) == 0 {
		t.Fatal("Default suite registered zero scenarios")
	}

	summary := Summarise(results)
	if !AllPassed(results) {
		t.Fatalf("golden suite regressed:\n%s", summary)
	}

	// Log the summary in normal runs so `go test -v ./internal/eval/`
	// surfaces timing + pass count.
	t.Log("\n" + summary)
}

// TestRunner_RunExecutesInRegistrationOrder locks the determinism
// claim — a mix of passing + failing scenarios must be reported in
// stable order so CI output is greppable.
func TestRunner_ResultsMatchRegistered(t *testing.T) {
	r := NewRunner().Register(Scenario{
		Name: "first",
		Run:  func() error { return nil },
	}).Register(Scenario{
		Name: "second",
		Run:  func() error { return errors.New("nope") },
	})
	results := r.Run()
	if len(results) != 2 {
		t.Fatalf("want 2 results, got %d", len(results))
	}
	if results[0].Name != "first" || results[1].Name != "second" {
		t.Errorf("results out of order: %s, %s", results[0].Name, results[1].Name)
	}
	if !results[0].Pass || results[1].Pass {
		t.Errorf("pass/fail mismatch: %+v", results)
	}
	if AllPassed(results) {
		t.Error("AllPassed should be false when one scenario fails")
	}
}

// TestRunner_RecoversFromPanic — a panicking scenario must not abort
// the rest of the suite. The panic text is surfaced in the Result's
// Err field.
func TestRunner_RecoversFromPanic(t *testing.T) {
	r := NewRunner().Register(Scenario{
		Name: "boom",
		Run:  func() error { panic("deliberate") },
	}).Register(Scenario{
		Name: "follow_up",
		Run:  func() error { return nil },
	})
	results := r.Run()
	if len(results) != 2 {
		t.Fatalf("want 2 results, got %d", len(results))
	}
	if results[0].Pass {
		t.Error("panicking scenario should not count as pass")
	}
	if results[0].Err == nil || !strings.Contains(results[0].Err.Error(), "panic") {
		t.Errorf("panic not surfaced in Err: %v", results[0].Err)
	}
	// Stack trace is included so operators can navigate to the
	// panic site without re-running with GOTRACEBACK=all.
	if results[0].Err == nil || !strings.Contains(results[0].Err.Error(), "stack:") {
		t.Errorf("panic Err missing stack trace: %v", results[0].Err)
	}
	if !results[1].Pass {
		t.Error("post-panic scenario should still run and pass")
	}
}

// TestRunner_RunMatchingFiltersByTag exercises the tag filter so
// operators can run a subset (e.g. `go test -run EvalTag/attack`).
func TestRunner_RunMatchingFiltersByTag(t *testing.T) {
	r := NewRunner().RegisterAll(
		Scenario{Name: "a", Tags: []string{"attack"}, Run: func() error { return nil }},
		Scenario{Name: "b", Tags: []string{"snapshot"}, Run: func() error { return nil }},
		Scenario{Name: "c", Tags: []string{"attack", "detector"}, Run: func() error { return nil }},
	)
	got := r.RunMatching("attack")
	if len(got) != 2 {
		t.Fatalf("attack filter should yield 2 results, got %d", len(got))
	}
	names := map[string]bool{}
	for _, r := range got {
		names[r.Name] = true
	}
	for _, want := range []string{"a", "c"} {
		if !names[want] {
			t.Errorf("filter dropped %q", want)
		}
	}
}

// TestSummarise_StableFormat ensures the summary lines are greppable
// — CI and external tooling rely on the PASS: / FAIL: prefixes.
func TestSummarise_StableFormat(t *testing.T) {
	got := Summarise([]Result{
		{Name: "a", Pass: true},
		{Name: "b", Pass: false, Err: errors.New("nope")},
	})
	if !strings.Contains(got, "PASS: a") {
		t.Errorf("summary missing PASS: prefix: %s", got)
	}
	if !strings.Contains(got, "FAIL: b") {
		t.Errorf("summary missing FAIL: prefix: %s", got)
	}
	if !strings.Contains(got, "1 / 2 scenarios passed") {
		t.Errorf("summary missing count line: %s", got)
	}
}

func TestSummarise_EmptyIsHonest(t *testing.T) {
	got := Summarise(nil)
	if !strings.Contains(got, "no scenarios") {
		t.Errorf("empty summary should say so: %s", got)
	}
}
