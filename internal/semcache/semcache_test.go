package semcache

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestKey_DeterministicAndCollisionResistant(t *testing.T) {
	a := Key("task", "claude/4-7", "system", "msg-a")
	b := Key("task", "claude/4-7", "system", "msg-a")
	if a != b {
		t.Errorf("same inputs → different keys: %q vs %q", a, b)
	}

	// Two part-lists that concat to the same string but split differently
	// MUST hash differently — this is the null-terminator's job.
	c := Key("foo", "bar")
	d := Key("fo", "obar")
	if c == d {
		t.Errorf("ambiguous concat collision: %q", c)
	}

	if len(a) != 64 {
		t.Errorf("key length = %d, want 64", len(a))
	}
}

func TestNew_DefaultsCapacityWhenNonPositive(t *testing.T) {
	c := New(t.TempDir(), 0)
	if c.capacity != DefaultCapacity {
		t.Errorf("capacity = %d, want %d", c.capacity, DefaultCapacity)
	}
	c2 := New(t.TempDir(), -1)
	if c2.capacity != DefaultCapacity {
		t.Errorf("negative capacity not normalised: %d", c2.capacity)
	}
	c3 := New(t.TempDir(), 5)
	if c3.capacity != 5 {
		t.Errorf("explicit capacity dropped: %d", c3.capacity)
	}
}

func TestPutThenGet_RoundTrips(t *testing.T) {
	c := New(t.TempDir(), 0)
	key := Key("badusb", "claude/4-7", "sys", "describe a thing")
	want := Entry{
		Task:     "badusb",
		Provider: "claude/4-7",
		Content:  "DELAY 500\nSTRING hello\n",
	}
	if err := c.Put(key, want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok := c.Get(key)
	if !ok {
		t.Fatalf("Get miss after Put")
	}
	if got.Content != want.Content || got.Task != want.Task || got.Provider != want.Provider {
		t.Errorf("entry round-trip mismatch: got %+v want %+v", got, want)
	}
	if got.Hits != 1 {
		t.Errorf("hits after one Get = %d, want 1", got.Hits)
	}
	if got.Created.IsZero() || got.LastAccessed.IsZero() {
		t.Errorf("timestamps zero: %+v", got)
	}

	// Second Get bumps Hits + LastAccessed forward.
	prev := got.LastAccessed
	time.Sleep(time.Millisecond * 5)
	got2, ok := c.Get(key)
	if !ok || got2.Hits != 2 {
		t.Errorf("second Get: hits=%d ok=%v", got2.Hits, ok)
	}
	if !got2.LastAccessed.After(prev) {
		t.Errorf("LastAccessed not advanced: %v vs %v", got2.LastAccessed, prev)
	}
}

func TestGet_MissOnUnknownKey(t *testing.T) {
	c := New(t.TempDir(), 0)
	if _, ok := c.Get(Key("nope")); ok {
		t.Errorf("Get on unknown key: expected miss")
	}
}

func TestGet_CorruptEntryIsDroppedAndReportsMiss(t *testing.T) {
	root := t.TempDir()
	c := New(root, 0)
	key := Key("badusb")

	// Plant a junk file at the expected path before any Put creates it.
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, key+".json")
	if err := os.WriteFile(target, []byte("not json {{{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get(key); ok {
		t.Errorf("corrupt entry: expected miss")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("corrupt entry not deleted on Get: stat err = %v", err)
	}
}

func TestPut_RejectsEmptyKey(t *testing.T) {
	c := New(t.TempDir(), 0)
	if err := c.Put("", Entry{Content: "x"}); err == nil {
		t.Errorf("empty key: expected error")
	}
}

func TestNilCache_AllOpsAreNoOps(t *testing.T) {
	var c *Cache
	if _, ok := c.Get("anything"); ok {
		t.Errorf("nil Cache Get should always miss")
	}
	if err := c.Put("k", Entry{Content: "x"}); err != nil {
		t.Errorf("nil Cache Put: %v, want nil", err)
	}
	if err := c.Clear(); err != nil {
		t.Errorf("nil Cache Clear: %v, want nil", err)
	}
	st, err := c.Stats()
	if err != nil || st.Entries != 0 {
		t.Errorf("nil Cache Stats: %+v err=%v", st, err)
	}
}

func TestEvict_LRURemovesOldestWhenOverCapacity(t *testing.T) {
	c := New(t.TempDir(), 2) // capacity 2 forces eviction at the 3rd Put

	// Pre-populate two stale entries with explicit LastAccessed in the past.
	older := Entry{Task: "a", Content: "A", LastAccessed: time.Now().Add(-2 * time.Hour)}
	mid := Entry{Task: "b", Content: "B", LastAccessed: time.Now().Add(-1 * time.Hour)}
	if err := c.Put(Key("a"), older); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(Key("b"), mid); err != nil {
		t.Fatal(err)
	}
	// Adding a third entry pushes capacity → 3 → eviction back to 2,
	// dropping the oldest (key "a").
	if err := c.Put(Key("c"), Entry{Task: "c", Content: "C"}); err != nil {
		t.Fatal(err)
	}

	if _, ok := c.Get(Key("a")); ok {
		t.Errorf("oldest entry not evicted")
	}
	if _, ok := c.Get(Key("b")); !ok {
		t.Errorf("mid-age entry should remain")
	}
	if _, ok := c.Get(Key("c")); !ok {
		t.Errorf("newest entry should remain")
	}
}

func TestClear_RemovesAllEntries(t *testing.T) {
	c := New(t.TempDir(), 0)
	if err := c.Put(Key("a"), Entry{Content: "A"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(Key("b"), Entry{Content: "B"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if _, ok := c.Get(Key("a")); ok {
		t.Errorf("entry survived Clear")
	}
}

func TestStats_ReportsRootCapacityEntries(t *testing.T) {
	root := t.TempDir()
	c := New(root, 4)
	if err := c.Put(Key("a"), Entry{Content: "A"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(Key("b"), Entry{Content: "BB"}); err != nil {
		t.Fatal(err)
	}
	st, err := c.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.Root != root {
		t.Errorf("Root = %q, want %q", st.Root, root)
	}
	if st.Capacity != 4 {
		t.Errorf("Capacity = %d, want 4", st.Capacity)
	}
	if st.Entries != 2 {
		t.Errorf("Entries = %d, want 2", st.Entries)
	}
	if st.Bytes <= 0 {
		t.Errorf("Bytes = %d, want > 0", st.Bytes)
	}
}

func TestDefaultRoot_ReturnsHomeRootedPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	got, err := DefaultRoot()
	if err != nil {
		t.Fatalf("DefaultRoot: %v", err)
	}
	want := filepath.Join(home, ".promptzero", "cache", "generations")
	if got != want {
		t.Errorf("DefaultRoot = %q, want %q", got, want)
	}
}

// TestPut_NormalisesEmptyTimestamps pins that we don't write zero-time
// JSON values that would later confuse the LRU comparison.
func TestPut_NormalisesEmptyTimestamps(t *testing.T) {
	c := New(t.TempDir(), 0)
	key := Key("only-content")
	if err := c.Put(key, Entry{Content: "x"}); err != nil {
		t.Fatal(err)
	}
	got, _ := c.Get(key)
	if got.Created.IsZero() {
		t.Errorf("Created not populated: %+v", got)
	}
	if got.LastAccessed.IsZero() {
		t.Errorf("LastAccessed not populated: %+v", got)
	}
	if !strings.EqualFold(got.Key, key) {
		t.Errorf("Key not stamped: got %q want %q", got.Key, key)
	}
}
