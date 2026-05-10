package generate

import (
	"context"
	"testing"

	"github.com/xunholy/promptzero/internal/provider"
	"github.com/xunholy/promptzero/internal/semcache"
)

// Cache-integration tests for the Generator (roadmap P2-27). Each
// test wires a stubProvider and a fresh semcache rooted at t.TempDir(),
// then verifies the cache short-circuits the second call.

func TestGenerator_CacheHit_AvoidsLLMCall(t *testing.T) {
	llm := &stubProvider{resp: &provider.Response{Content: "DELAY 200\nSTRING cached\n"}}
	g := New(llm, nil)
	g.SetCache(semcache.New(t.TempDir(), 0))

	if _, err := g.BadUSB(context.Background(), "starbucks", "windows", "us"); err != nil {
		t.Fatalf("first BadUSB: %v", err)
	}
	if llm.callCount != 1 {
		t.Fatalf("first call count = %d, want 1", llm.callCount)
	}

	// Identical inputs → cache hit; LLM should not be called again.
	got, err := g.BadUSB(context.Background(), "starbucks", "windows", "us")
	if err != nil {
		t.Fatalf("second BadUSB: %v", err)
	}
	if llm.callCount != 1 {
		t.Errorf("second call count = %d, want 1 (cached)", llm.callCount)
	}
	if got.Content == "" {
		t.Errorf("second call: empty content from cache")
	}
}

func TestGenerator_CacheMiss_OnDifferentDescription(t *testing.T) {
	llm := &stubProvider{resp: &provider.Response{Content: "DELAY 1\n"}}
	g := New(llm, nil)
	g.SetCache(semcache.New(t.TempDir(), 0))

	_, _ = g.BadUSB(context.Background(), "starbucks", "windows", "us")
	_, _ = g.BadUSB(context.Background(), "costa coffee", "windows", "us")

	if llm.callCount != 2 {
		t.Errorf("call count = %d, want 2 (different descriptions)", llm.callCount)
	}
}

func TestGenerator_CacheMiss_OnDifferentTaskLabel(t *testing.T) {
	// Same description but different generators (BadUSB vs SubGHz)
	// resolve to different task labels and must NOT collide.
	llm := &stubProvider{resp: &provider.Response{Content: "x"}}
	g := New(llm, nil)
	g.SetCache(semcache.New(t.TempDir(), 0))

	_, _ = g.BadUSB(context.Background(), "garage", "windows", "us")
	_, _ = g.SubGHz(context.Background(), "garage")

	if llm.callCount != 2 {
		t.Errorf("call count = %d, want 2 (different task labels)", llm.callCount)
	}
}

func TestGenerator_CacheBypass_SkipsReadButStillWrites(t *testing.T) {
	llm := &stubProvider{resp: &provider.Response{Content: "first"}}
	cache := semcache.New(t.TempDir(), 0)
	g := New(llm, nil)
	g.SetCache(cache)

	// Seed the cache.
	_, _ = g.BadUSB(context.Background(), "x", "windows", "us")
	if llm.callCount != 1 {
		t.Fatalf("seed call count = %d, want 1", llm.callCount)
	}

	// Bypass mode: should call LLM even though entry exists.
	llm.resp = &provider.Response{Content: "fresh"}
	g.SetCacheBypass(true)
	_, _ = g.BadUSB(context.Background(), "x", "windows", "us")
	if llm.callCount != 2 {
		t.Errorf("bypass call count = %d, want 2", llm.callCount)
	}

	// Disable bypass; result from second call should now be cached.
	g.SetCacheBypass(false)
	_, _ = g.BadUSB(context.Background(), "x", "windows", "us")
	if llm.callCount != 2 {
		t.Errorf("post-bypass cache miss: call count = %d, want 2", llm.callCount)
	}
}

func TestGenerator_RefusalIsNotCached(t *testing.T) {
	// A refusal response on the first call must not poison the cache —
	// a follow-up call should hit the LLM again so a transient policy
	// pop doesn't lock the operator out.
	refusal := "I cannot assist with that request."
	llm := &stubProvider{resp: &provider.Response{Content: refusal}}
	g := New(llm, nil)
	g.SetCache(semcache.New(t.TempDir(), 0))

	_, _ = g.BadUSB(context.Background(), "x", "windows", "us")
	_, _ = g.BadUSB(context.Background(), "x", "windows", "us")

	if llm.callCount != 2 {
		t.Errorf("refusal cached: call count = %d, want 2", llm.callCount)
	}
}

func TestGenerator_NoCache_FallsThroughEachCall(t *testing.T) {
	// Sanity: with no cache configured, every call hits the LLM.
	llm := &stubProvider{resp: &provider.Response{Content: "out"}}
	g := New(llm, nil)

	_, _ = g.BadUSB(context.Background(), "x", "windows", "us")
	_, _ = g.BadUSB(context.Background(), "x", "windows", "us")

	if llm.callCount != 2 {
		t.Errorf("no-cache: call count = %d, want 2", llm.callCount)
	}
}

func TestGenerator_CachedContent_PreservedThroughCleanOutput(t *testing.T) {
	// First call's response goes through cleanOutput before being
	// returned. The cache stores the *raw* LLM bytes, so the second
	// call's returned content must also pass through cleanOutput.
	// Easiest pin: the second-call output equals the first-call
	// output (both are post-cleanOutput).
	fenced := "```html\n<!DOCTYPE html><body>portal</body>\n```"
	llm := &stubProvider{resp: &provider.Response{Content: fenced}}
	g := New(llm, nil)
	g.SetCache(semcache.New(t.TempDir(), 0))

	first, err := g.EvilPortal(context.Background(), "starbucks")
	if err != nil {
		t.Fatalf("first EvilPortal: %v", err)
	}
	second, err := g.EvilPortal(context.Background(), "starbucks")
	if err != nil {
		t.Fatalf("second EvilPortal: %v", err)
	}
	if first.Content != second.Content {
		t.Errorf("cache round-trip mismatch:\n first: %q\nsecond: %q", first.Content, second.Content)
	}
	if llm.callCount != 1 {
		t.Errorf("call count = %d, want 1", llm.callCount)
	}
}
