package flipper

import (
	"testing"
	"time"
)

// TestProfileSettingsTable asserts the canonical struct shape returned by
// ProfileSettings for each named profile. The Balanced row is the
// behaviour-preservation guard rail: every value must equal the legacy
// hard-coded constant from before the pipeline refactor (see comments in
// pipeline.go for the source-of-truth call sites).
func TestProfileSettingsTable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   PipelineProfile
		want Pipeline
	}{
		{
			name: "fast",
			in:   ProfileFast,
			want: Pipeline{
				CLIRetryAttempts:       1,
				CLIRetryDelay:          100 * time.Millisecond,
				RPCRetryAttempts:       3,
				RPCRetryDelay:          250 * time.Millisecond,
				FileWriteRetryAttempts: 1,
				FileWriteRetryDelay:    100 * time.Millisecond,
				Exec:                   5 * time.Second,
				WriteFile:              5 * time.Second,
				Connect:                5 * time.Second,
				ReconnectAttemptDelay:  150 * time.Millisecond,
			},
		},
		{
			// Behaviour-preservation guard. Any change here means the
			// pipeline=balanced default no longer matches the
			// pre-refactor wire timing — the whole point of carrying
			// these constants around is so existing tests / scripts
			// don't notice the new layer. If a future maintainer
			// genuinely needs to retune Balanced, they must also
			// re-baseline every dependent timing test.
			name: "balanced matches legacy hard-coded constants",
			in:   ProfileBalanced,
			want: Pipeline{
				CLIRetryAttempts:       1,
				CLIRetryDelay:          250 * time.Millisecond,
				RPCRetryAttempts:       5,
				RPCRetryDelay:          500 * time.Millisecond,
				FileWriteRetryAttempts: 1,
				FileWriteRetryDelay:    250 * time.Millisecond,
				Exec:                   10 * time.Second,
				WriteFile:              10 * time.Second,
				Connect:                10 * time.Second,
				ReconnectAttemptDelay:  250 * time.Millisecond,
			},
		},
		{
			name: "resilient",
			in:   ProfileResilient,
			want: Pipeline{
				CLIRetryAttempts:       3,
				CLIRetryDelay:          750 * time.Millisecond,
				RPCRetryAttempts:       10,
				RPCRetryDelay:          1 * time.Second,
				FileWriteRetryAttempts: 3,
				FileWriteRetryDelay:    750 * time.Millisecond,
				Exec:                   30 * time.Second,
				WriteFile:              30 * time.Second,
				Connect:                30 * time.Second,
				ReconnectAttemptDelay:  500 * time.Millisecond,
			},
		},
		{
			// Empty string and unknown profiles must resolve to the
			// Balanced bundle so a stale config string can't silently
			// zero out the timeouts in production.
			name: "empty string falls back to balanced",
			in:   "",
			want: ProfileSettings(ProfileBalanced),
		},
		{
			name: "unknown name falls back to balanced",
			in:   "yolo",
			want: ProfileSettings(ProfileBalanced),
		},
		{
			// Case + whitespace tolerance — operators copy/paste from
			// docs, hand-edit YAML, etc. Normalisation guarantees a
			// trailing newline doesn't quietly downgrade them.
			name: "case-insensitive and whitespace-trimmed",
			in:   "  Resilient \n",
			want: ProfileSettings(ProfileResilient),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ProfileSettings(tc.in)
			if got != tc.want {
				t.Errorf("ProfileSettings(%q) =\n  got:  %+v\n  want: %+v", tc.in, got, tc.want)
			}
		})
	}
}

// TestSetPipelineSwapsResolved verifies (*Flipper).SetPipeline + pipeline()
// round-trip a profile change atomically — i.e. the next read after a
// SetPipeline call observes the new bundle.
func TestSetPipelineSwapsResolved(t *testing.T) {
	t.Parallel()

	f := &Flipper{}

	// Default (no Set call) must resolve to Balanced — this is the
	// guarantee that lets dispatch code call f.pipeline() unconditionally
	// without a nil-check escape hatch.
	got := f.pipeline()
	if want := ProfileSettings(ProfileBalanced); got != want {
		t.Fatalf("zero-value pipeline = %+v, want Balanced %+v", got, want)
	}

	f.SetPipeline(ProfileResilient)
	if got, want := f.pipeline(), ProfileSettings(ProfileResilient); got != want {
		t.Errorf("after SetPipeline(Resilient): got %+v, want %+v", got, want)
	}

	f.SetPipeline(ProfileFast)
	if got, want := f.pipeline(), ProfileSettings(ProfileFast); got != want {
		t.Errorf("after SetPipeline(Fast): got %+v, want %+v", got, want)
	}

	// Empty string must resolve to Balanced via SetPipeline — verifies
	// the same normalisation the YAML loader relies on.
	f.SetPipeline("")
	if got, want := f.pipeline(), ProfileSettings(ProfileBalanced); got != want {
		t.Errorf("after SetPipeline(\"\"): got %+v, want %+v", got, want)
	}
}

// TestSetPipelineBundleAcceptsCustom verifies the lower-level
// SetPipelineBundle setter — used by the (future) auto-tuner and by
// tests that need a one-off bundle that doesn't match a named profile.
func TestSetPipelineBundleAcceptsCustom(t *testing.T) {
	t.Parallel()

	f := &Flipper{}
	custom := Pipeline{
		CLIRetryAttempts:       2,
		CLIRetryDelay:          333 * time.Millisecond,
		RPCRetryAttempts:       7,
		RPCRetryDelay:          800 * time.Millisecond,
		FileWriteRetryAttempts: 2,
		FileWriteRetryDelay:    333 * time.Millisecond,
		Exec:                   20 * time.Second,
		WriteFile:              15 * time.Second,
		Connect:                25 * time.Second,
		ReconnectAttemptDelay:  300 * time.Millisecond,
	}
	f.SetPipelineBundle(custom)
	if got := f.pipeline(); got != custom {
		t.Errorf("SetPipelineBundle round-trip mismatch:\n  got:  %+v\n  want: %+v", got, custom)
	}
}

// TestSetPipelineBundle_RejectsZeroValue pins the docstring's
// "rejected with a warn log" promise. Pre-fix the body just stored
// whatever was passed, so a caller who did `var p Pipeline;
// f.SetPipelineBundle(p)` silently wedged the agent's CLI
// dispatch: every timeout would be 0, every ExecCtx /
// WriteFileCtx would fire context.DeadlineExceeded immediately on
// the next command. The fix rejects the zero value and the
// existing Balanced default stays installed via pipeline()'s
// nil-pointer fallback. End-state assertion: f.pipeline() == Balanced
// after the reject.
func TestSetPipelineBundle_RejectsZeroValue(t *testing.T) {
	t.Parallel()

	f := &Flipper{}
	// Install Balanced first so we have a known good baseline to
	// confirm the reject didn't overwrite it.
	f.SetPipeline(ProfileBalanced)
	want := ProfileSettings(ProfileBalanced)

	var zero Pipeline
	f.SetPipelineBundle(zero) // should warn and be ignored

	if got := f.pipeline(); got != want {
		t.Errorf("SetPipelineBundle(zero) modified the active bundle:\n  got:  %+v\n  want: %+v (Balanced, unchanged)", got, want)
	}
}

// TestSetPipelineBundle_RejectsZeroFromUnsetState covers the case
// where the very first SetPipelineBundle call is the zero value.
// f.pipelineCfg is still nil, so the reject leaves the lazy
// Balanced fallback in place — the first ExecCtx after still gets
// non-zero timeouts. Without the reject, the zero bundle would be
// stored and every subsequent ExecCtx would expire immediately.
func TestSetPipelineBundle_RejectsZeroFromUnsetState(t *testing.T) {
	t.Parallel()

	f := &Flipper{}
	var zero Pipeline
	f.SetPipelineBundle(zero) // first call, zero value

	// pipeline() falls back to ProfileSettings(ProfileBalanced) when
	// pipelineCfg is nil. Asserting that confirms the zero wasn't
	// stored (otherwise we'd see all-zero timeouts here).
	got := f.pipeline()
	if got.Exec == 0 || got.WriteFile == 0 || got.Connect == 0 {
		t.Errorf("Pipeline has zero timeouts after SetPipelineBundle(zero) — the reject didn't fire: %+v", got)
	}
}
