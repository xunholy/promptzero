package agent

import (
	"testing"

	"github.com/xunholy/promptzero/internal/confidence"
	"github.com/xunholy/promptzero/internal/persona"
)

// TestRouterConfidenceThreshold_FromPersona pins that the persona's
// `confidence.router` value flows through to the router's abstention
// check. The threshold lookup is the only new logic the router took
// on for P3-29; the parse + clamp helpers are exercised in
// internal/confidence's own tests.
func TestRouterConfidenceThreshold_FromPersona(t *testing.T) {
	cases := []struct {
		name     string
		persona  *persona.Persona
		want     confidence.Score
		wantZero bool // expect the "use default" sentinel (Score == 0)
	}{
		{
			name:     "no persona → default sentinel",
			persona:  nil,
			wantZero: true,
		},
		{
			name:     "persona without confidence map → default sentinel",
			persona:  &persona.Persona{Name: "p"},
			wantZero: true,
		},
		{
			name:     "persona with router threshold",
			persona:  &persona.Persona{Name: "p", Confidence: map[string]float64{"router": 0.7}},
			want:     0.7,
			wantZero: false,
		},
		{
			name:     "vision-only override leaves router at default",
			persona:  &persona.Persona{Name: "p", Confidence: map[string]float64{"vision": 0.9}},
			wantZero: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &Agent{persona: tc.persona}
			got := a.routerConfidenceThresholdLocked()
			if tc.wantZero {
				if got != 0 {
					t.Errorf("got %v, want 0 (default sentinel)", got)
				}
				return
			}
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRouterConfidenceThreshold_AbstainsBelowConfiguredThreshold
// composes the persona-supplied threshold with the abstention
// helper to confirm the integration end-to-end.
func TestRouterConfidenceThreshold_AbstainsBelowConfiguredThreshold(t *testing.T) {
	a := &Agent{
		persona: &persona.Persona{
			Name:       "tight",
			Confidence: map[string]float64{"router": 0.9},
		},
	}
	threshold := a.routerConfidenceThresholdLocked()

	// 0.85 is below the persona's 0.9 → abstain.
	if !confidence.ShouldAbstainAt(0.85, threshold) {
		t.Error("expected abstention at score=0.85, threshold=0.9")
	}
	// 0.95 is above → proceed.
	if confidence.ShouldAbstainAt(0.95, threshold) {
		t.Error("expected proceed at score=0.95, threshold=0.9")
	}
}
