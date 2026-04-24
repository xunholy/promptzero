package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/risk"
)

// firmware.go — v0.5 wave-1 firmware oracle Spec.
//
// This file owns only the firmware_introspect Spec. Registration lives in the
// sibling file firmware_wave1_wire.go (a 3-line init() that calls Register).
//
// The four offline-cracker Specs (mfoc_attack, mfcuk_attack, mfkey32_recover,
// iclass_loclass_recover) were removed from this file; they will be created by
// engineer #7 in internal/tools/mifare.go and engineer #8 in
// internal/tools/iclass.go per the v0.5 team-lead brief.
//
// See docs/refactor/v0.5-runbook.md §B.1 and docs/refactor/firmware-matrix.md
// for the full design including the Capabilities struct expansion this Spec
// surfaces.

// firmwareIntrospectSpec returns the connected Flipper's full capability bitmap
// as structured JSON. It is the LLM's primary "know before you act" oracle:
// calling it before any fork-gated tool eliminates trial-and-error round trips.
var firmwareIntrospectSpec = Spec{
	Name:        "firmware_introspect",
	Description: "Return the connected Flipper's firmware capability bitmap as structured JSON: fork, version, commit, build date, feature flags (HasNFCSubshell, SubGHzNeedsDev, NFCFlaggedArgs, SubGHzRxRawHasFilePath, JSEngineKind, SubGHzBruteforcerAvail, ...), and the resolved fork+version band (e.g. 'momentum/mntm-dev', 'unleashed/v1.2.x'). Use this before any fork-gated tool call so the LLM can pick the right verb variant without a trial-and-error round trip.",
	Schema:      json.RawMessage(`{"type":"object","properties":{"refresh":{"type":"boolean","description":"Re-issue device_info and recompute the bitmap instead of returning the connect-time snapshot. Default false."}}}`),
	Required:    nil,
	Risk:        risk.Low,
	Group:       GroupFlipperSystem,
	AgentOnly:   false,
	Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
		if d == nil || d.Flipper == nil {
			return "", fmt.Errorf("firmware_introspect: Flipper transport unavailable")
		}
		if boolOr(p, "refresh", false) {
			if _, err := d.Flipper.DetectCapabilities(); err != nil {
				return "", fmt.Errorf("re-detect failed: %w", err)
			}
		}
		caps := d.Flipper.Capabilities()
		b, err := json.Marshal(caps)
		if err != nil {
			return "", err
		}
		return string(b), nil
	},
}
