// Package mode defines named operation profiles that constrain which
// tools the agent will dispatch. Each Mode owns an allow-list over the
// existing [tools.Group] taxonomy — modes do NOT introduce new tool
// metadata, they only filter the existing set.
//
// The rationale is operator safety: an operator working a Recon job
// should not be able to fat-finger an RF transmit because the same
// Spec catalog the LLM is reasoning over also includes Sub-GHz TX
// primitives. Switching to ModeRecon refuses every group whose group
// is not on the allow-list, surfacing the refusal as a structured
// error the UI can display verbatim.
//
// Mode is orthogonal to risk.Level. Recon happens to imply low-risk-
// only as a rule, but the implementation reads spec.Risk separately
// when relevant; Allows itself only inspects the group.
//
// The default mode is ModeStandard and its allow-list is exactly the
// full set of registered groups, so unsetting --mode preserves the
// historic "everything goes" behaviour.
package mode

import (
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/tools"
)

// Mode is a named operation profile. The string form (lower case) is
// what operators see on the CLI flag and in the REPL.
type Mode string

// Operation modes. New modes MUST be added to allModes so /mode listing
// and ParseMode pick them up automatically.
const (
	// ModeStandard is the default, no-op profile — every group is
	// allowed. Behaviour identical to a build without modes.
	ModeStandard Mode = "standard"

	// ModeRecon is read-only reconnaissance. Allows Flipper system /
	// storage / IR-rx, Marauder scan, and host-side analysis tools.
	// Forbids any RF transmit, NFC/RFID write, BadUSB run, or
	// generation tool. Pairs naturally with risk.Low, but the rule is
	// expressed as a group allow-list — callers that need to layer
	// risk filtering can read spec.Risk separately.
	ModeRecon Mode = "recon"

	// ModeIntel is Recon plus host-side analysis (vision, RAG,
	// security/host tools). Same TX prohibition; adds the tools an
	// analyst needs to correlate captures.
	ModeIntel Mode = "intel"

	// ModeStealth is the minimal-RF profile. Disables every Marauder
	// group (SSID broadcasts, deauth, evil portal, scans), Sub-GHz
	// (TX and RX), NFC, RFID, and iButton. Allows Flipper system
	// (CLI introspection), storage, and IR — the IR group is
	// transmit-capable in name but the receive primitives live in
	// the same group, so this is a deliberate compromise: operators
	// in stealth mode use ir_decode_file but should not invoke
	// ir_send_universal. Future split of GroupFlipperIR into rx/tx
	// subgroups would tighten this naturally.
	ModeStealth Mode = "stealth"

	// ModeAssault permits everything ModeStandard permits. The
	// distinction is documentational — operators flipping into
	// Assault are stating an intent so audit/UI banners can flag the
	// session. The dispatch behaviour is identical to Standard.
	ModeAssault Mode = "assault"
)

// allModes lists every supported mode in display order (left-to-right
// from least-to-most permissive). ParseMode and DescribeAll iterate
// this slice.
var allModes = []Mode{
	ModeStandard,
	ModeRecon,
	ModeIntel,
	ModeStealth,
	ModeAssault,
}

// All returns the canonical ordered list of supported modes. Returned
// slice is a fresh copy so callers may sort or filter without side
// effects on package state.
func All() []Mode {
	out := make([]Mode, len(allModes))
	copy(out, allModes)
	return out
}

// ParseMode resolves a user-supplied string into a Mode. Matching is
// case-insensitive and whitespace-tolerant. The empty string returns
// ModeStandard so unset CLI flags / config fields behave as the
// default. Unknown strings return an error listing every supported
// mode so misuse is self-correcting.
func ParseMode(s string) (Mode, error) {
	trimmed := strings.ToLower(strings.TrimSpace(s))
	if trimmed == "" {
		return ModeStandard, nil
	}
	for _, m := range allModes {
		if string(m) == trimmed {
			return m, nil
		}
	}
	return "", fmt.Errorf("unknown mode %q (supported: %s)", s, strings.Join(modeNames(), ", "))
}

// modeNames returns the lower-case identifier of every mode. Internal
// helper for error formatting.
func modeNames() []string {
	out := make([]string, 0, len(allModes))
	for _, m := range allModes {
		out = append(out, string(m))
	}
	return out
}

// IsReadRestrictive reports whether the mode implies the
// ReadOnly safety rail (defence-in-depth overlay). Recon, Intel,
// and Stealth all forbid writes/transmits as part of their
// definition, so the cmd/promptzero setupMode + /mode runtime
// switch both engage the ReadOnly overlay when entering one of
// these modes.
//
// Centralised here (rather than open-coded in setup.go) so a
// new constrained mode added to allModes stays in lockstep with
// the read-only coupling — a single edit covers both the
// startup banner and the runtime /mode handler.
func (m Mode) IsReadRestrictive() bool {
	switch m {
	case ModeRecon, ModeIntel, ModeStealth:
		return true
	}
	return false
}

// DisplayName returns a Title-Cased operator-facing label.
func (m Mode) DisplayName() string {
	switch m {
	case ModeStandard:
		return "Standard"
	case ModeRecon:
		return "Recon"
	case ModeIntel:
		return "Intel"
	case ModeStealth:
		return "Stealth"
	case ModeAssault:
		return "Assault"
	default:
		// Fall back to the raw string with first-letter upper-cased
		// rather than panicking — DisplayName is purely cosmetic.
		if m == "" {
			return "Standard"
		}
		s := string(m)
		return strings.ToUpper(s[:1]) + s[1:]
	}
}

// Description returns a one-line operator summary of the mode's
// intent. Used in /mode listings and the startup banner.
func (m Mode) Description() string {
	switch m {
	case ModeStandard:
		return "everything allowed (default — no operation-mode constraints)"
	case ModeRecon:
		return "read-only reconnaissance: scan/inspect only, no RF transmit, no writes"
	case ModeIntel:
		return "Recon plus host-side analysis (vision, RAG, security tooling)"
	case ModeStealth:
		return "minimal RF: no Marauder, no Sub-GHz, no NFC/RFID — Flipper CLI + storage + IR only"
	case ModeAssault:
		return "active TX features explicitly enabled — review legality before use"
	default:
		return "unknown mode"
	}
}

// modeAllowList is the per-mode set of permitted tool groups. nil
// means "every group" (used for ModeStandard and ModeAssault). A
// non-nil empty set would refuse every tool — which is not a useful
// operator-facing state, so the constructor below populates each
// non-default mode explicitly.
var modeAllowList = map[Mode]map[tools.Group]struct{}{
	ModeRecon:   reconGroups(),
	ModeIntel:   intelGroups(),
	ModeStealth: stealthGroups(),
}

// reconGroups returns the read-only allow-list. RF transmit, NFC
// write, RFID write, BadUSB run, generation, workflows, and the
// auxiliary peripheral groups (Bruce, Faultier) are excluded.
// Workflows are excluded because every workflow today chains a
// write/transmit primitive.
//
// GroupFlipperSystem covers both system info and SD-card I/O — the
// runtime risk gate (see internal/risk) is the second line of
// defence for the storage-write subset.
//
// GroupMarauderWiFi includes scan, list, and clear-only sub-tools
// alongside deauth/beacon/probe TX; risk gating is what keeps the
// transmit primitives out at runtime when an operator is in Recon.
func reconGroups() map[tools.Group]struct{} {
	return setOf(
		tools.GroupMetaAudit,
		tools.GroupMetaUtil,
		tools.GroupFlipperSystem,
		tools.GroupMarauderWiFi,
	)
}

// intelGroups extends Recon with analysis tooling. Vision and host-
// side security helpers (hash analysis, RAG, etc.) are pure read /
// host-CPU work — appropriate for an analyst phase between recon
// and engagement.
func intelGroups() map[tools.Group]struct{} {
	out := reconGroups()
	out[tools.GroupVision] = struct{}{}
	out[tools.GroupSecurity] = struct{}{}
	out[tools.GroupHostTools] = struct{}{}
	return out
}

// stealthGroups is the minimal-RF allow-list. Anything that touches
// the radio (Marauder, Sub-GHz TX, NFC, RFID, iButton) is excluded.
// IR is allowed because the receive primitives (ir_decode_file,
// ir_universal_list) share the group with the transmit ones; the
// risk gate is the second line of defence for the TX subset.
func stealthGroups() map[tools.Group]struct{} {
	return setOf(
		tools.GroupMetaAudit,
		tools.GroupMetaUtil,
		tools.GroupFlipperSystem,
		tools.GroupFlipperIR,
	)
}

// setOf builds a struct{} set from a variadic of tools.Group values.
// Sized exactly so the returned map needs no growth.
func setOf(groups ...tools.Group) map[tools.Group]struct{} {
	out := make(map[tools.Group]struct{}, len(groups))
	for _, g := range groups {
		out[g] = struct{}{}
	}
	return out
}

// Allows reports whether a tool whose Spec has the given Group can
// be dispatched in this mode. Standard and Assault always return
// true; the constrained modes consult modeAllowList. An unknown Mode
// also returns true so a future mode added to allModes but not to
// modeAllowList degrades open rather than refusing every tool.
func (m Mode) Allows(group tools.Group) bool {
	if m == ModeStandard || m == ModeAssault {
		return true
	}
	allow, ok := modeAllowList[m]
	if !ok {
		// Unknown / unconstrained mode — degrade open. Constrained
		// modes are explicitly registered above.
		return true
	}
	_, permitted := allow[group]
	return permitted
}

// Reason returns a short operator-readable explanation for why a
// group is refused under this mode. The agent dispatch wraps this
// into the rejection message so the UI / LLM see a human sentence
// rather than the raw mode + group identifiers.
func (m Mode) Reason(group tools.Group) string {
	switch m {
	case ModeRecon:
		return "Recon mode is read-only — RF transmit, writes, BadUSB, and generation tools are disabled"
	case ModeIntel:
		return "Intel mode is read-only — RF transmit, writes, BadUSB, and generation tools are disabled (analysis tools are allowed)"
	case ModeStealth:
		return "Stealth mode disables RF emissions — Marauder, Sub-GHz, NFC, RFID, and iButton groups are blocked"
	default:
		return fmt.Sprintf("%s mode does not permit group %s", m.DisplayName(), group)
	}
}
