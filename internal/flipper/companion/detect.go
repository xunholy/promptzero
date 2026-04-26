package companion

import (
	"context"
	"strings"
)

// FAPProbe is a tiny subset of *flipper.Flipper that only needs the
// "storage info <path>" / "storage stat <path>" CLI dance to decide
// whether a file exists on the device. Defined here (rather than
// imported) for the same cycle-avoidance reason FileWriter is.
type FAPProbe interface {
	ExecCtx(ctx context.Context, command string) (string, error)
}

// CandidatePaths is the list of SD locations Detect probes when
// looking for the Companion FAP. Different firmware forks default
// to different category folders; we accept any of them.
//
// The list is ordered by descending likelihood given the firmware
// distribution in docs/catalog/firmware.md (Momentum > RogueMaster
// > Unleashed > Official).
var CandidatePaths = []string{
	"/ext/apps/Tools/promptzero_companion.fap",
	"/ext/apps/Misc/promptzero_companion.fap",
	"/ext/apps/Main/promptzero_companion.fap",
	"/ext/apps/promptzero_companion.fap",
}

// Detect returns the first candidate path where the Companion FAP
// is installed, or "" if none are found. ctx governs the whole
// probe — pass a short deadline (a few seconds) so a flaky USB link
// can't stall startup.
//
// Detection is best-effort: any error from the underlying CLI is
// treated as "not found" rather than propagated, because the
// companion integration is optional and the agent must keep
// starting even if the storage layer is acting up.
func Detect(ctx context.Context, p FAPProbe) string {
	if p == nil {
		return ""
	}
	for _, path := range CandidatePaths {
		if existsAt(ctx, p, path) {
			return path
		}
	}
	return ""
}

// existsAt asks the Flipper whether path resolves to a file. The
// Flipper CLI returns a body containing "size:" lines for files and
// "directory" for dirs; "Storage error" or "no such file" indicates
// absence. We pattern-match on these because the CLI's exit-code
// surface isn't exposed over USB.
func existsAt(ctx context.Context, p FAPProbe, path string) bool {
	out, err := p.ExecCtx(ctx, "storage stat "+path)
	if err != nil {
		return false
	}
	low := strings.ToLower(out)
	if strings.Contains(low, "error") || strings.Contains(low, "no such") {
		return false
	}
	// Both "size:" (file) and "directory" (dir) count as present;
	// we accept either so a future migration to a directory layout
	// won't break detection.
	return strings.Contains(low, "size:") || strings.Contains(low, "directory")
}
