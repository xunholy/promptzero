package workflows

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// defaultGarageFrequencies is the Sub-GHz scan sweep used when the
// caller doesn't override it. Covers the common garage/gate/car-remote
// bands in the EU+US plans (MHz: 300, 310, 315, 318, 390, 433.92, 868.35).
var defaultGarageFrequencies = []int{
	300_000_000,
	310_000_000,
	315_000_000,
	318_000_000,
	390_000_000,
	433_920_000,
	868_350_000,
}

// GarageDoorTriage scans each frequency, saves any RX captures to
// /ext/subghz, decodes them, and aggregates the results with an attack
// suggestion. Receive-only — does NOT call subghz_transmit.
//
// Risk is Medium (RX only, but writes files).
//
// Params:
//   - frequencies ([]int, optional): override the frequency list.
//   - per_freq_seconds (int, default 5): per-frequency capture length.
func GarageDoorTriage(ctx context.Context, deps Deps, params map[string]interface{}) (string, error) {
	const wf = "garage_door_triage"

	freqs := paramIntList(params, "frequencies")
	if len(freqs) == 0 {
		freqs = defaultGarageFrequencies
	}
	perFreq := clamp(paramInt(params, "per_freq_seconds", 5), 2, 30)
	dur := time.Duration(perFreq) * time.Second

	var phases []PhaseResult
	signals := make([]map[string]interface{}, 0)
	extra := map[string]interface{}{
		"frequencies_scanned": freqs,
	}

	for _, freq := range freqs {
		if ctx.Err() != nil {
			extra["signals_found"] = signals
			return cancelledResult("garage door triage", phases, extra), nil
		}
		freq := freq

		// --- RX on this frequency ---
		ts := time.Now().Unix()
		capturePath := fmt.Sprintf("/ext/subghz/triage_%d_%d.sub", freq, ts)
		rxPhase := runPhase(fmt.Sprintf("rx_%d", freq), "subghz_rx_raw", func() (string, error) {
			out, err := deps.Flipper.SubGHzRxRaw(uint32(freq), dur)
			if err != nil {
				return out, err
			}
			if out != "" {
				if werr := deps.Flipper.StorageWrite(capturePath, out); werr != nil {
					return out, fmt.Errorf("saving raw capture: %w", werr)
				}
			}
			return out, nil
		})
		phases = append(phases, rxPhase)
		recordPhase(deps.Audit, wf, rxPhase, map[string]interface{}{"frequency": freq, "file": capturePath}, "medium")

		// Skip decode if the capture phase itself errored or produced no
		// meaningful output. The Flipper prints "No signal" / empty when
		// nothing is picked up.
		if !rxPhase.OK || looksLikeEmptyCapture(rxPhase.Output) {
			continue
		}

		// --- Decode ---
		if ctx.Err() != nil {
			extra["signals_found"] = signals
			return cancelledResult("garage door triage", phases, extra), nil
		}
		decodePhase := runPhase(fmt.Sprintf("decode_%d", freq), "subghz_decode", func() (string, error) {
			return deps.Flipper.SubGHzDecode(capturePath)
		})
		phases = append(phases, decodePhase)
		recordPhase(deps.Audit, wf, decodePhase, map[string]string{"file": capturePath}, "low")

		if !decodePhase.OK {
			continue
		}

		info := parseSubGHzDecode(decodePhase.Output)
		if info.Protocol == "" && info.KeyHex == "" {
			// Nothing useful decoded; skip this frequency.
			continue
		}
		sig := map[string]interface{}{
			"freq":     freq,
			"file":     capturePath,
			"protocol": info.Protocol,
			"key":      info.KeyHex,
			"rolling":  info.Rolling,
		}
		sig["attack_path"] = subGHzAttackPath(info, capturePath)
		signals = append(signals, sig)
	}

	extra["signals_found"] = signals

	summary := fmt.Sprintf("scanned %d frequencies — %d decoded signal(s)", len(freqs), len(signals))
	next := subGHzNextSteps(signals)

	return encode(Result{
		Summary:   summary,
		Phases:    phases,
		NextSteps: next,
		Extra:     extra,
	}), nil
}

// SubGHzDecodeInfo is the parsed shape of `subghz decode_raw` output.
// Rolling is true for protocols whose decode output marks the key as
// rolling-code (KeeLoq, AES, Somfy Telis, etc.).
type SubGHzDecodeInfo struct {
	Protocol string
	KeyHex   string
	Rolling  bool
}

var (
	subghzProtocolPattern = regexp.MustCompile(`(?i)Protocol[:\s]+([A-Za-z0-9_ \-]+)`)
	subghzKeyPattern      = regexp.MustCompile(`(?i)Key[:\s]+((?:[0-9A-F]{2}[ :]?){2,16})`)
)

// rollingProtocolNames is the set of Sub-GHz protocols whose key is
// rolling / counter-stepped and therefore not replayable verbatim.
// Conservative: when in doubt, treat as rolling and skip the replay
// suggestion.
var rollingProtocolNames = []string{
	"keeloq",
	"aes",
	"somfy telis", "somfy keytis",
	"nice flor-s", "nice smilo",
	"faac slh",
	"bft mitto",
	"hormann bisecur",
}

func parseSubGHzDecode(out string) SubGHzDecodeInfo {
	info := SubGHzDecodeInfo{}
	if m := subghzProtocolPattern.FindStringSubmatch(out); len(m) == 2 {
		info.Protocol = strings.TrimSpace(m[1])
	}
	if m := subghzKeyPattern.FindStringSubmatch(out); len(m) == 2 {
		info.KeyHex = strings.ToUpper(strings.TrimSpace(m[1]))
	}
	lower := strings.ToLower(info.Protocol)
	for _, roll := range rollingProtocolNames {
		if strings.Contains(lower, roll) {
			info.Rolling = true
			break
		}
	}
	return info
}

// looksLikeEmptyCapture heuristically decides whether the Flipper's
// rx_raw output indicates no signal was captured. Firmware strings vary,
// so we check for common "no signal" phrasings plus a short-output
// heuristic.
func looksLikeEmptyCapture(out string) bool {
	l := strings.ToLower(strings.TrimSpace(out))
	if l == "" {
		return true
	}
	for _, phrase := range []string{"no signal", "no data", "nothing captured", "no packets", "no raw data"} {
		if strings.Contains(l, phrase) {
			return true
		}
	}
	// Heuristic: a capture that's under ~40 bytes almost certainly has no
	// payload data — the Flipper's "Capture started/stopped" banners
	// alone are longer than that.
	return len(out) < 40
}

func subGHzAttackPath(info SubGHzDecodeInfo, file string) string {
	if info.Rolling {
		return "rolling code — no replay possible without rolljam; capture for reference only"
	}
	if info.Protocol == "" {
		return "unknown protocol — raw replay may work: `subghz_transmit " + file + "`"
	}
	return "fixed code — replay with `subghz_transmit " + file + "`"
}

func subGHzNextSteps(signals []map[string]interface{}) []string {
	if len(signals) == 0 {
		return []string{
			"No signals captured — press the remote near the Flipper during the scan window",
			"Try a longer `per_freq_seconds` (e.g. 10) or a narrower frequency list for a specific target",
		}
	}
	seenRolling := false
	seenReplay := false
	for _, s := range signals {
		if s["rolling"].(bool) {
			seenRolling = true
		} else {
			seenReplay = true
		}
	}
	var next []string
	if seenReplay {
		next = append(next, "Replay any fixed-code capture with `subghz_transmit <file>`")
	}
	if seenRolling {
		next = append(next, "Rolling codes captured — use `workflow_rolljam_lab_demo` (requires lab_consent) for authorised rolljam research")
	}
	return next
}
