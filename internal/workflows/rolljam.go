package workflows

import (
	"context"
	"fmt"
	"time"
)

// RolljamLabDemo walks a lab-consented researcher through a two-capture
// rolljam sequence: prompt → RX capture #1 → prompt → RX capture #2.
// Both .sub files are retained on the SD card so the researcher can
// compare consecutive rolling-code transmissions and study the counter
// step at their leisure.
//
// This workflow does NOT perform a real rolljam — a live rolljam
// requires simultaneous jam + capture on two separate radios, which the
// Flipper Zero's single CC1101 cannot do. It exists to stage the
// capture side of the attack under an authorised lab setting so the
// rolling-code math can be understood without ever transmitting.
//
// Risk is Critical because the captures enable a real rolljam if paired
// with external jamming gear — we therefore hard-require lab_consent
// and refuse to run otherwise.
//
// Params:
//   - frequency (int, required): MHz in Hz (e.g. 433920000).
//   - lab_consent (bool, REQUIRED true): explicit acknowledgement that
//     this is authorised lab research. No default.
//   - per_press_seconds (int, default 5, clamped 2..30): capture length
//     per press.
//   - output_dir (string, default /ext/subghz): SD card directory.
func RolljamLabDemo(ctx context.Context, deps Deps, params map[string]interface{}) (string, error) {
	const wf = "rolljam_lab_demo"

	if !paramBool(params, "lab_consent", false) {
		return encode(Result{
			Summary: "refused: lab_consent is required for rolljam research",
			NextSteps: []string{
				"Call again with `lab_consent: true` to acknowledge this is authorised lab research",
				"Do NOT run this workflow against third-party garage doors or vehicles — it captures material that enables a rolljam replay",
			},
		}), nil
	}

	freq := paramInt(params, "frequency", 0)
	if freq <= 0 {
		return encode(Result{
			Summary: "frequency is required (Hz, e.g. 433920000 for 433.92 MHz)",
		}), nil
	}

	perPress := clamp(paramInt(params, "per_press_seconds", 5), 2, 30)
	outputDir := paramString(params, "output_dir")
	if outputDir == "" {
		outputDir = "/ext/subghz"
	}

	dur := time.Duration(perPress) * time.Second
	ts := time.Now().Unix()

	press1 := fmt.Sprintf("%s/rolljam_%d_press1.sub", outputDir, ts)
	press2 := fmt.Sprintf("%s/rolljam_%d_press2.sub", outputDir, ts)

	var phases []PhaseResult
	extra := map[string]interface{}{
		"frequency":      freq,
		"press1_capture": press1,
		"press2_capture": press2,
		"output_dir":     outputDir,
		"lab_consent":    true,
	}

	// --- Press #1 ---
	if ctx.Err() != nil {
		return cancelledResult("rolljam lab demo", phases, extra), nil
	}
	phases = append(phases, internalPhase("prompt_press1",
		fmt.Sprintf("Ready for press #1 on %d Hz — capturing for %d seconds", freq, perPress)))

	p1 := runPhase("press1_rx", "subghz_rx_raw", func() (string, error) {
		return deps.Flipper.SubGHzRxRaw(press1, uint32(freq), dur)
	})
	phases = append(phases, p1)
	recordPhase(deps.Audit, wf, p1,
		map[string]interface{}{"frequency": freq, "file": press1}, "critical")

	if !p1.OK {
		return encode(Result{
			Summary:   "press #1 capture failed: " + firstLine(p1.Output),
			Phases:    phases,
			NextSteps: []string{"Retry after confirming the remote is in range and the frequency is correct"},
			Extra:     extra,
		}), nil
	}

	// --- Press #2 ---
	if ctx.Err() != nil {
		return cancelledResult("rolljam lab demo", phases, extra), nil
	}
	phases = append(phases, internalPhase("prompt_press2",
		fmt.Sprintf("Press #1 captured to %s — now press the remote again for press #2", press1)))

	p2 := runPhase("press2_rx", "subghz_rx_raw", func() (string, error) {
		return deps.Flipper.SubGHzRxRaw(press2, uint32(freq), dur)
	})
	phases = append(phases, p2)
	recordPhase(deps.Audit, wf, p2,
		map[string]interface{}{"frequency": freq, "file": press2}, "critical")

	if !p2.OK {
		return encode(Result{
			Summary:   "press #2 capture failed: " + firstLine(p2.Output),
			Phases:    phases,
			NextSteps: []string{"Press #1 succeeded at " + press1 + " — retry the workflow to recapture press #2"},
			Extra:     extra,
		}), nil
	}

	summary := fmt.Sprintf("rolljam lab demo captured 2 presses at %d Hz", freq)

	next := []string{
		fmt.Sprintf("Compare the two captures byte-by-byte: `storage_read %s` and `%s`", press1, press2),
		"Decode each with `subghz_decode <file>` to inspect the rolling counter step",
		"Study how the rolling code increments between presses — this is the material a live rolljam would replay",
		"Keep captures on SD; they are only useful paired with an external jammer which is OUT OF SCOPE for this CLI",
	}

	return encode(Result{
		Summary:   summary,
		Phases:    phases,
		NextSteps: next,
		Extra:     extra,
	}), nil
}
