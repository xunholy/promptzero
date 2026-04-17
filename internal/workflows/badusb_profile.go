package workflows

import (
	"context"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/generate"
)

// BadUSBTargetProfile generates a DuckyScript payload tailored to a
// described target, deploys it to the Flipper SD card, and optionally
// launches it via the BadUSB FAP. The workflow binds together the
// three primitives (generate → deploy → run) so the LLM can kick off
// a vetted payload with a single call.
//
// Risk is High: the generated script lands on the Flipper SD card and,
// if auto_run=true, executes as keyboard input on whatever host the
// Flipper is connected to.
//
// Params:
//   - description (string, required): the payload's intended behaviour.
//     Passed verbatim to the Generator LLM.
//   - target_os (string, required): "windows" | "linux" | "macos".
//   - auto_run (bool, default false): launch BadUSB FAP after deploy.
//   - path (string, default /ext/badusb/generated_payload.txt): SD path.
func BadUSBTargetProfile(ctx context.Context, deps Deps, params map[string]interface{}) (string, error) {
	const wf = "badusb_target_profile"

	if deps.Generator == nil {
		return encode(Result{
			Summary: "generator is not wired (no --api-key / LLM provider)",
			NextSteps: []string{
				"Re-run with a configured Anthropic API key so the payload generator can call the LLM",
			},
		}), nil
	}

	description := strings.TrimSpace(paramString(params, "description"))
	if description == "" {
		return encode(Result{
			Summary: "description is required",
			NextSteps: []string{
				"Call again with a `description` field describing what the payload should do",
			},
		}), nil
	}
	targetOS := strings.ToLower(strings.TrimSpace(paramString(params, "target_os")))
	if targetOS == "" {
		return encode(Result{
			Summary: "target_os is required (windows|linux|macos)",
		}), nil
	}
	autoRun := paramBool(params, "auto_run", false)
	path := paramString(params, "path")

	var phases []PhaseResult
	extra := map[string]interface{}{
		"target_os":   targetOS,
		"description": description,
	}

	// --- 1. Generate ---
	var result *generate.Result
	genPhase := runPhase("generate", "generate_badusb", func() (string, error) {
		r, err := deps.Generator.BadUSB(ctx, description, targetOS)
		if err != nil {
			return "", err
		}
		result = r
		extra["preview"] = r.Preview
		extra["script_length"] = len(r.Content)
		return r.Preview, nil
	})
	phases = append(phases, genPhase)
	recordPhase(deps.Audit, wf, genPhase, map[string]string{"target_os": targetOS}, "high")

	if !genPhase.OK || result == nil {
		return encode(Result{
			Summary:   "BadUSB generation failed: " + firstLine(genPhase.Output),
			Phases:    phases,
			NextSteps: []string{"Check API key validity and retry with a simpler description"},
			Extra:     extra,
		}), nil
	}

	// --- 2. Deploy ---
	if ctx.Err() != nil {
		return cancelledResult("badusb profile", phases, extra), nil
	}
	depPhase := runPhase("deploy", "deploy_payload", func() (string, error) {
		if err := deps.Generator.Deploy(result, path); err != nil {
			return "", err
		}
		return "wrote to " + result.Path, nil
	})
	phases = append(phases, depPhase)
	recordPhase(deps.Audit, wf, depPhase, map[string]string{"path": result.Path}, "high")

	if !depPhase.OK {
		return encode(Result{
			Summary:   "BadUSB deploy failed: " + firstLine(depPhase.Output),
			Phases:    phases,
			NextSteps: []string{"Check SD card presence and /ext/badusb directory"},
			Extra:     extra,
		}), nil
	}
	extra["path"] = result.Path

	// --- 3. Optional run ---
	var next []string
	if autoRun {
		if ctx.Err() != nil {
			return cancelledResult("badusb profile", phases, extra), nil
		}
		runP := runPhase("run", "badusb_run", func() (string, error) {
			return deps.Flipper.BadUSBRun(result.Path)
		})
		phases = append(phases, runP)
		recordPhase(deps.Audit, wf, runP, map[string]string{"path": result.Path}, "high")

		if !runP.OK {
			next = append(next,
				"BadUSB FAP launch failed — run the script manually from the on-device Apps menu",
				"Verify the Flipper's USB cable is connected to the target and BadUSB FAP is present")
		} else {
			next = append(next,
				"Payload running — watch the target for expected behaviour",
				"Press BACK on the Flipper to abort if needed")
		}
	} else {
		next = append(next,
			"Payload deployed but not launched. Launch it with `badusb_run "+result.Path+"`",
			"Or call this workflow again with `auto_run=true` to chain generate→deploy→run")
	}

	summary := fmt.Sprintf("generated %d-byte BadUSB for %s and deployed to %s",
		len(result.Content), targetOS, result.Path)
	if autoRun {
		summary += " (auto-run requested)"
	}

	return encode(Result{
		Summary:   summary,
		Phases:    phases,
		NextSteps: next,
		Extra:     extra,
	}), nil
}
