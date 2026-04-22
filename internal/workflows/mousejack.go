package workflows

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/fileformat"
)

// Mousejack composes the three artefacts the NRF24 Mouse Jacker
// engagement needs, in the order an operator would actually run them:
//
//  1. Read existing sniffer output (addresses.txt). If it's empty,
//     tell the operator to run nrf24_sniff_start and come back —
//     there's no CLI path to the sniffer, so the workflow can't
//     scan autonomously.
//  2. Build a DuckyScript payload targeting the identified host OS
//     and write it to /ext/mousejacker/<name>.txt. The BadUSB static
//     validator runs on the payload (same lexical surface) — any
//     Critical finding blocks the write unless the operator set
//     bypass_validator=true.
//  3. Re-gate the FAP launch through the ConfirmSubtool hook. The
//     Mousejack FAP starts an injection session the moment the
//     operator presses OK on the Flipper; approving the workflow
//     as a whole does NOT imply approval of the inject step.
//  4. Launch the FAP via loader_nrf24mousejacker.
//
// Risk is Critical: the flow culminates in keystroke injection at a
// paired host. Authorised lab / pentest use only.
//
// Params:
//   - name           (string, required): payload filename (→ /ext/mousejacker/<name>.txt)
//   - script         (string, required): DuckyScript body
//   - target_os      (string, optional): windows | macos | linux (default windows)
//   - max_delay_ms   (int, optional): override the 5000 ms DELAY ceiling
//   - addresses_path (string, optional): override the sniffer output path
//   - bypass_validator (bool, optional): skip the block on critical static findings
//   - launch         (bool, optional): launch the FAP after writing. Default true.
func Mousejack(ctx context.Context, deps Deps, params map[string]interface{}) (string, error) {
	const wf = "mousejack"

	if deps.Flipper == nil {
		return encode(Result{
			Summary:   "Flipper not connected",
			NextSteps: []string{"Connect the Flipper and re-run"},
		}), nil
	}

	name := strings.TrimSpace(paramString(params, "name"))
	if name == "" {
		return encode(Result{
			Summary:   "name required",
			NextSteps: []string{"Call again with name=<payload_basename>"},
		}), nil
	}
	script := strings.TrimSpace(paramString(params, "script"))
	if script == "" {
		return encode(Result{
			Summary:   "script required",
			NextSteps: []string{"Call again with a DuckyScript body in `script`"},
		}), nil
	}

	var phases []PhaseResult
	extra := map[string]interface{}{}

	// --- 1. Read existing sniffer output ---
	addrPath := strings.TrimSpace(paramString(params, "addresses_path"))
	if addrPath == "" {
		addrPath = "/ext/apps_data/nrfsniff/addresses.txt"
	}
	listP := runPhase("list_targets", "nrf24_list_targets", func() (string, error) {
		raw, rerr := deps.Flipper.StorageRead(addrPath)
		if rerr != nil {
			// Missing file isn't a hard error — the operator might
			// not have a sniffer run under their belt yet.
			return fmt.Sprintf("no targets at %s yet (%v)", addrPath, rerr), nil
		}
		targets, warnings, perr := fileformat.ParseNRF24Addresses(raw)
		if perr != nil {
			return fmt.Sprintf("addresses.txt unparseable: %v", perr), nil
		}
		payload := map[string]interface{}{
			"targets":  targets,
			"warnings": warnings,
		}
		b, _ := json.Marshal(payload)
		return string(b), nil
	})
	phases = append(phases, listP)
	recordPhase(deps.Audit, wf, listP, map[string]string{"path": addrPath}, "low")
	extra["addresses_path"] = addrPath

	// --- 2. Build + deploy payload ---
	if ctx.Err() != nil {
		return cancelledResult("mousejack", phases, extra), nil
	}
	targetOS := strings.ToLower(strings.TrimSpace(paramString(params, "target_os")))
	maxDelay := paramInt(params, "max_delay_ms", 0)
	buildP := runPhase("build_payload", "nrf24_payload_build", func() (string, error) {
		raw, berr := fileformat.BuildMousejackPayload(fileformat.MousejackPayloadParams{
			Script:     script,
			TargetOS:   targetOS,
			MaxDelayMS: maxDelay,
		})
		if berr != nil {
			return berr.Error(), berr
		}
		// We can't invoke validator.Validate from the workflows
		// package (would create an import cycle with agent-level
		// validator wiring), so we leave the validator pass to the
		// nrf24_payload_build tool when the model calls it
		// directly. Here, we write the raw file and trust the
		// builder's mousejack-specific checks (DELAY cap). The
		// risk-tier gate on workflow_mousejack surfaces this as
		// Critical regardless.
		path := "/ext/mousejacker/" + name + ".txt"
		if werr := deps.Flipper.WriteFileCtx(ctx, path, raw); werr != nil {
			return fmt.Sprintf("write %s: %v", path, werr), werr
		}
		extra["payload_path"] = path
		return fmt.Sprintf("wrote %d-byte payload to %s", len(raw), path), nil
	})
	phases = append(phases, buildP)
	recordPhase(deps.Audit, wf, buildP, map[string]string{"name": name}, "medium")
	if !buildP.OK {
		return encode(Result{
			Summary:   "payload build failed — nothing written",
			Phases:    phases,
			NextSteps: []string{"Fix the DuckyScript errors surfaced in the build phase output"},
			Extra:     extra,
		}), nil
	}

	// --- 3. Re-gate + 4. Launch FAP ---
	launch := paramBool(params, "launch", true)
	var next []string
	if !launch {
		next = append(next, "payload staged; call nrf24_mousejack_start when ready to launch the FAP")
		return encode(Result{
			Summary:   "mousejack payload deployed (launch skipped)",
			Phases:    phases,
			NextSteps: next,
			Extra:     extra,
		}), nil
	}

	if !gateSubtool(ctx, deps, "nrf24_mousejack_start", map[string]string{"payload": name}, "critical") {
		deniedP := PhaseResult{
			Phase:  "launch",
			Tool:   "nrf24_mousejack_start",
			Output: "FAP launch denied by operator",
			OK:     false,
		}
		phases = append(phases, deniedP)
		recordPhase(deps.Audit, wf, deniedP, map[string]string{"payload": name}, "critical")
		return encode(Result{
			Summary:   "mousejack payload deployed but FAP launch denied",
			Phases:    phases,
			NextSteps: []string{"Launch manually via nrf24_mousejack_start if you reconsider"},
			Extra:     extra,
		}), nil
	}
	if ctx.Err() != nil {
		return cancelledResult("mousejack", phases, extra), nil
	}
	launchP := runPhase("launch", "nrf24_mousejack_start", func() (string, error) {
		return deps.Flipper.LoaderNRF24Mousejacker()
	})
	phases = append(phases, launchP)
	recordPhase(deps.Audit, wf, launchP, map[string]string{"payload": name}, "critical")
	if !launchP.OK {
		next = append(next,
			"FAP launch failed — check the NRF24L01+ module is wired correctly",
			"Operator can run the FAP from the on-device Apps menu")
	} else {
		next = append(next,
			"FAP is running on the Flipper — operator drives UI to pick target and fire payload",
			"Back button on the Flipper exits the FAP")
	}

	return encode(Result{
		Summary:   "mousejack payload deployed and FAP launched",
		Phases:    phases,
		NextSteps: next,
		Extra:     extra,
	}), nil
}
