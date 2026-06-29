package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/fileformat"
	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/generate"
	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/validator"
)

// generate.go registers:
//   - nfc_read_save     — scan-and-save NFC tag (AgentOnly)
//   - generate_evil_portal, generate_badusb, generate_subghz,
//     generate_ir, generate_nfc  — LLM-driven payload generators (AgentOnly)
//   - run_payload       — run a previously deployed payload (AgentOnly)
//   - generate_deploy_run — all-in-one generate → deploy → run (AgentOnly)

//nolint:gochecknoinits
func init() {
	Register(Spec{
		Name: "nfc_read_save",
		Description: "Scan an NFC tag and save it to the SD card as /ext/nfc/<name>.nfc. This is the default " +
			"tool for operator requests like 'scan this fob', 'read the badge', or 'save this card'. Does a full " +
			"NFCDetect, constructs a valid .nfc file (UID + ATQA + SAK, device-type-aware), runs the static " +
			"verifier, and writes via the same snapshot/rewind pipeline as the parametric builders. Works for " +
			"Classic 1K/4K, NTAG213/215/216, Ultralight. For high-security badges where sector keys are required " +
			"for full block reads, the UID-only save is still useful as a first pass — chain with loader_mfkey / " +
			"loader_mifare_nested for key recovery.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"name":{"type":"string","description":"Output filename stem (default: scanned_<uid>). Result lands at /ext/nfc/<name>.nfc"},` +
			`"path":{"type":"string","description":"Full SD path override — when set, takes precedence over name"},` +
			`"timeout_seconds":{"type":"integer","description":"How long to wait for a tag (default 15)"},` +
			`"verify_bypass":{"type":"boolean","description":"Skip the static verifier block on high/critical findings"}` +
			`}}`),
		Required:  nil,
		Risk:      risk.Medium,
		Group:     GroupFlipperNFC,
		AgentOnly: true,
		Handler:   nfcReadSaveHandler,
	})

	Register(Spec{
		Name: "generate_evil_portal",
		Description: "Generate an evil portal captive portal HTML page from a description. Creates a convincing " +
			"login page that captures credentials. Describe what it should look like: 'Google login page', " +
			"'Starbucks WiFi portal', 'corporate VPN login', etc. The AI creates a pixel-perfect replica. " +
			"Returns the generated HTML and optionally deploys it to the Flipper.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"description":{"type":"string","description":"What the portal should look like. Be specific: 'Google sign-in page with dark mode', 'airport free WiFi captive portal', 'Netflix login page'"},` +
			`"deploy":{"type":"boolean","description":"Auto-deploy to Flipper SD card (default true)"},` +
			`"path":{"type":"string","description":"Custom path on SD card (default /ext/apps_data/evil_portal/index.html)"},` +
			`"verify_bypass":{"type":"boolean","description":"Bypass the chain-of-verification pre-deploy check. Default false."}` +
			`}}`),
		Required:  []string{"description"},
		Risk:      risk.Medium,
		Group:     GroupGen,
		AgentOnly: true,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			return generatePayloadWithBypass(ctx, d, "evil_portal", str(p, "description"), str(p, "path"), "", "", boolOr(p, "deploy", true), boolOr(p, "verify_bypass", false))
		},
	})

	Register(Spec{
		Name: "generate_badusb",
		Description: "Generate a BadUSB/DuckyScript payload from a description. Describe what it should do: " +
			"'open reverse shell on Windows', 'exfiltrate WiFi passwords', 'rickroll the screen', 'install a keylogger'. " +
			"The AI creates the payload, validates syntax, and deploys to the Flipper.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"description":{"type":"string","description":"What the payload should do. Be specific about the target and goal."},` +
			`"target_os":{"type":"string","description":"Target OS: windows, macos, linux (default windows)"},` +
			`"keyboard_layout":{"type":"string","description":"Target keyboard layout (us, gb, de, fr, es, it, dk, no, sv, pt, br) — affects character encoding for non-ASCII text. Default us. Pair with v1nc / Momentum / Unleashed firmware that ships matching .kl layout files."},` +
			`"deploy":{"type":"boolean","description":"Auto-deploy to Flipper SD card (default true)"},` +
			`"path":{"type":"string","description":"Custom path on SD card"},` +
			`"verify_bypass":{"type":"boolean","description":"Bypass the chain-of-verification pre-deploy check. Default false."}` +
			`}}`),
		Required:  []string{"description"},
		Risk:      risk.Medium,
		Group:     GroupGen,
		AgentOnly: true,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			return generatePayloadWithBypass(ctx, d, "badusb", str(p, "description"), str(p, "path"), str(p, "target_os"), str(p, "keyboard_layout"), boolOr(p, "deploy", true), boolOr(p, "verify_bypass", false))
		},
	})

	Register(Spec{
		Name: "generate_subghz",
		Description: "Generate a Sub-GHz signal file (.sub) from a description. Describe the target: " +
			"'433MHz garage door opener', '315MHz car remote', 'CAME protocol gate opener'. " +
			"The AI creates the signal file with proper encoding.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"description":{"type":"string","description":"Target device and protocol details"},` +
			`"deploy":{"type":"boolean","description":"Auto-deploy to Flipper SD card (default true)"},` +
			`"path":{"type":"string","description":"Custom path on SD card"},` +
			`"verify_bypass":{"type":"boolean","description":"Bypass the chain-of-verification pre-deploy check. Default false."}` +
			`}}`),
		Required:  []string{"description"},
		Risk:      risk.Medium,
		Group:     GroupGen,
		AgentOnly: true,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			return generatePayloadWithBypass(ctx, d, "subghz", str(p, "description"), str(p, "path"), "", "", boolOr(p, "deploy", true), boolOr(p, "verify_bypass", false))
		},
	})

	Register(Spec{
		Name: "generate_ir",
		Description: "Generate an infrared remote file (.ir) from a description. Describe the target: " +
			"'Samsung TV remote', 'LG AC unit', 'Sony soundbar'. Creates a complete remote with all common commands.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"description":{"type":"string","description":"Target device — brand, model, type"},` +
			`"deploy":{"type":"boolean","description":"Auto-deploy to Flipper SD card (default true)"},` +
			`"path":{"type":"string","description":"Custom path on SD card"},` +
			`"verify_bypass":{"type":"boolean","description":"Bypass the chain-of-verification pre-deploy check. Default false."}` +
			`}}`),
		Required:  []string{"description"},
		Risk:      risk.Medium,
		Group:     GroupGen,
		AgentOnly: true,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			return generatePayloadWithBypass(ctx, d, "ir", str(p, "description"), str(p, "path"), "", "", boolOr(p, "deploy", true), boolOr(p, "verify_bypass", false))
		},
	})

	Register(Spec{
		Name: "generate_nfc",
		Description: "Generate an NFC tag file (.nfc) from a description. Describe what kind of tag: " +
			"'MIFARE Classic 1K with default keys', 'NTAG215 amiibo data', 'blank UID-changeable tag'.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"description":{"type":"string","description":"Tag type and data description"},` +
			`"deploy":{"type":"boolean","description":"Auto-deploy to Flipper SD card (default true)"},` +
			`"path":{"type":"string","description":"Custom path on SD card"},` +
			`"verify_bypass":{"type":"boolean","description":"Bypass the chain-of-verification pre-deploy check. Default false."}` +
			`}}`),
		Required:  []string{"description"},
		Risk:      risk.Medium,
		Group:     GroupGen,
		AgentOnly: true,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			return generatePayloadWithBypass(ctx, d, "nfc", str(p, "description"), str(p, "path"), "", "", boolOr(p, "deploy", true), boolOr(p, "verify_bypass", false))
		},
	})

	Register(Spec{
		Name: "run_payload",
		Description: "Run a previously generated or existing payload on the Flipper. Automatically detects the " +
			"type from the file path and executes the appropriate command (evil portal start, badusb run, subghz tx, " +
			"ir tx, nfc emulate).",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"path":{"type":"string","description":"Path to the payload file on Flipper SD card"},` +
			`"command":{"type":"string","description":"For IR files: specific command name to send"}` +
			`}}`),
		Required:  []string{"path"},
		Risk:      risk.High,
		Group:     GroupGen,
		AgentOnly: true,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return runPayload(d, str(p, "path"), str(p, "command"))
		},
	})

	Register(Spec{
		Name: "generate_deploy_run",
		Description: "All-in-one: generate a payload from a description, deploy it to the Flipper, and immediately " +
			"execute it. This is the fastest way to go from idea to action. Specify the type and describe what you want.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"type":{"type":"string","description":"Payload type: evil_portal, badusb, subghz, ir, nfc"},` +
			`"description":{"type":"string","description":"What to generate — be descriptive"},` +
			`"target_os":{"type":"string","description":"For badusb: target OS (default windows)"},` +
			`"path":{"type":"string","description":"Custom deploy path"}` +
			`}}`),
		Required:  []string{"type", "description"},
		Risk:      risk.Critical,
		Group:     GroupGen,
		AgentOnly: true,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			return generateDeployRun(ctx, d, str(p, "type"), str(p, "description"), str(p, "path"), str(p, "target_os"))
		},
	})
}

// --- Generation pipeline helpers ---

// generatePayloadWithBypass honours the chain-of-verification (P1-16).
// keyboardLayout is consumed only by payloadType=="badusb" — empty
// for every other type. v0.23-keyboard-layout work added it so the
// generate_badusb Spec can target non-US layouts without requiring a
// new dispatch path; tests + workflows that don't care pass "".
func generatePayloadWithBypass(ctx context.Context, d *Deps, payloadType, description, path, targetOS, keyboardLayout string, deploy, bypass bool) (string, error) {
	if d.Generator == nil {
		return "", fmt.Errorf("generator not configured — set a generation LLM provider")
	}

	var result *generate.Result
	var err error

	switch payloadType {
	case "evil_portal":
		result, err = d.Generator.EvilPortal(ctx, description)
	case "badusb":
		// keyboardLayout is plumbed through from the Spec handler for
		// generate_badusb. Workflow callers that don't care pass "" —
		// the Generator falls back to "us" in that case so existing
		// callers keep their pre-this-fix behaviour.
		result, err = d.Generator.BadUSB(ctx, description, targetOS, keyboardLayout)
	case "subghz":
		result, err = d.Generator.SubGHz(ctx, description)
	case "ir":
		result, err = d.Generator.IR(ctx, description)
	case "nfc":
		result, err = d.Generator.NFC(ctx, description)
	default:
		return "", fmt.Errorf("unknown payload type: %s", payloadType)
	}
	if err != nil {
		return "", err
	}

	// Static validator gate — deterministic / offline.
	if staticRep, haveStatic := genRunStaticValidator(payloadType, result.Path, result.Content); haveStatic {
		if deploy && staticRep.Has(validator.SeverityCritical) && !bypass {
			return fmt.Sprintf("Generated %s but static validator blocked deploy.\n\n%s\n\nPreview:\n%s\n\nPass verify_bypass=true to override.",
				payloadType, genRenderValidatorReport(staticRep), result.Preview), nil
		}
	}

	// Chain-of-verification: LLM pass against the generated content before deploy.
	verdictSummary, blockMsg := d.RunBuildVerification(ctx, payloadType, []byte(result.Content), bypass)
	if deploy && blockMsg != "" {
		return fmt.Sprintf("Generated %s but deploy blocked by verifier.\n\n%s\n\nPreview:\n%s\n\nPass verify_bypass=true to override if you accept the risk.",
			payloadType, blockMsg, result.Preview), nil
	}

	if deploy {
		deployPath := path
		if deployPath == "" {
			deployPath = genDefaultPath(payloadType)
		}
		d.SnapshotBeforeWrite(ctx, deployPath)

		deployCtx, deployCancel := context.WithTimeout(ctx, 30*time.Second)
		deployErr := d.Generator.Deploy(deployCtx, result, path)
		deployCancel()
		if deployErr != nil {
			return "", fmt.Errorf("generated %s but deploy failed: %w\n\n%s\n\nContent preview:\n%s", payloadType, deployErr, verdictSummary, result.Preview)
		}
		return fmt.Sprintf("Generated and deployed %s to %s\n\n%s\n\nPreview:\n%s", payloadType, result.Path, verdictSummary, result.Preview), nil
	}

	return fmt.Sprintf("Generated %s (not deployed)\n\n%s\n\nPreview:\n%s", payloadType, verdictSummary, result.Preview), nil
}

// runPayload dispatches to the appropriate flipper method based on the file path suffix.
func runPayload(d *Deps, path, command string) (string, error) {
	switch {
	case strings.Contains(path, "evil_portal"):
		if d.Marauder != nil {
			return d.Marauder.EvilPortalStart("")
		}
		return "", fmt.Errorf("evil portal requires WiFi devboard (--wifi)")
	case strings.HasSuffix(path, ".txt") && strings.Contains(path, "badusb"):
		return d.Flipper.BadUSBRun(path)
	case strings.HasSuffix(path, ".sub"):
		return d.Flipper.SubGHzTx(path)
	case strings.HasSuffix(path, ".ir"):
		if command == "" {
			command = "Power"
		}
		return d.Flipper.IRUniversal(path, command)
	case strings.HasSuffix(path, ".nfc"):
		return d.Flipper.NFCEmulate(path)
	case strings.HasSuffix(path, ".rfid"):
		return d.Flipper.LoaderOpen("RFID", path)
	default:
		return "", fmt.Errorf("unknown payload type for path: %s", path)
	}
}

// generateDeployRun runs the full generate → deploy → run pipeline.
// The run step is gated through d.WorkflowConfirm so each payload type
// (badusb/portal/subghz/nfc/ir) surfaces a typed confirm before execution.
func generateDeployRun(ctx context.Context, d *Deps, payloadType, description, path, targetOS string) (string, error) {
	genResult, err := generatePayloadWithBypass(ctx, d, payloadType, description, path, targetOS, "", true, false)
	if err != nil {
		return "", err
	}

	deployedPath := path
	if deployedPath == "" {
		deployedPath = genDefaultPath(payloadType)
	}

	// Gate the run step on the underlying tool's actual risk level so
	// portal/badusb/sub-GHz/IR/NFC each surface a typed confirm.
	underlyingTool, riskLevel := genRunPayloadRisk(deployedPath)
	if d.WorkflowConfirm != nil {
		if !d.WorkflowConfirm(ctx, underlyingTool, map[string]string{"path": deployedPath}, riskLevel.String()) {
			return genResult + "\n\nRun denied: operator declined the confirm gate.", nil
		}
	}

	runResult, err := runPayload(d, deployedPath, "")
	if err != nil {
		return genResult + fmt.Sprintf("\n\nGenerated and deployed, but run failed: %v", err), nil
	}
	return genResult + "\n\nExecuted: " + runResult, nil
}

// genRunPayloadRisk returns the underlying tool name and effective risk level
// for a given deployed payload path. Delegates to risk.ResolveRunPayloadRisk,
// the single source of truth shared with the agent loop, RunTool, and the MCP
// consent gate so the surfaces cannot drift.
func genRunPayloadRisk(path string) (underlyingTool string, level risk.Level) {
	return risk.ResolveRunPayloadRisk(path)
}

// genDefaultPath mirrors the generator package's default-path selection.
func genDefaultPath(payloadType string) string {
	switch payloadType {
	case "evil_portal":
		return "/ext/apps_data/evil_portal/index.html"
	case "badusb":
		return "/ext/badusb/generated_payload.txt"
	case "subghz":
		return "/ext/subghz/generated_signal.sub"
	case "ir":
		return "/ext/infrared/generated_remote.ir"
	case "nfc":
		return "/ext/nfc/generated_tag.nfc"
	}
	return ""
}

// genRunStaticValidator dispatches to the per-payload-type static validator.
func genRunStaticValidator(payloadType, path, content string) (validator.Report, bool) {
	switch payloadType {
	case "badusb":
		return validator.Validate(path, content), true
	case "evil_portal":
		return validator.ValidateEvilPortal(path, content), true
	default:
		return validator.Report{}, false
	}
}

// genRenderValidatorReport flattens a Report into a short multi-line string.
func genRenderValidatorReport(r validator.Report) string {
	if len(r.Findings) == 0 {
		return fmt.Sprintf("static validator: %s (no findings)", r.Severity)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "static validator: %s — %d finding(s)\n", r.Severity, len(r.Findings))
	for _, f := range r.Findings {
		if f.Line > 0 {
			fmt.Fprintf(&b, "  [%s] L%d %s: %s\n", f.Severity, f.Line, f.Rule, f.Message)
		} else {
			fmt.Fprintf(&b, "  [%s] %s: %s\n", f.Severity, f.Rule, f.Message)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// --- nfc_read_save handler ---

// dumpSavedPathRE captures the file path from Momentum's `dump` output banner:
// `Dump saved to '/ext/nfc/dump-YYYYMMDD-HHMMSS.nfc'`.
var dumpSavedPathRE = regexp.MustCompile(`Dump saved to '([^']+)'`)

func nfcReadSaveHandler(ctx context.Context, d *Deps, p map[string]any) (string, error) {
	timeout := time.Duration(intOr(p, "timeout_seconds", 15)) * time.Second
	raw, err := d.Flipper.NFCDetect(timeout)
	if err != nil {
		return "", fmt.Errorf("nfc_read_save: %w", err)
	}
	parsed := flipper.ParseNFCDetect(raw)
	if !parsed.Detected {
		return "", fmt.Errorf("nfc_read_save: no tag detected after %s — hold the tag flat against the NFC (front) side of the Flipper and retry. For 125 kHz LF prox fobs use rfid_read instead", timeout)
	}
	// Momentum's nfc scanner identifies the protocol family but does NOT emit
	// UID/ATQA/SAK — fall back to dump (auto-detect) which scans, identifies,
	// AND writes a complete .nfc file.
	if parsed.UID == "" {
		return nfcReadSaveViaDump(ctx, d, parsed, p, timeout)
	}

	deviceType := genMapNFCType(parsed.Type)
	nfcBytes, err := fileformat.BuildNFC(fileformat.NFCBuildParams{
		DeviceType: deviceType,
		UID:        parsed.UID,
		ATQA:       parsed.ATQA,
		SAK:        parsed.SAK,
	})
	if err != nil {
		// UID-length mismatch on an odd device — fall back to type-less save.
		fallback, ferr := fileformat.BuildNFC(fileformat.NFCBuildParams{
			DeviceType: "NFC",
			UID:        parsed.UID,
			ATQA:       parsed.ATQA,
			SAK:        parsed.SAK,
		})
		if ferr != nil {
			return "", fmt.Errorf("nfc_read_save: build failed (primary: %v; fallback: %v)", err, ferr)
		}
		nfcBytes = fallback
		deviceType = "NFC"
	}

	summary, blockMsg := d.RunBuildVerification(ctx, "nfc", nfcBytes, boolOr(p, "verify_bypass", false))
	if blockMsg != "" {
		return blockMsg, nil
	}

	outPath := str(p, "path")
	if outPath == "" {
		name := str(p, "name")
		if name == "" {
			name = "scanned_" + genSanitizeFilename(parsed.UID)
		}
		outPath = "/ext/nfc/" + name + ".nfc"
	}
	d.SnapshotBeforeWrite(ctx, outPath)
	if err := d.Flipper.WriteFileCtx(ctx, outPath, nfcBytes); err != nil {
		return "", fmt.Errorf("write %s: %w", outPath, err)
	}

	nextHint := ""
	if strings.Contains(strings.ToLower(deviceType), "classic") {
		nextHint = "\n\nNote: this is a UID-only save — full block data requires sector keys. For cloning against real readers, chain loader_mfkey (with captured reader nonces) → loader_mifare_nested → re-run nfc_dump_protocol once keys are known."
	}
	return fmt.Sprintf("saved %s (%s, UID %s) → %s\n%s%s", parsed.Type, deviceType, parsed.UID, outPath, summary, nextHint), nil
}

// nfcReadSaveViaDump is the Momentum-specific fallback when nfc scanner identified
// a tag but didn't emit UID. It calls the auto-detect dump (no -p), captures the
// firmware's saved-file path, and renames to the caller's requested path.
func nfcReadSaveViaDump(ctx context.Context, d *Deps, scan flipper.NFCDetectResult, p map[string]any, timeout time.Duration) (string, error) {
	dumpOut, err := d.Flipper.NFCDumpProtocol("", timeout)
	if err != nil {
		return "", fmt.Errorf("nfc_read_save: dump fallback failed: %w", err)
	}
	m := dumpSavedPathRE.FindStringSubmatch(dumpOut)
	if len(m) != 2 {
		return "", fmt.Errorf("nfc_read_save: dump returned no saved-file path (output: %q)", strings.TrimSpace(dumpOut))
	}
	dumpedPath := m[1]

	outPath := str(p, "path")
	if outPath == "" {
		name := str(p, "name")
		if name == "" {
			name = "scanned_" + time.Now().UTC().Format("20060102_150405")
		}
		outPath = "/ext/nfc/" + name + ".nfc"
	}

	if outPath != dumpedPath {
		d.SnapshotBeforeWrite(ctx, outPath)
		if _, err := d.Flipper.StorageRename(dumpedPath, outPath); err != nil {
			return "", fmt.Errorf("nfc_read_save: rename %s → %s failed: %w (original dump preserved)", dumpedPath, outPath, err)
		}
	}

	deviceType := genMapNFCType(scan.Type)
	nextHint := ""
	if strings.Contains(strings.ToLower(deviceType), "classic") {
		nextHint = "\n\nNote: full sector data requires keys. If the dump shows blocks past sector 0, you already have them — otherwise chain loader_mfkey (with captured reader nonces) → loader_mifare_nested to recover keys."
	}
	return fmt.Sprintf("saved %s (%s, via auto-detect dump) → %s%s", scan.Type, deviceType, outPath, nextHint), nil
}

// genMapNFCType translates the scanner's Type string into a DeviceType value
// BuildNFC + validateUIDLength will accept.
func genMapNFCType(typ string) string {
	lower := strings.ToLower(typ)
	switch {
	case strings.Contains(lower, "ntag213"):
		return "NTAG213"
	case strings.Contains(lower, "ntag215"):
		return "NTAG215"
	case strings.Contains(lower, "ntag216"):
		return "NTAG216"
	case strings.Contains(lower, "ultralight"):
		return "Mifare Ultralight"
	case strings.Contains(lower, "classic"):
		return "Mifare Classic"
	case strings.Contains(lower, "desfire"):
		return "Mifare DESFire"
	case strings.Contains(lower, "plus"):
		return "Mifare Plus"
	default:
		return "NFC"
	}
}

// genSanitizeFilename strips characters that aren't safe in a Flipper SD filename.
func genSanitizeFilename(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9',
			r >= 'A' && r <= 'Z',
			r >= 'a' && r <= 'z',
			r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := b.String()
	if out == "" {
		return "unknown"
	}
	return out
}
