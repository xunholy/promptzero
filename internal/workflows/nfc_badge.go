package workflows

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// NFCBadgePipeline triages an unknown NFC badge: nfc_detect → protocol
// classifier → protocol-specific follow-up. Returns a structured JSON
// report describing what the tag is and how to clone or attack it.
//
// Risk is High: may launch dumping FAPs that can write to magic tags.
//
// Params:
//   - attempt_dump (bool, default false): launch protocol-appropriate
//     dumping FAP after detection.
//   - timeout_seconds (int, default 30): timeout for nfc_detect.
func NFCBadgePipeline(ctx context.Context, deps Deps, params map[string]interface{}) (string, error) {
	const wf = "nfc_badge_pipeline"

	timeout := clamp(paramInt(params, "timeout_seconds", 30), 5, 120)
	attemptDump := paramBool(params, "attempt_dump", false)

	var phases []PhaseResult
	extra := map[string]interface{}{}

	// --- 1. Detect ---
	if ctx.Err() != nil {
		return cancelledResult("nfc badge triage", phases, extra), nil
	}
	p := runPhase("detect", "nfc_detect", func() (string, error) {
		return deps.Flipper.NFCDetect(time.Duration(timeout) * time.Second)
	})
	phases = append(phases, p)
	recordPhase(deps.Audit, wf, p, map[string]int{"timeout_seconds": timeout}, "medium")

	if !p.OK {
		return encode(Result{
			Summary: "nfc_detect failed: " + firstLine(p.Output),
			Phases:  phases,
			NextSteps: []string{
				"Re-seat the tag against the back of the Flipper and retry",
				"If the tag is 125 kHz LF (prox fob), use workflow_phys_pentest_badge_walk or rfid_read instead",
			},
			Extra: extra,
		}), nil
	}

	info := parseNFCDetectOutput(p.Output)
	extra["protocol"] = info.Protocol
	extra["uid"] = info.UID

	if info.Protocol == "" {
		return encode(Result{
			Summary:   "no tag detected",
			Phases:    phases,
			NextSteps: []string{"Hold the tag flat against the back of the Flipper and retry"},
			Extra:     extra,
		}), nil
	}

	// --- 2. Protocol-specific follow-up ---
	var nextSteps []string
	switch info.Family {
	case NFCFamilyMIFAREClassic:
		nextSteps = append(nextSteps,
			"Run `loader_mfkey` to recover sector keys from captured reader nonces",
			"Once keys are known, run `loader_mifare_nested` for full key recovery",
			"With all keys recovered, `nfc_dump_protocol Mifare_Classic` produces a full dump",
		)
		if attemptDump {
			dp := runPhase("magic_launch", "loader_nfc_magic", func() (string, error) {
				return deps.Flipper.LoaderNFCMagic()
			})
			phases = append(phases, dp)
			recordPhase(deps.Audit, wf, dp, nil, "high")
		} else {
			phases = append(phases, internalPhase("suggest",
				"MIFARE Classic detected — keys unknown; recommending loader_mfkey before any dump"))
		}

	case NFCFamilyUltralight:
		// Read pages 0 and 4 (typical UID + user-data boundary).
		for _, pg := range []int{0, 4} {
			if ctx.Err() != nil {
				return cancelledResult("nfc badge triage", phases, extra), nil
			}
			page := pg
			dp := runPhase(fmt.Sprintf("mfu_rdbl_%d", page), "nfc_mfu_rdbl", func() (string, error) {
				return deps.Flipper.NFCMFURead(page, 10*time.Second)
			})
			phases = append(phases, dp)
			recordPhase(deps.Audit, wf, dp, map[string]int{"page": page}, "medium")
		}
		nextSteps = append(nextSteps,
			"Ultralight / NTAG detected — run `nfc_dump_protocol Mifare_Ultralight` for the full contents",
			"If the tag is password-protected, try default auth (FFFFFFFF) via `nfc_raw_frame`",
		)

	case NFCFamilyNTAG:
		nextSteps = append(nextSteps,
			"NTAG detected — `nfc_dump_protocol NTAG` produces a full page dump",
			"Check for password-locked pages (typical NTAG213/215/216 config page offset)",
		)
		phases = append(phases, internalPhase("suggest",
			"NTAG detected — cloning possible onto a magic NTAG (UID-changeable)"))

	case NFCFamilyDESFire, NFCFamilyEMV, NFCFamilyISO14443_4:
		nextSteps = append(nextSteps,
			fmt.Sprintf("%s is applet-hosting — cloning requires the private keys and is typically out of scope", info.Protocol),
			"Use `nfc_apdu` for further enumeration: SELECT PPSE (00A404000E325041592E5359532E4444463031) for EMV",
			"DESFire: SELECT application then GetFileIDs (0x6F) to list files",
		)
		phases = append(phases, internalPhase("suggest",
			info.Protocol+" — out-of-scope-for-cloning, suggesting APDU recon"))

	default:
		nextSteps = append(nextSteps,
			"Unknown/unclassified protocol — try `nfc_subcommand dump` to dump whatever the Flipper can read",
			"If the tag's ATQA/SAK suggests a proprietary protocol, check vendor docs",
		)
		phases = append(phases, internalPhase("suggest",
			"Unknown protocol "+info.Protocol+" — no standard attack path"))
	}

	summary := fmt.Sprintf("Detected %s", info.Protocol)
	if info.UID != "" {
		summary += fmt.Sprintf(" UID %s", info.UID)
	}
	summary += " — " + nfcFamilyHint(info.Family)

	return encode(Result{
		Summary:   summary,
		Phases:    phases,
		NextSteps: nextSteps,
		Extra:     extra,
	}), nil
}

// NFCFamily is a coarse classification of the detected NFC tag.
// Drives the protocol-specific follow-up branch in NFCBadgePipeline.
type NFCFamily int

const (
	NFCFamilyUnknown NFCFamily = iota
	NFCFamilyMIFAREClassic
	NFCFamilyUltralight
	NFCFamilyNTAG
	NFCFamilyDESFire
	NFCFamilyEMV
	NFCFamilyISO14443_4
)

// NFCDetectInfo is the parsed shape of an nfc_detect / NFC scanner output
// — enough for the pipeline to branch on family and echo key fields in
// the JSON result.
type NFCDetectInfo struct {
	Protocol string
	UID      string
	ATQA     string
	SAK      string
	Family   NFCFamily
}

var (
	nfcProtocolPattern = regexp.MustCompile(`(?i)\b(Mifare Classic|Mifare Ultralight|Mifare UL|NTAG2\d{2}|NTAG|DESFire|EMV|ISO14443-[34][AB]?)\b`)
	nfcUIDPattern      = regexp.MustCompile(`(?i)UID[:\s]+((?:[0-9A-F]{2}[: ]?){4,10})`)
	nfcATQAPattern     = regexp.MustCompile(`(?i)ATQA[:\s]+([0-9A-F]{2}[: ]?[0-9A-F]{2})`)
	nfcSAKPattern      = regexp.MustCompile(`(?i)SAK[:\s]+([0-9A-F]{2})`)
)

// parseNFCDetectOutput classifies an NFC detection string by scanning for
// the protocol token, UID, ATQA and SAK. We deliberately avoid a
// one-liner regex and walk the output field-by-field so a new protocol
// name surfaces as an unknown-family tag rather than being mis-parsed.
func parseNFCDetectOutput(out string) NFCDetectInfo {
	info := NFCDetectInfo{}

	if m := nfcProtocolPattern.FindStringSubmatch(out); len(m) == 2 {
		info.Protocol = strings.TrimSpace(m[1])
		info.Family = classifyNFCFamily(info.Protocol)
	}
	if m := nfcUIDPattern.FindStringSubmatch(out); len(m) == 2 {
		info.UID = strings.ToUpper(strings.TrimSpace(m[1]))
	}
	if m := nfcATQAPattern.FindStringSubmatch(out); len(m) == 2 {
		info.ATQA = strings.ToUpper(strings.TrimSpace(m[1]))
	}
	if m := nfcSAKPattern.FindStringSubmatch(out); len(m) == 2 {
		info.SAK = strings.ToUpper(strings.TrimSpace(m[1]))
	}

	// If we didn't match a protocol name but did see an SAK, try inferring
	// from the SAK byte: 0x08/0x09 = MIFARE Classic 1K/4K, 0x00 =
	// Ultralight/NTAG, 0x20 = ISO14443-4.
	if info.Family == NFCFamilyUnknown && info.SAK != "" {
		info.Family = classifyNFCSAK(info.SAK)
		if info.Family != NFCFamilyUnknown && info.Protocol == "" {
			info.Protocol = nfcFamilyName(info.Family)
		}
	}

	return info
}

func classifyNFCFamily(protocol string) NFCFamily {
	p := strings.ToLower(protocol)
	switch {
	case strings.Contains(p, "mifare classic"):
		return NFCFamilyMIFAREClassic
	case strings.Contains(p, "mifare ultralight"), strings.Contains(p, "mifare ul"):
		return NFCFamilyUltralight
	case strings.Contains(p, "ntag"):
		return NFCFamilyNTAG
	case strings.Contains(p, "desfire"):
		return NFCFamilyDESFire
	case strings.Contains(p, "emv"):
		return NFCFamilyEMV
	case strings.Contains(p, "iso14443-4"):
		return NFCFamilyISO14443_4
	default:
		return NFCFamilyUnknown
	}
}

func classifyNFCSAK(sak string) NFCFamily {
	switch strings.ToUpper(strings.TrimSpace(sak)) {
	case "08", "09", "18", "19":
		return NFCFamilyMIFAREClassic
	case "00":
		return NFCFamilyUltralight
	case "20", "28":
		return NFCFamilyISO14443_4
	default:
		return NFCFamilyUnknown
	}
}

func nfcFamilyName(f NFCFamily) string {
	switch f {
	case NFCFamilyMIFAREClassic:
		return "Mifare Classic"
	case NFCFamilyUltralight:
		return "Mifare Ultralight"
	case NFCFamilyNTAG:
		return "NTAG"
	case NFCFamilyDESFire:
		return "DESFire"
	case NFCFamilyEMV:
		return "EMV"
	case NFCFamilyISO14443_4:
		return "ISO14443-4"
	default:
		return "unknown"
	}
}

func nfcFamilyHint(f NFCFamily) string {
	switch f {
	case NFCFamilyMIFAREClassic:
		return "MIFARE Classic: suggest mfkey32 recovery against default keys"
	case NFCFamilyUltralight:
		return "MIFARE Ultralight: dump-and-clone is straightforward once unlocked"
	case NFCFamilyNTAG:
		return "NTAG: cloneable onto a magic NTAG tag"
	case NFCFamilyDESFire:
		return "DESFire: applet-hosting, cloning requires keys"
	case NFCFamilyEMV:
		return "EMV payment card: out-of-scope-for-cloning"
	case NFCFamilyISO14443_4:
		return "ISO14443-4: applet-hosting, probe with nfc_apdu"
	default:
		return "unknown family — manual triage required"
	}
}
