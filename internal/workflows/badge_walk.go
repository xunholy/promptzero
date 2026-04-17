package workflows

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// PhysPentestBadgeWalk loops RFID (LF 125 kHz) → NFC (HF 13.56 MHz) →
// iButton (1-Wire) reads until the caller's duration elapses or ctx is
// cancelled, dedupes captures by their decoded identifier, and mirrors
// every new sighting to a CSV on the Flipper's SD card.
//
// Intended for a physical-pentest site walk: keep the Flipper in your
// pocket, run this workflow, and brush the reader against every badge/
// fob/reader you encounter. The CSV is consumable by downstream tooling
// and the JSON report summarises unique badges seen.
//
// Risk is Medium: read-only across three radios, but it writes a log
// file to SD.
//
// Params:
//   - duration_seconds (int, default 120, clamped 10..1800): total walk length.
//   - per_read_timeout (int, default 3, clamped 1..15): per-radio read timeout.
//   - csv_path (string, default /ext/badge_walk.csv): CSV output path.
func PhysPentestBadgeWalk(ctx context.Context, deps Deps, params map[string]interface{}) (string, error) {
	const wf = "phys_pentest_badge_walk"

	total := clamp(paramInt(params, "duration_seconds", 120), 10, 1800)
	perRead := clamp(paramInt(params, "per_read_timeout", 3), 1, 15)
	csvPath := paramString(params, "csv_path")
	if csvPath == "" {
		csvPath = "/ext/badge_walk.csv"
	}

	deadline := time.Now().Add(time.Duration(total) * time.Second)
	perReadDur := time.Duration(perRead) * time.Second

	var phases []PhaseResult
	seen := map[string]badgeRecord{}
	extra := map[string]interface{}{
		"csv_path":         csvPath,
		"duration_seconds": total,
	}

	csv := strings.Builder{}
	csv.WriteString("ts,radio,protocol,identifier,raw\n")

	iteration := 0
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			break
		}
		iteration++

		// --- RFID (LF 125 kHz) ---
		rfPhase := runPhase(fmt.Sprintf("rfid_%d", iteration), "rfid_read", func() (string, error) {
			return deps.Flipper.RFIDRead(ctx, "", perReadDur)
		})
		phases = append(phases, rfPhase)
		if rfPhase.OK {
			if rec := parseRFIDBadge(rfPhase.Output); rec.identifier != "" {
				recordIfNew(seen, rec, &csv)
			}
		}

		if ctx.Err() != nil {
			break
		}

		// --- NFC (HF 13.56 MHz) ---
		nfcPhase := runPhase(fmt.Sprintf("nfc_%d", iteration), "nfc_detect", func() (string, error) {
			return deps.Flipper.NFCDetect(perReadDur)
		})
		phases = append(phases, nfcPhase)
		if nfcPhase.OK {
			info := parseNFCDetectOutput(nfcPhase.Output)
			if info.UID != "" {
				rec := badgeRecord{
					radio:      "nfc",
					protocol:   info.Protocol,
					identifier: info.UID,
					raw:        firstLine(nfcPhase.Output),
				}
				recordIfNew(seen, rec, &csv)
			}
		}

		if ctx.Err() != nil {
			break
		}

		// --- iButton (1-Wire) ---
		ibPhase := runPhase(fmt.Sprintf("ibutton_%d", iteration), "ibutton_read", func() (string, error) {
			return deps.Flipper.IButtonRead(perReadDur)
		})
		phases = append(phases, ibPhase)
		if ibPhase.OK {
			if rec := parseIButtonBadge(ibPhase.Output); rec.identifier != "" {
				recordIfNew(seen, rec, &csv)
			}
		}
	}

	// Persist the CSV to the SD card — best-effort; a write failure is
	// surfaced as a phase but doesn't fail the whole workflow.
	writePhase := runPhase("csv_write", "storage_write", func() (string, error) {
		err := deps.Flipper.StorageWrite(csvPath, csv.String())
		if err != nil {
			return err.Error(), err
		}
		return fmt.Sprintf("wrote %d bytes to %s", csv.Len(), csvPath), nil
	})
	phases = append(phases, writePhase)
	recordPhase(deps.Audit, wf, writePhase, map[string]string{"path": csvPath}, "medium")

	badges := make([]map[string]interface{}, 0, len(seen))
	for _, r := range seen {
		badges = append(badges, map[string]interface{}{
			"radio":      r.radio,
			"protocol":   r.protocol,
			"identifier": r.identifier,
			"first_seen": r.firstSeen.UTC().Format(time.RFC3339),
		})
	}
	extra["badges"] = badges

	summary := fmt.Sprintf("walked %d iterations — %d unique badge(s)", iteration, len(seen))
	var next []string
	if len(seen) == 0 {
		next = append(next,
			"No badges seen — brush the Flipper back (LF antenna) against the reader/fob",
			"Verify the badge type — if it's 13.56 MHz only, NFC will match but RFID will not",
		)
	} else {
		next = append(next,
			"Replay any captured RFID with `rfid_emulate <protocol> <data>` after authorisation",
			"For MIFARE Classic UIDs, chain into workflow_nfc_badge_pipeline to recover keys",
			fmt.Sprintf("Full CSV on the Flipper SD at %s — pull via `storage_read`", csvPath),
		)
	}

	return encode(Result{
		Summary:   summary,
		Phases:    phases,
		NextSteps: next,
		Extra:     extra,
	}), nil
}

// badgeRecord is an internal dedupe entry keyed by radio+identifier.
type badgeRecord struct {
	radio      string
	protocol   string
	identifier string
	raw        string
	firstSeen  time.Time
}

// recordIfNew adds a record to `seen` and appends a CSV row if the
// radio+identifier pair hasn't already been captured this walk.
func recordIfNew(seen map[string]badgeRecord, rec badgeRecord, csv *strings.Builder) {
	key := rec.radio + "|" + rec.identifier
	if _, exists := seen[key]; exists {
		return
	}
	rec.firstSeen = time.Now()
	seen[key] = rec
	// CSV escaping: quote anything with commas/quotes; replace embedded
	// quotes with "".
	fmt.Fprintf(csv, "%s,%s,%s,%s,%s\n",
		rec.firstSeen.UTC().Format(time.RFC3339),
		csvField(rec.radio),
		csvField(rec.protocol),
		csvField(rec.identifier),
		csvField(rec.raw))
}

func csvField(v string) string {
	if strings.ContainsAny(v, ",\"\n") {
		return `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
	}
	return v
}

var (
	rfidProtocolPattern = regexp.MustCompile(`(?i)^(EM4100|EM-?410x|HID ?Prox|H10301|Indala|AWID|FDX-?[AB]|Pyramid|Viking|IOProx|Jablotron|Paradox|NexWatch|Presco|Keri)\b`)
	rfidDataPattern     = regexp.MustCompile(`(?i)(?:Data|Key|Card ID)[:\s]+([0-9A-F][0-9A-F :]{3,})`)

	// iButton output: "Key: 01 23 45 67 89 AB CD EF" preceded by a
	// protocol line like "Dallas" or "Cyfral".
	ibuttonKeyPattern   = regexp.MustCompile(`(?i)Key[:\s]+((?:[0-9A-F]{2}[: ]?){4,16})`)
	ibuttonProtoPattern = regexp.MustCompile(`(?i)(Dallas|Cyfral|Metakom)`)
)

// parseRFIDBadge extracts the protocol + decoded data from an
// `rfid read` output. Returns a zero record if nothing matched.
func parseRFIDBadge(out string) badgeRecord {
	rec := badgeRecord{radio: "rfid"}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if m := rfidProtocolPattern.FindStringSubmatch(line); len(m) == 2 && rec.protocol == "" {
			rec.protocol = strings.TrimSpace(m[1])
			rec.raw = line
		}
		if m := rfidDataPattern.FindStringSubmatch(line); len(m) == 2 && rec.identifier == "" {
			rec.identifier = strings.ToUpper(strings.TrimSpace(m[1]))
		}
	}
	return rec
}

// parseIButtonBadge extracts the key bytes from an `ikey read` output.
// The protocol line appears on its own line in every firmware variant
// we've seen (Dallas, Cyfral, Metakom).
func parseIButtonBadge(out string) badgeRecord {
	rec := badgeRecord{radio: "ibutton"}
	if m := ibuttonProtoPattern.FindStringSubmatch(out); len(m) == 2 {
		rec.protocol = strings.TrimSpace(m[1])
	}
	if m := ibuttonKeyPattern.FindStringSubmatch(out); len(m) == 2 {
		rec.identifier = strings.ToUpper(strings.TrimSpace(m[1]))
		rec.raw = strings.TrimSpace(m[0])
	}
	return rec
}
