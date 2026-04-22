// Command flipper-usecases runs realistic operator tasks against a
// live Flipper Zero and reports pass/fail + concise summaries.
//
// Complementary to flipper-validate: that binary exercises every
// primitive one-by-one to prove the transport works. This binary
// exercises the *user-visible* surface — the short natural-language
// requests operators actually type into PromptZero ("scan my fob",
// "what's on my Flipper", "listen for garage doors on 433") — and
// shows what the tool_result would look like when the agent
// dispatches them. No LLM required; each use case is a thin
// operator-prompt → tool-call mapping.
//
// Use this to catch "the tool returns success=true but didn't do
// what the operator wanted" regressions before they reach a real
// engagement. See docs/RELEASING.md for how results feed the
// Verified block in CHANGELOG.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/fileformat"
	"github.com/xunholy/promptzero/internal/flipper"
)

// Outcome is the three-state result every use case returns.
type Outcome int

const (
	OutcomePass Outcome = iota
	OutcomeSkip
	OutcomeFail
)

func (o Outcome) marker() string {
	switch o {
	case OutcomePass:
		return "\x1b[32m✓\x1b[0m"
	case OutcomeSkip:
		return "\x1b[33m⊘\x1b[0m"
	default:
		return "\x1b[31m✗\x1b[0m"
	}
}

// Usecase pairs an operator-facing prompt with the dispatch logic the
// agent would invoke. Each case should feel like a real request —
// concise, no jargon, no implementation details leaking into the
// prompt phrasing. The Run function's job is to execute the
// corresponding primitive(s) and return a summary the operator
// could read back.
type Usecase struct {
	Category    string
	Prompt      string
	Description string
	// When RequiresCard is true, the use case needs an NFC/RFID card
	// or contact key physically present during the run. We still
	// execute it; the summary surfaces the "no tag" outcome when
	// nothing is on the reader.
	RequiresCard bool
	// When non-empty, the case is skipped with this explanation.
	// Used for tasks that would affect other people / equipment
	// (transmit, emulate without target) or that lock the CLI
	// (FAP launch).
	Skip string
	Run  func(ctx context.Context, f *flipper.Flipper) (summary string, err error)
}

var cases = []Usecase{
	// ----- Device health (always runnable, no hardware touch) -----
	{
		Category:    "health",
		Prompt:      "what's my flipper's battery level?",
		Description: "reads power_info — typical first-turn question on a fresh session",
		Run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			pm, err := f.PowerInfoMap()
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("battery=%s%%, charging=%s", pm["charge_level"], pm["charging"]), nil
		},
	},
	{
		Category:    "health",
		Prompt:      "what firmware am I running?",
		Description: "reads device_info to identify the fork (stock / Momentum / Unleashed / Xtreme)",
		Run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			di, err := f.DeviceInfoMap()
			if err != nil {
				return "", err
			}
			fork := di["firmware_origin_fork"]
			if fork == "" {
				fork = "stock"
			}
			return fmt.Sprintf("fork=%s, version=%s, hw_model=%s",
				fork, di["firmware_version"], di["hardware_model"]), nil
		},
	},
	{
		Category:    "health",
		Prompt:      "how much space do I have on the SD card?",
		Description: "reads storage_info for /ext — useful before large captures or generate_* deploys",
		Run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			fs, err := f.StorageFSInfoMap("/ext")
			if err != nil {
				return "", err
			}
			totalGB := bytesToGB(fs["totalSpace"])
			freeGB := bytesToGB(fs["freeSpace"])
			return fmt.Sprintf("label=%q type=%s total=%.1fGB free=%.1fGB",
				fs["label"], fs["type"], totalGB, freeGB), nil
		},
	},

	// ----- Storage / file discovery -----
	{
		Category:    "storage",
		Prompt:      "what NFC files do I have saved?",
		Description: "lists /ext/nfc — common operator lookup after a scan session",
		Run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			out, err := f.StorageList("/ext/nfc")
			if err != nil {
				return "", err
			}
			files := countListEntries(out, ".nfc")
			return fmt.Sprintf("%d .nfc files under /ext/nfc", files), nil
		},
	},
	{
		Category:    "storage",
		Prompt:      "what SubGHz captures are on the Flipper?",
		Description: "lists /ext/subghz — handy for picking a .sub to replay",
		Run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			out, err := f.StorageList("/ext/subghz")
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("%d .sub files under /ext/subghz",
				countListEntries(out, ".sub")), nil
		},
	},
	{
		Category:    "storage",
		Prompt:      "any BadUSB scripts on the SD?",
		Description: "lists /ext/badusb — confirm what payloads are deployable",
		Run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			out, err := f.StorageList("/ext/badusb")
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("%d BadUSB files (.txt) under /ext/badusb",
				countListEntries(out, ".txt")), nil
		},
	},

	// ----- NFC (needs card on the reader) -----
	{
		Category:     "nfc",
		Prompt:       "scan this NFC card",
		Description:  "the motivating use case — NFCDetect loops until card appears or timeout",
		RequiresCard: true,
		Run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			raw, err := f.NFCDetect(8 * time.Second)
			if err != nil {
				return "", err
			}
			parsed := flipper.ParseNFCDetect(raw)
			if !parsed.Detected {
				return "no tag detected after 8s (place a card on the NFC antenna to exercise this)", nil
			}
			var parts []string
			parts = append(parts, "detected "+parsed.Type)
			if parsed.UID != "" {
				parts = append(parts, "UID="+parsed.UID)
			}
			if parsed.ATQA != "" {
				parts = append(parts, "ATQA="+parsed.ATQA)
			}
			if parsed.SAK != "" {
				parts = append(parts, "SAK="+parsed.SAK)
			}
			if parsed.UID == "" {
				parts = append(parts, "(Momentum's scanner outputs protocol only; UID harvest needs nfc_dump_protocol / loader_mfkey for Classic)")
			}
			return strings.Join(parts, ", "), nil
		},
	},
	{
		Category:     "nfc",
		Prompt:       "save this card to an .nfc file",
		Description:  "nfc_read_save handler path — the default for 'scan my fob / badge'. Composes detect → BuildNFC → write.",
		RequiresCard: true,
		Run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			raw, err := f.NFCDetect(8 * time.Second)
			if err != nil {
				return "", err
			}
			parsed := flipper.ParseNFCDetect(raw)
			if !parsed.Detected {
				return "no tag detected — place card on NFC antenna and retry", nil
			}
			if parsed.UID == "" {
				return fmt.Sprintf("detected %s but scanner returned no UID on this firmware — full capture needs nfc_dump_protocol (keys required for Classic)", parsed.Type), nil
			}
			dt := mapTypeToDeviceType(parsed.Type)
			nfcBytes, err := fileformat.BuildNFC(fileformat.NFCBuildParams{
				DeviceType: dt,
				UID:        parsed.UID,
				ATQA:       parsed.ATQA,
				SAK:        parsed.SAK,
			})
			if err != nil {
				// Fallback to typeless save so odd UIDs still persist.
				nfcBytes, err = fileformat.BuildNFC(fileformat.NFCBuildParams{
					DeviceType: "NFC",
					UID:        parsed.UID,
				})
				if err != nil {
					return "", err
				}
			}
			name := sanitize(parsed.UID)
			path := "/ext/nfc/usecase_" + name + ".nfc"
			if werr := f.WriteFileCtx(ctx, path, nfcBytes); werr != nil {
				return "", werr
			}
			return fmt.Sprintf("%s UID %s saved to %s (%d bytes)",
				dt, parsed.UID, path, len(nfcBytes)), nil
		},
	},

	// ----- RFID (passive — no transmit) -----
	{
		Category:     "rfid",
		Prompt:       "read this prox fob",
		Description:  "125 kHz LF read — HID Prox, EM4100, Indala, etc.",
		RequiresCard: true,
		Run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			out, err := f.RFIDRead(ctx, "", 4*time.Second)
			if err != nil {
				if strings.Contains(err.Error(), "card not") || strings.Contains(err.Error(), "no") {
					return "no LF fob detected — hold fob against the BACK of the Flipper (LF antenna side)", nil
				}
				return "", err
			}
			return firstInterestingLine(out), nil
		},
	},
	{
		Category:    "rfid",
		Prompt:      "capture a raw LF signal to a file",
		Description: "rfid raw_read ASK — writes a .lfrfid file for later analysis",
		Run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			testPath := "/ext/apps_data/flipper-usecases/raw.lfrfid"
			_, _ = f.StorageMkdir("/ext/apps_data/flipper-usecases")
			out, err := f.RFIDRawRead("ask", testPath, 2*time.Second)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("raw capture written to %s (%d bytes of transcript)",
				testPath, len(out)), nil
		},
	},

	// ----- SubGHz (passive, no target; frequency picks common ISM) -----
	{
		Category:    "subghz",
		Prompt:      "listen on 433 MHz for 3 seconds",
		Description: "subghz_receive on the universal garage-door band — passive",
		Run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			out, err := f.SubGHzRx(433920000, 3*time.Second)
			if err != nil {
				return "", err
			}
			parsed := flipper.ParseSubGHzReceive(out)
			if len(parsed.Candidates) == 0 {
				return "3s scan, no signals decoded (normal if nothing was transmitting)", nil
			}
			return fmt.Sprintf("%d candidate signals decoded in 3s", len(parsed.Candidates)), nil
		},
	},

	// ----- IR (passive) -----
	{
		Category:    "ir",
		Prompt:      "listen for IR for 2 seconds",
		Description: "ir_rx — point a TV / AC remote at the Flipper and press a button to test",
		Run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			out, err := f.IRRx(2 * time.Second)
			if err != nil {
				return "", err
			}
			if strings.TrimSpace(out) == "" {
				return "2s listen complete, no IR activity detected", nil
			}
			return firstInterestingLine(out), nil
		},
	},

	// ----- Bluetooth (self-report only; full scan needs Marauder) -----
	{
		Category:    "bt",
		Prompt:      "what does the Flipper's Bluetooth radio report?",
		Description: "bt_hci_info — reads stack version / manufacturer. Full BLE scan would need the Marauder devboard.",
		Run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			out, err := f.BTHCIInfo()
			if err != nil {
				return "", err
			}
			return firstInterestingLine(out), nil
		},
	},

	// ----- Loader / apps -----
	{
		Category:    "apps",
		Prompt:      "what apps are installed on my Flipper?",
		Description: "loader list_parsed — enumerates FAPs (NFC tools, spectrum analyzer, subghz playlist, etc.)",
		Run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			la, err := f.LoaderListParsed()
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("apps=%d, settings=%d", len(la.Apps), len(la.Settings)), nil
		},
	},

	// ----- Feedback (always runnable, brief UX touch) -----
	{
		Category:    "feedback",
		Prompt:      "flash the Flipper's blue LED briefly",
		Description: "led set — useful smoke test that the UX feedback layer works",
		Run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			if err := f.SetLED("b", 96); err != nil {
				return "", err
			}
			time.Sleep(150 * time.Millisecond)
			_ = f.SetLED("b", 0)
			return "LED pulsed blue for 150 ms", nil
		},
	},
	{
		Category:    "feedback",
		Prompt:      "make the Flipper vibrate once",
		Description: "vibro — confirms the device is responsive and the operator is in the right room",
		Run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			if _, err := f.Vibro(true); err != nil {
				return "", err
			}
			time.Sleep(100 * time.Millisecond)
			_, _ = f.Vibro(false)
			return "~100 ms vibrate pulse sent", nil
		},
	},

	// ----- Tasks we deliberately don't run (safety) -----
	{
		Category:    "skip",
		Prompt:      "run this BadUSB payload",
		Description: "badusb_run — skipped by design; would type keys into the host",
		Skip:        "destructive: keystrokes injected into the host PC are out of scope",
	},
	{
		Category:    "skip",
		Prompt:      "transmit on 433 MHz",
		Description: "subghz_transmit — skipped without a specific authorised target",
		Skip:        "destructive: unauthorised RF transmission can affect nearby systems",
	},
	{
		Category:    "skip",
		Prompt:      "reboot the Flipper",
		Description: "device_reboot — skipped; drops the WSL USB passthrough and forces a replug",
		Skip:        "would disconnect the serial port mid-run",
	},
}

// mapTypeToDeviceType mirrors the agent's handler. Keep this in sync
// with internal/agent/agent.go mapNFCTypeToDeviceType — the usecases
// runner lives outside the agent package and can't import it without
// pulling in half the agent's dependency graph just for one helper.
func mapTypeToDeviceType(typ string) string {
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
	default:
		return "NFC"
	}
}

func sanitize(s string) string {
	var b strings.Builder
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

// firstInterestingLine returns the first non-empty, non-prompt line of
// a Flipper CLI response — usually the one carrying the actual result.
// Keeps operator-facing summaries short without dropping the signal.
func firstInterestingLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == ">:" {
			continue
		}
		if len(line) > 120 {
			line = line[:120] + "…"
		}
		return line
	}
	return "(empty response)"
}

// countListEntries counts filename lines ending with the given suffix
// in a storage-list transcript. Robust across firmware forks that
// format the listing slightly differently.
func countListEntries(listing, suffix string) int {
	count := 0
	for _, line := range strings.Split(listing, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasSuffix(strings.ToLower(line), strings.ToLower(suffix)) {
			count++
		}
	}
	return count
}

// bytesToGB takes a byte-count string like "127831900160" and returns
// it as gigabytes. Unparseable values produce 0 — the report line is
// still useful when size is missing.
func bytesToGB(s string) float64 {
	var n float64
	_, _ = fmt.Sscanf(s, "%f", &n)
	return n / 1024 / 1024 / 1024
}

func main() {
	port := flag.String("port", "/dev/ttyACM0", "serial device path")
	baud := flag.Int("baud", 230400, "serial baud")
	categoryFilter := flag.String("category", "", "only run cases with this category (health, storage, nfc, rfid, subghz, ir, bt, apps, feedback)")
	flag.Parse()

	url := fmt.Sprintf("serial://%s?baud=%d", *port, *baud)
	fmt.Printf("connecting %s ...\n", url)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	flip, err := flipper.ConnectURL(ctx, url, 10*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: ConnectURL: %v\n", err)
		os.Exit(1)
	}
	defer flip.Close()

	if _, err := flip.DetectCapabilities(); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: DetectCapabilities: %v\n", err)
		os.Exit(1)
	}
	di, _ := flip.DeviceInfoMap()
	fmt.Printf("connected: fork=%q version=%q hw=%q\n\n",
		di["firmware_origin_fork"], di["firmware_version"], di["hardware_model"])

	var pass, skip, fail int
	var lastCategory string
	for _, uc := range cases {
		if *categoryFilter != "" && uc.Category != *categoryFilter {
			continue
		}
		if uc.Category != lastCategory {
			fmt.Printf("\n== %s ==\n", strings.ToUpper(uc.Category))
			lastCategory = uc.Category
		}

		if uc.Skip != "" {
			fmt.Printf("  %s \"%s\"  — SKIP (%s)\n", OutcomeSkip.marker(), uc.Prompt, uc.Skip)
			skip++
			continue
		}

		start := time.Now()
		callCtx, callCancel := context.WithTimeout(context.Background(), 30*time.Second)
		summary, runErr := uc.Run(callCtx, flip)
		callCancel()
		elapsed := time.Since(start).Round(time.Millisecond)

		outcome := OutcomePass
		if runErr != nil {
			outcome = OutcomeFail
			summary = "ERROR: " + runErr.Error()
			fail++
		} else {
			pass++
		}
		fmt.Printf("  %s \"%s\" [%s]\n      %s\n",
			outcome.marker(), uc.Prompt, elapsed, summary)
	}

	fmt.Printf("\n--- SUMMARY ---\n pass=%d skip=%d fail=%d total=%d\n",
		pass, skip, fail, pass+skip+fail)
	if fail > 0 {
		os.Exit(1)
	}
}
