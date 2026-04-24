package tools

import (
	"context"
	"encoding/json"
	"time"

	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() {
	Register(Spec{
		Name:        "nfc_detect",
		Description: "Detect an NFC tag/card and return UID/ATQA/SAK/Type. Use this when the operator asks what a tag IS. When the operator asks to SCAN / SAVE / CLONE a tag, prefer nfc_read_save — it detects and writes a .nfc file in one call.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"timeout_seconds":{"type":"number","description":"How long to wait for a tag in seconds (default 30)"}}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupFlipperNFC,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			timeoutSeconds := 30
			if v, ok := p["timeout_seconds"]; ok {
				switch n := v.(type) {
				case float64:
					timeoutSeconds = int(n)
				case int:
					timeoutSeconds = n
				}
			}
			raw, err := d.Flipper.NFCDetect(time.Duration(timeoutSeconds) * time.Second)
			if err != nil {
				return raw, err
			}
			parsed := flipper.ParseNFCDetect(raw)
			b, _ := json.Marshal(parsed)
			return string(b), nil
		},
	})

	Register(Spec{
		Name: "nfc_emulate",
		Description: "Emulate a saved NFC tag/card. The Flipper becomes the tag — hold it against a reader.\n\nExamples:\n" +
			`- {"file":"/ext/nfc/badge.nfc"}  — replay a previously captured MIFARE access badge`,
		Schema:    json.RawMessage(`{"type":"object","properties":{"file":{"type":"string","description":"Path to .nfc file on Flipper SD card"}}}`),
		Required:  []string{"file"},
		Risk:      risk.High,
		Group:     GroupFlipperNFC,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.NFCEmulate(str(p, "file"))
		},
	})

	Register(Spec{
		Name:        "nfc_subcommand",
		Description: "Run an arbitrary NFC subshell subcommand. Valid subcommands: scanner, emulate, dump, field, raw, apdu, mfu. Fork-gated: requires the nfc CLI subshell (stock/Unleashed/RogueMaster). Not available on Xtreme.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"subcommand":{"type":"string","description":"Subcommand (scanner/emulate/dump/field/raw/apdu/mfu)"},"timeout_seconds":{"type":"number","description":"Wait time (default 30)"}}}`),
		Required:    []string{"subcommand"},
		Risk:        risk.Medium,
		Group:       GroupFlipperNFC,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.NFCSubcommand(
				str(p, "subcommand"),
				time.Duration(intOr(p, "timeout_seconds", 30))*time.Second,
			)
		},
	})

	Register(Spec{
		Name:        "nfc_raw_frame",
		Description: "Send a raw ISO14443 frame to a field-held NFC tag and return its response. Fork-gated: requires the nfc CLI subshell. Hardware: keep the tag against the back of the Flipper.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"hex":{"type":"string","description":"Raw frame bytes as hex, e.g. '30 04' to read block 4"},"timeout_seconds":{"type":"number","description":"Wait time (default 10)"}}}`),
		Required:    []string{"hex"},
		Risk:        risk.High,
		Group:       GroupFlipperNFC,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.NFCRawFrame(
				str(p, "hex"),
				time.Duration(intOr(p, "timeout_seconds", 10))*time.Second,
			)
		},
	})

	Register(Spec{
		Name:        "nfc_apdu",
		Description: "Send an ISO7816 APDU command to a contactless smart card (EMV, DESFire, applet-hosting cards). Fork-gated on the nfc CLI subshell. Hardware: hold the card against the back of the Flipper.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"hex":{"type":"string","description":"APDU as hex, e.g. '00A404000E325041592E5359532E4444463031' (SELECT PPSE)"},"timeout_seconds":{"type":"number","description":"Wait time (default 10)"}}}`),
		Required:    []string{"hex"},
		Risk:        risk.High,
		Group:       GroupFlipperNFC,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.NFCAPDU(
				str(p, "hex"),
				time.Duration(intOr(p, "timeout_seconds", 10))*time.Second,
			)
		},
	})

	Register(Spec{
		Name:        "nfc_mfu_rdbl",
		Description: "Read a single page (4 bytes) from a MIFARE Ultralight / NTAG tag via the nfc subshell. Fork-gated.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"page":{"type":"integer","description":"Page number to read (0-based)"},"timeout_seconds":{"type":"number","description":"Wait time (default 10)"}}}`),
		Required:    []string{"page"},
		Risk:        risk.Medium,
		Group:       GroupFlipperNFC,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.NFCMFURead(
				intOr(p, "page", 0),
				time.Duration(intOr(p, "timeout_seconds", 10))*time.Second,
			)
		},
	})

	Register(Spec{
		Name:        "nfc_mfu_wrbl",
		Description: "Write 4 bytes of hex data to a MIFARE Ultralight / NTAG page. Destructive — the previous contents of the page are overwritten. Some pages (OTP, lock bytes) are one-way. Fork-gated.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"page":{"type":"integer","description":"Page number to write"},"hex":{"type":"string","description":"Exactly 4 bytes as hex, e.g. 'DEADBEEF'"},"timeout_seconds":{"type":"number","description":"Wait time (default 10)"}}}`),
		Required:    []string{"page", "hex"},
		Risk:        risk.High,
		Group:       GroupFlipperNFC,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.NFCMFUWrite(
				intOr(p, "page", 0),
				str(p, "hex"),
				time.Duration(intOr(p, "timeout_seconds", 10))*time.Second,
			)
		},
	})

	// nfc_dump_protocol: translation (mfc/mfu/mfp/felica) is inside
	// flipper.NFCDumpProtocol — do NOT add translation here (§F.3).
	Register(Spec{
		Name:        "nfc_dump_protocol",
		Description: "Dump all readable contents of a protocol-matched NFC tag. Pass an empty string to skip the protocol filter — on Momentum that auto-detects + dumps + writes the .nfc file in one step. The wrapper translates canonical protocol names to firmware-specific tokens.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"protocol":{"type":"string","description":"Canonical protocol name: Mifare_Classic, Mifare_Ultralight, Mifare_Plus, FeliCa. Pass empty string for auto-detect."},"timeout_seconds":{"type":"number","description":"Wait time (default 30)"}}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupFlipperNFC,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.NFCDumpProtocol(
				str(p, "protocol"),
				time.Duration(intOr(p, "timeout_seconds", 30))*time.Second,
			)
		},
	})
}
