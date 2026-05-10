package tools

import (
	"context"
	"encoding/json"
	"time"

	"github.com/xunholy/promptzero/internal/risk"
)

func init() {
	Register(Spec{
		Name:        "rfid_read",
		Description: "Read a 125kHz RFID tag/card (building access fobs, prox cards). Returns as soon as a tag is decoded; the timeout is just the max wait. Supports EM4100, HIDProx, Indala, AWID, FDX, and more. Hardware: hold the fob flat against the BACK of the Flipper (LF antenna side).",
		Schema:      json.RawMessage(`{"type":"object","properties":{"mode":{"type":"string","description":"Read mode: normal, indala, ask, psk (default: empty for auto-detect)"},"timeout_seconds":{"type":"number","description":"Max wait in seconds (default 15)"}}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupFlipperRFID,
		AgentOnly:   false,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.RFIDRead(
				ctx,
				str(p, "mode"),
				time.Duration(intOr(p, "timeout_seconds", 15))*time.Second,
			)
		},
	})

	Register(Spec{
		Name:        "rfid_emulate",
		Description: "Emulate an RFID tag by specifying protocol and data directly.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"protocol":{"type":"string","description":"RFID protocol: EM4100, HIDProx, Indala, AWID, FDX-A, FDX-B, etc."},"data":{"type":"string","description":"Hex data to emulate"},"duration_seconds":{"type":"number","description":"Emulation window (default 10)"}}}`),
		Required:    []string{"protocol", "data"},
		Risk:        risk.High,
		Group:       GroupFlipperRFID,
		AgentOnly:   false,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.RFIDEmulateCtx(
				ctx,
				str(p, "protocol"),
				str(p, "data"),
				time.Duration(intOr(p, "duration_seconds", 10))*time.Second,
			)
		},
	})

	Register(Spec{
		Name: "rfid_write",
		Description: "Write data to a writable RFID tag (e.g. T5577). Clones data onto a blank tag.\n\nExamples:\n" +
			`- {"protocol":"EM4100","data":"1A2B3C4D5E"}  — clone a captured 40-bit EM4100 fob onto a T5577 blank`,
		Schema:    json.RawMessage(`{"type":"object","properties":{"protocol":{"type":"string","description":"RFID protocol: EM4100, HIDProx, Indala, AWID, FDX-A, FDX-B, etc."},"data":{"type":"string","description":"Hex data to write"}}}`),
		Required:  []string{"protocol", "data"},
		Risk:      risk.High,
		Group:     GroupFlipperRFID,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.RFIDWrite(str(p, "protocol"), str(p, "data"))
		},
	})

	Register(Spec{
		Name:        "rfid_raw_read",
		Description: "Perform a raw 125 kHz LF capture to a file for later analysis. Unlike rfid_read, the result is the unprocessed bitstream — use when you need to reverse-engineer a non-standard protocol. Hardware: hold the fob flat against the BACK of the Flipper.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"mode":{"type":"string","description":"Modulation: 'ask' or 'psk' (default: empty for auto)"},"file":{"type":"string","description":"Destination file path, e.g. /ext/lfrfid/raw_01.raw"},"duration_seconds":{"type":"number","description":"Capture duration (default 30)"}}}`),
		Required:    []string{"file"},
		Risk:        risk.Medium,
		Group:       GroupFlipperRFID,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.RFIDRawRead(
				str(p, "mode"),
				str(p, "file"),
				time.Duration(intOr(p, "duration_seconds", 30))*time.Second,
			)
		},
	})

	Register(Spec{
		Name:        "rfid_raw_analyze",
		Description: "Analyse a previously captured raw LF file and attempt to decode the protocol. Read-only; runs entirely on the device.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"file":{"type":"string","description":"Path to the raw LF capture to analyse"}}}`),
		Required:    []string{"file"},
		Risk:        risk.Low,
		Group:       GroupFlipperRFID,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.RFIDRawAnalyze(str(p, "file"))
		},
	})

	Register(Spec{
		Name:        "rfid_raw_emulate",
		Description: "Replay a raw LF capture against a reader. Active transmission — use only with authorisation from the reader's operator. Hardware: hold the BACK of the Flipper against the reader coil.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"file":{"type":"string","description":"Path to the raw LF capture to replay"},"duration_seconds":{"type":"number","description":"How long to emulate (default 30)"}}}`),
		Required:    []string{"file"},
		Risk:        risk.High,
		Group:       GroupFlipperRFID,
		AgentOnly:   false,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.RFIDRawEmulateCtx(
				ctx,
				str(p, "file"),
				time.Duration(intOr(p, "duration_seconds", 30))*time.Second,
			)
		},
	})

	Register(Spec{
		Name:        "loader_t5577_multiwriter",
		Description: "Launch the T5577 Multiwriter FAP — batch-writes T5577 blanks with a list of protocol/data combinations. Requires the FAP to be installed.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.High,
		Group:       GroupFlipperRFID,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.LoaderT5577MultiWriter()
		},
	})
}
