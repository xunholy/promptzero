package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/streaming"
)

func init() {
	Register(Spec{
		Name:        "ir_transmit",
		Description: "Send a decoded infrared command using protocol, address, and command values. Use for TVs, ACs, projectors, sound systems, or any IR-controlled device.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"protocol":{"type":"string","description":"IR protocol name, e.g. NEC, Samsung32, RC6, SIRC"},"address":{"type":"string","description":"Address hex value, e.g. 00 00 00 00"},"command":{"type":"string","description":"Command hex value, e.g. 70 00 00 00"}}}`),
		Required:    []string{"protocol", "address", "command"},
		Risk:        risk.High,
		Group:       GroupFlipperIR,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.IRTxParsed(str(p, "protocol"), str(p, "address"), str(p, "command"))
		},
	})

	Register(Spec{
		Name:        "ir_transmit_raw",
		Description: "Send a raw infrared signal with explicit frequency, duty cycle, and timing data.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"frequency":{"type":"integer","description":"Carrier frequency in Hz (default 38000)"},"duty_cycle":{"type":"number","description":"Duty cycle 0.0-1.0 (default 0.33)"},"data":{"type":"string","description":"Space-separated timing values in microseconds"}}}`),
		Required:    []string{"data"},
		Risk:        risk.Medium,
		Group:       GroupFlipperIR,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.IRTxRaw(
				safeUint32(intOr(p, "frequency", 38000)),
				floatOr(p, "duty_cycle", 0.33),
				str(p, "data"),
			)
		},
	})

	Register(Spec{
		Name:        "ir_receive",
		Description: "Capture/learn an infrared signal from a remote control. Point the remote at the Flipper and press a button.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"timeout_seconds":{"type":"number","description":"How long to wait for a signal (default 30)"}}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupFlipperIR,
		AgentOnly:   false,
		// Streaming opt-in: each decoded IR line lands at the host's
		// stream callback as a frame. Particularly useful for the
		// "press a button" UX — the agent can see the signal arrive
		// the moment the operator's remote is captured, rather than
		// waiting for the full timeout.
		Streams: true,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.IRRxCtx(ctx, time.Duration(intOr(p, "timeout_seconds", 30))*time.Second)
		},
		StreamHandler: func(ctx context.Context, d *Deps, p map[string]any, sink *streaming.Sink) (string, error) {
			defer sink.Close()
			timeout := time.Duration(intOr(p, "timeout_seconds", 30)) * time.Second
			return d.Flipper.IRRxStream(ctx, timeout, func(line string) (stop bool) {
				sink.Send([]byte(line))
				return sink.IsAborted()
			})
		},
	})

	// ir_bruteforce is AgentOnly — uses ExecLong passthrough (§A.4).
	Register(Spec{
		Name:        "ir_bruteforce",
		Description: "Brute force IR codes against a device. Cycles through known protocols to find working commands.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"file":{"type":"string","description":"Path to .ir brute force database file"},"duration_seconds":{"type":"integer","description":"How long to run (default 60)"}}}`),
		Required:    []string{"file"},
		Risk:        risk.Critical,
		Group:       GroupFlipperIR,
		AgentOnly:   true,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.ExecLong(
				fmt.Sprintf("ir bruteforce %s", flipper.SanitizeArg(str(p, "file"))),
				time.Duration(intOr(p, "duration_seconds", 60))*time.Second,
			)
		},
	})

	Register(Spec{
		Name:        "ir_decode_file",
		Description: "Decode a saved .ir file and return the parsed remote entries (protocol, address, command per button). Read-only.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","description":"Path to the .ir file, e.g. /ext/infrared/tv.ir"}}}`),
		Required:    []string{"path"},
		Risk:        risk.Low,
		Group:       GroupFlipperIR,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.IRDecodeFile(str(p, "path"))
		},
	})

	Register(Spec{
		Name:        "ir_universal_list",
		Description: "List the button entries inside a universal-remote library file (TVs, ACs, audio, projectors). Read-only.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"library":{"type":"string","description":"Universal library name, e.g. tv, ac, audio, projector"}}}`),
		Required:    []string{"library"},
		Risk:        risk.Low,
		Group:       GroupFlipperIR,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.IRUniversalList(str(p, "library"))
		},
	})
}
