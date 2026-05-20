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
		Name: "subghz_transmit",
		Description: "Transmit a saved Sub-GHz signal file (.sub). Use for garage doors, remotes, gate openers, car keys, weather stations, or any device operating on Sub-GHz frequencies.\n\nExamples:\n" +
			`- {"file":"/ext/subghz/garage.sub"}  — replay a saved garage-door capture` + "\n" +
			`- {"file":"/ext/subghz/car_fob.sub"}  — re-transmit a rolling-code car key capture`,
		Schema:    json.RawMessage(`{"type":"object","properties":{"file":{"type":"string","description":"Path to .sub file on Flipper SD card, e.g. /ext/subghz/garage.sub"}}}`),
		Required:  []string{"file"},
		Risk:      risk.High,
		Group:     GroupFlipperSubGHz,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.SubGHzTx(str(p, "file"))
		},
	})

	Register(Spec{
		Name: "subghz_receive",
		Description: "Capture Sub-GHz signals on a frequency. Records signals from nearby transmitters and returns structured JSON: {candidates:[{protocol,frequency,key,bit,te}]}.\n\nExamples:\n" +
			`- {"frequency":433920000,"duration_seconds":15}  — common garage-door band, 15 s sweep` + "\n" +
			`- {"frequency":315000000,"duration_seconds":30}  — common car-key band, longer sweep`,
		Schema:    json.RawMessage(`{"type":"object","properties":{"frequency":{"type":"number","description":"Frequency in Hz, e.g. 433920000 for 433.92MHz"},"duration_seconds":{"type":"number","description":"How long to listen (default 30)"}}}`),
		Required:  []string{"frequency"},
		Risk:      risk.Medium,
		Group:     GroupFlipperSubGHz,
		AgentOnly: false,
		// Streaming opt-in: hosts that wire SetToolStreamCallback get
		// per-line frames (one Send per firmware-emitted scan line) AND
		// abort-early — returning false from the host callback fires
		// sink.Abort() + ctx cancel, the StreamHandler observes via
		// IsAborted() / ctx.Done() inside StreamCtx and stops the
		// capture cleanly. Hosts without a callback fall back to the
		// non-streaming Handler below — semantics unchanged.
		Streams: true,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			raw, err := d.Flipper.SubGHzRxCtx(
				ctx,
				safeUint32(intOr(p, "frequency", 0)),
				time.Duration(intOr(p, "duration_seconds", 30))*time.Second,
			)
			if err != nil {
				return raw, err
			}
			// Structured parse (§F.6): model sees {candidates:[...]} instead
			// of raw scan transcript.
			parsed := flipper.ParseSubGHzReceive(raw)
			b, _ := json.Marshal(parsed)
			return string(b), nil
		},
		StreamHandler: func(ctx context.Context, d *Deps, p map[string]any, sink *streaming.Sink) (string, error) {
			defer sink.Close()
			freq := safeUint32(intOr(p, "frequency", 0))
			duration := time.Duration(intOr(p, "duration_seconds", 30)) * time.Second
			raw, err := d.Flipper.SubGHzRxStream(ctx, freq, duration, func(line string) (stop bool) {
				sink.Send([]byte(line))
				// IsAborted() honours consumer-driven abort (host
				// callback returned false). ctx is also cancelled on
				// abort so StreamCtx will return promptly even if the
				// firmware never emits another line for IsAborted to
				// be polled against.
				return sink.IsAborted()
			})
			if err != nil {
				return raw, err
			}
			parsed := flipper.ParseSubGHzReceive(raw)
			b, _ := json.Marshal(parsed)
			return string(b), nil
		},
	})

	Register(Spec{
		Name:        "subghz_decode",
		Description: "Decode and analyze a captured Sub-GHz signal file. Shows protocol, frequency, key data.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"file":{"type":"string","description":"Path to .sub file to decode"}}}`),
		Required:    []string{"file"},
		Risk:        risk.Medium,
		Group:       GroupFlipperSubGHz,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.SubGHzDecode(str(p, "file"))
		},
	})

	// subghz_bruteforce is AgentOnly — uses ExecLong passthrough (§A.4).
	Register(Spec{
		Name:        "subghz_bruteforce",
		Description: "Brute force a Sub-GHz signal by replaying with variations. No limits on attempts or frequency.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"file":{"type":"string","description":"Path to .sub file to use as base"},"frequency":{"type":"integer","description":"Target frequency in Hz"},"duration_seconds":{"type":"integer","description":"How long to run (default 60)"}}}`),
		Required:    []string{"file", "frequency"},
		Risk:        risk.Critical,
		Group:       GroupFlipperSubGHz,
		AgentOnly:   true,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.ExecLong(
				fmt.Sprintf("subghz bruteforce %s %d",
					flipper.SanitizeArg(str(p, "file")),
					intOr(p, "frequency", 0),
				),
				time.Duration(intOr(p, "duration_seconds", 60))*time.Second,
			)
		},
	})

	Register(Spec{
		Name:        "subghz_tx_key",
		Description: "Transmit a raw Sub-GHz key on a specific frequency without needing a saved .sub file. Use for replay attacks, custom codes, and protocol experimentation.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"key_hex":{"type":"string","description":"Key bytes as hex, e.g. 'F00F00AA'"},"frequency":{"type":"integer","description":"Frequency in Hz, e.g. 433920000"},"te":{"type":"integer","description":"Timing base in microseconds (protocol-dependent, e.g. 400 for common OOK remotes)"},"repeat":{"type":"integer","description":"Repeat count, typically 3-10"}}}`),
		Required:    []string{"key_hex", "frequency", "te", "repeat"},
		Risk:        risk.High,
		Group:       GroupFlipperSubGHz,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.SubGHzTxKey(
				str(p, "key_hex"),
				safeUint32(intOr(p, "frequency", 0)),
				safeUint32(intOr(p, "te", 0)),
				intOr(p, "repeat", 0),
			)
		},
	})

	Register(Spec{
		Name:        "subghz_rx_raw",
		Description: "Stream raw Sub-GHz pulse data (Momentum firmware only). Returns captured pulses; use storage_write to save as a .sub file if persistence is needed.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"frequency":{"type":"number","description":"Frequency in Hz (defaults to firmware last-used)"},"duration_seconds":{"type":"number","description":"Capture duration (default 30)"}}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupFlipperSubGHz,
		AgentOnly:   false,
		// Streaming opt-in mirrors subghz_receive / log_stream: each
		// pulse line emitted by firmware lands at the host's stream
		// callback as a frame in real time. Hosts without a callback
		// fall back to the blocking SubGHzRxRaw Handler unchanged.
		Streams: true,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.SubGHzRxRawCtx(
				ctx,
				safeUint32(intOr(p, "frequency", 0)),
				time.Duration(intOr(p, "duration_seconds", 30))*time.Second,
			)
		},
		StreamHandler: func(ctx context.Context, d *Deps, p map[string]any, sink *streaming.Sink) (string, error) {
			defer sink.Close()
			freq := safeUint32(intOr(p, "frequency", 0))
			duration := time.Duration(intOr(p, "duration_seconds", 30)) * time.Second
			return d.Flipper.SubGHzRxRawStream(ctx, freq, duration, func(line string) (stop bool) {
				sink.Send([]byte(line))
				return sink.IsAborted()
			})
		},
	})

	Register(Spec{
		Name:        "subghz_chat",
		Description: "Join an interactive Sub-GHz text chat on the given frequency — the Flipper transmits on every keystroke until the duration elapses.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"frequency":{"type":"number","description":"Frequency in Hz, e.g. 433920000"},"duration_seconds":{"type":"number","description":"How long to stay in the chat (default 60)"}}}`),
		Required:    []string{"frequency"},
		Risk:        risk.High,
		Group:       GroupFlipperSubGHz,
		AgentOnly:   false,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.SubGHzChatCtx(
				ctx,
				safeUint32(intOr(p, "frequency", 0)),
				time.Duration(intOr(p, "duration_seconds", 60))*time.Second,
			)
		},
	})
}
