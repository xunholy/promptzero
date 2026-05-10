package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/streaming"
)

func init() {
	Register(Spec{
		Name:        "device_info",
		Aliases:     []string{"system_info"}, // agent-side legacy synonym (§F.4)
		Description: "Get Flipper Zero device information: firmware version, hardware revision, uptime, etc.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.DeviceInfo()
		},
	})

	Register(Spec{
		Name:        "power_info",
		Description: "Get battery and power information: charge level, voltage, charging status.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.PowerInfo()
		},
	})

	Register(Spec{
		Name:        "device_reboot",
		Description: "Reboot the Flipper Zero.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Critical,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.Reboot()
		},
	})

	Register(Spec{
		Name:        "flipper_raw_cli",
		Description: "Escape hatch: send an arbitrary command directly to the Flipper CLI. Use only when no dedicated tool exists for what you need. Critical — unrestricted passthrough.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"command":{"type":"string","description":"CLI command string"}}}`),
		Required:    []string{"command"},
		Risk:        risk.Critical,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.RawCLI(str(p, "command"))
		},
	})

	Register(Spec{
		Name:        "led_set",
		Description: "Set a single Flipper LED channel to a brightness value. Channels: r (red), g (green), b (blue), bl (backlight).",
		Schema:      json.RawMessage(`{"type":"object","properties":{"channel":{"type":"string","description":"LED channel: r, g, b, bl"},"value":{"type":"integer","description":"Brightness 0-255"}}}`),
		Required:    []string{"channel", "value"},
		Risk:        risk.Low,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.LED(str(p, "channel"), intOr(p, "value", 0))
		},
	})

	Register(Spec{
		Name:        "vibro",
		Description: "Trigger the Flipper vibration motor.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"on":{"type":"boolean","description":"true to vibrate, false to stop"}}}`),
		Required:    []string{"on"},
		Risk:        risk.Low,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.Vibro(boolOr(p, "on", false))
		},
	})

	Register(Spec{
		Name:        "list_devices",
		Description: "List all named devices from the user's configuration. These are friendly names mapped to signal files (e.g. 'garage' -> /ext/subghz/garage.sub). Use this to discover what the user has set up before trying to control devices by name.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupMetaUtil,
		AgentOnly:   true,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			if d.Config == nil || len(d.Config.Devices) == 0 {
				return "No devices configured. Add devices to config.yaml.", nil
			}
			var out string
			for name, dev := range d.Config.Devices {
				out += fmt.Sprintf("- %s (type: %s, file: %s)\n", name, dev.Type, dev.File)
				for cmd, signal := range dev.Commands {
					out += fmt.Sprintf("    command: %s -> %s\n", cmd, signal)
				}
			}
			return out, nil
		},
	})

	Register(Spec{
		Name:        "log_stream",
		Description: "Capture the live Flipper debug log for the supplied duration. Read-only; useful when the user reports 'app X is misbehaving' and you need the firmware's own log output.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Stream duration (default 15)"},"level":{"type":"string","description":"Minimum severity: default|error|warn|info|debug|trace"}}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		// Streaming opt-in mirrors subghz_receive: each log line
		// emitted by firmware lands at the host's stream callback as
		// a frame. Hosts without a callback (or with Streams=false
		// dispatch) fall back to the blocking Handler unchanged.
		Streams: true,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.LogStreamCtx(ctx, time.Duration(intOr(p, "duration_seconds", 15))*time.Second, str(p, "level"))
		},
		StreamHandler: func(ctx context.Context, d *Deps, p map[string]any, sink *streaming.Sink) (string, error) {
			defer sink.Close()
			duration := time.Duration(intOr(p, "duration_seconds", 15)) * time.Second
			return d.Flipper.LogStreamLines(ctx, duration, str(p, "level"), func(line string) (stop bool) {
				sink.Send([]byte(line))
				return sink.IsAborted()
			})
		},
	})

	Register(Spec{
		Name:        "power_reboot_dfu",
		Description: "Reboot the Flipper into STM32 DFU mode. CRITICAL: after this the Flipper has no running firmware — recovery requires a host reflash or a physical power-cycle. Only call when the user explicitly wants to reflash.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Critical,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.PowerRebootDFU()
		},
	})

	Register(Spec{
		Name:        "update_install",
		Description: "Install a firmware update from a manifest already staged on the SD card. CRITICAL: reflashes the device; a bad manifest can brick it.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"manifest":{"type":"string","description":"Path to update.fuf manifest"}}}`),
		Required:    []string{"manifest"},
		Risk:        risk.Critical,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.UpdateInstall(str(p, "manifest"))
		},
	})

	Register(Spec{
		Name:        "crypto_store_key",
		Description: "Store a key in one of the Flipper's secure-storage slots (e.g. for BadUSB string encryption). Overwrites whatever is in the slot — verify with the user before calling.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"slot":{"type":"integer","description":"Slot number"},"key_type":{"type":"string","description":"Key type: master, simple, or encrypted"},"key_size":{"type":"integer","description":"Key size in bits: 128 or 256"},"hex":{"type":"string","description":"Key bytes as hex (key_size/8 bytes)"}}}`),
		Required:    []string{"slot", "key_type", "key_size", "hex"},
		Risk:        risk.High,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.CryptoStoreKey(intOr(p, "slot", 0), str(p, "key_type"), intOr(p, "key_size", 128), str(p, "hex"))
		},
	})
}
