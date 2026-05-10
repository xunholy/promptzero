package tools

import (
	"context"
	"encoding/json"
	"time"

	"github.com/xunholy/promptzero/internal/risk"
)

func init() {
	Register(Spec{
		Name:        "gpio_set",
		Description: "Set a GPIO pin high (1) or low (0). Control external hardware, relays, LEDs, motors.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"pin":{"type":"string","description":"GPIO pin name: PA7, PA6, PA4, PB3, PB2, PC3, PC1, PC0"},"value":{"type":"integer","description":"0 for low, 1 for high"}}}`),
		Required:    []string{"pin", "value"},
		Risk:        risk.High,
		Group:       GroupFlipperHW,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.GPIOSet(str(p, "pin"), intOr(p, "value", 0))
		},
	})

	Register(Spec{
		Name:        "gpio_read",
		Description: "Read the current state of a GPIO pin. Returns high/low and voltage level.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"pin":{"type":"string","description":"GPIO pin name: PA7, PA6, PA4, PB3, PB2, PC3, PC1, PC0"}}}`),
		Required:    []string{"pin"},
		Risk:        risk.Low,
		Group:       GroupFlipperHW,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.GPIORead(str(p, "pin"))
		},
	})

	Register(Spec{
		Name:        "onewire_search",
		Description: "Enumerate devices on the 1-Wire bus and return their ROM codes. Use to discover keys/sensors before iButton read/emulate. Hardware: touch the iButton contact pad on the top-left corner of the Flipper.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"How long to scan (default 10)"}}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupFlipperHW,
		AgentOnly:   false,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.OneWireSearchCtx(ctx, time.Duration(intOr(p, "duration_seconds", 10))*time.Second)
		},
	})

	Register(Spec{
		Name:        "i2c_scan",
		Description: "Scan the I²C bus for connected devices and return their addresses. Use for hardware recon when probing a GPIO-attached sensor/chip. Hardware: wire SCL/SDA to the Flipper's GPIO header pins (PC0=SCL, PC1=SDA) with pull-ups.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupFlipperHW,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.I2CScan()
		},
	})

	Register(Spec{
		Name:        "input_send",
		Description: "Send a synthetic button input event to the Flipper UI.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"button":{"type":"string","description":"Button: up, down, left, right, ok, back"},"event_type":{"type":"string","description":"Event type: press, release, short, long, repeat"}}}`),
		Required:    []string{"button", "event_type"},
		Risk:        risk.Medium,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.InputSend(str(p, "button"), str(p, "event_type"))
		},
	})

	Register(Spec{
		Name:        "bt_hci_info",
		Description: "Return local Bluetooth controller info: chip, firmware version, MAC. Read-only and does not bring up a BLE stack — this is purely device metadata.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.BTHCIInfo()
		},
	})
}
