// buspirate.go — Bus Pirate 5 universal-bus probe Specs.
//
// Wraps the internal/buspirate Client. Bus Pirate 5 (RP2040, PIO-driven
// I2C/SPI/UART/1-Wire) is a sibling backend to the Flipper's bit-banged
// GPIO; both can drive bus probes but the Bus Pirate is faster and
// supports voltages up to 5V on its IO header.
//
// Reference: https://github.com/DangerousPrototypes/BusPirate5-firmware

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/risk"
)

// RequireBusPirate returns a friendly error when the optional Bus Pirate 5
// universal-bus probe is not connected. BusPirate handlers call this
// before invoking any d.BusPirate method, mirroring [Deps.RequireMarauder].
func (d *Deps) RequireBusPirate() error {
	if d == nil || d.BusPirate == nil {
		return fmt.Errorf("bus pirate 5 not connected — set buspirate.port in config or pass --buspirate")
	}
	return nil
}

func init() { //nolint:gochecknoinits
	Register(buspirateModeSpec)
	Register(buspirateI2CScanSpec)
	Register(buspirateSPIDumpSpec)
	Register(buspirateUARTBridgeSpec)
	Register(buspirateVoltagesSpec)
	Register(buspiratePinSetSpec)
	Register(buspiratePinReadSpec)
}

// --- buspirate_mode ----------------------------------------------------

var buspirateModeSpec = Spec{
	Name:        "buspirate_mode",
	Description: "Switch the Bus Pirate 5 to a specific bus mode. Valid modes: HiZ (idle / safe), I2C, SPI, UART, 1Wire. Required before mode-specific Specs (e.g. switch to I2C before buspirate_i2c_scan).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"name":{"type":"string","description":"One of HiZ, I2C, SPI, UART, 1Wire (case-insensitive)"}
		},
		"required":["name"]
	}`),
	Required:  []string{"name"},
	Risk:      risk.Low,
	Group:     GroupFlipperHW,
	AgentOnly: false,
	Handler: func(ctx context.Context, d *Deps, args map[string]any) (string, error) {
		// Validate args BEFORE the transport check (v0.176). Otherwise a
		// missing/empty name masquerades as "not connected", masking the
		// real defect — same pattern as the canbus v0.174/v0.175 fixes.
		name := str(args, "name")
		if name == "" {
			return "", fmt.Errorf("buspirate_mode: name is required")
		}
		if err := d.RequireBusPirate(); err != nil {
			return "", err
		}
		if err := d.BusPirate.Mode(ctx, name); err != nil {
			return "", fmt.Errorf("buspirate_mode: %w", err)
		}
		body, _ := json.Marshal(map[string]any{"status": "ok", "mode": name})
		return string(body), nil
	},
}

// --- buspirate_i2c_scan ------------------------------------------------

var buspirateI2CScanSpec = Spec{
	Name:        "buspirate_i2c_scan",
	Description: "Scan the I2C bus for responding devices. Mode must be I2C (call buspirate_mode first). Returns the 7-bit addresses that ACK'd. Up to 500 kHz on Bus Pirate 5 PIO.",
	Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
	Required:    nil,
	Risk:        risk.Medium,
	Group:       GroupFlipperHW,
	AgentOnly:   false,
	Handler: func(ctx context.Context, d *Deps, _ map[string]any) (string, error) {
		if err := d.RequireBusPirate(); err != nil {
			return "", err
		}
		addrs, err := d.BusPirate.I2CScan(ctx)
		if err != nil {
			return "", fmt.Errorf("buspirate_i2c_scan: %w", err)
		}
		out := make([]string, len(addrs))
		for i, a := range addrs {
			out[i] = fmt.Sprintf("0x%02X", a)
		}
		body, _ := json.Marshal(map[string]any{
			"addresses_found": len(addrs),
			"addresses":       out,
		})
		return string(body), nil
	},
}

// --- buspirate_spi_dump ------------------------------------------------

var buspirateSPIDumpSpec = Spec{
	Name:        "buspirate_spi_dump",
	Description: "Read N bytes from the SPI bus. Mode must be SPI (call buspirate_mode first). Returns hex-encoded payload. For SPI flash dumps, set up your CS/clock manually before this Spec — Bus Pirate 5 leaves chip-select control to the operator.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"n":{"type":"integer","description":"Number of bytes to read"}
		},
		"required":["n"]
	}`),
	Required:  []string{"n"},
	Risk:      risk.Medium,
	Group:     GroupFlipperHW,
	AgentOnly: false,
	Handler: func(ctx context.Context, d *Deps, args map[string]any) (string, error) {
		// Validate before transport (v0.176).
		n := intOr(args, "n", 0)
		if n <= 0 {
			return "", fmt.Errorf("buspirate_spi_dump: n must be > 0")
		}
		if err := d.RequireBusPirate(); err != nil {
			return "", err
		}
		data, err := d.BusPirate.SPIDump(ctx, n)
		if err != nil {
			return "", fmt.Errorf("buspirate_spi_dump: %w", err)
		}
		body, _ := json.Marshal(map[string]any{
			"bytes_read": len(data),
			"data_hex":   hex.EncodeToString(data),
		})
		return string(body), nil
	},
}

// --- buspirate_uart_bridge ---------------------------------------------

var buspirateUARTBridgeSpec = Spec{
	Name:        "buspirate_uart_bridge",
	Description: "Send bytes over UART (mode must be UART) and capture whatever the target echoes back within the read window. Useful for poking at debug consoles on a captured device.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"send_hex":{"type":"string","description":"Hex-encoded bytes to send (e.g. 'AABBCC')"}
		},
		"required":["send_hex"]
	}`),
	Required:  []string{"send_hex"},
	Risk:      risk.Medium,
	Group:     GroupFlipperHW,
	AgentOnly: false,
	Handler: func(ctx context.Context, d *Deps, args map[string]any) (string, error) {
		// Validate before transport (v0.176).
		raw, err := hex.DecodeString(str(args, "send_hex"))
		if err != nil {
			return "", fmt.Errorf("buspirate_uart_bridge: send_hex: %w", err)
		}
		if err := d.RequireBusPirate(); err != nil {
			return "", err
		}
		resp, err := d.BusPirate.UARTBridge(ctx, raw)
		if err != nil {
			return "", fmt.Errorf("buspirate_uart_bridge: %w", err)
		}
		body, _ := json.Marshal(map[string]any{
			"sent_bytes":     len(raw),
			"received_bytes": len(resp),
			"received_hex":   hex.EncodeToString(resp),
		})
		return string(body), nil
	},
}

// --- buspirate_voltages ------------------------------------------------

var buspirateVoltagesSpec = Spec{
	Name:        "buspirate_voltages",
	Description: "Read the voltage on every Bus Pirate 5 IO pin (8 channels). Read-only.",
	Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
	Required:    nil,
	Risk:        risk.Low,
	Group:       GroupFlipperHW,
	AgentOnly:   false,
	Handler: func(ctx context.Context, d *Deps, _ map[string]any) (string, error) {
		if err := d.RequireBusPirate(); err != nil {
			return "", err
		}
		v, err := d.BusPirate.MeasureVoltages(ctx)
		if err != nil {
			return "", fmt.Errorf("buspirate_voltages: %w", err)
		}
		body, _ := json.Marshal(map[string]any{"voltages": v})
		return string(body), nil
	},
}

// --- buspirate_pin_set -------------------------------------------------

var buspiratePinSetSpec = Spec{
	Name:        "buspirate_pin_set",
	Description: "Set a Bus Pirate 5 IO pin's output. value can be a logic level (0/1) or an analog voltage (e.g. 1.5). High-risk because mis-driving an IO pin can damage the target circuit.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"pin":{"type":"integer","description":"IO pin number, 1-8"},
			"value":{"description":"0/1 for logic, or float for analog volts"}
		},
		"required":["pin","value"]
	}`),
	Required:  []string{"pin", "value"},
	Risk:      risk.High,
	Group:     GroupFlipperHW,
	AgentOnly: false,
	Handler: func(ctx context.Context, d *Deps, args map[string]any) (string, error) {
		// Validate before transport (v0.176).
		pin := intOr(args, "pin", 0)
		if pin < 1 || pin > 8 {
			return "", fmt.Errorf("buspirate_pin_set: pin must be 1-8")
		}
		v := args["value"]
		if err := d.RequireBusPirate(); err != nil {
			return "", err
		}
		if err := d.BusPirate.PinSet(ctx, pin, v); err != nil {
			return "", fmt.Errorf("buspirate_pin_set: %w", err)
		}
		body, _ := json.Marshal(map[string]any{"status": "ok", "pin": pin, "value": v})
		return string(body), nil
	},
}

// --- buspirate_pin_read ------------------------------------------------

var buspiratePinReadSpec = Spec{
	Name:        "buspirate_pin_read",
	Description: "Read the analog voltage at a single Bus Pirate 5 IO pin. Read-only.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"pin":{"type":"integer","description":"IO pin number, 1-8"}
		},
		"required":["pin"]
	}`),
	Required:  []string{"pin"},
	Risk:      risk.Low,
	Group:     GroupFlipperHW,
	AgentOnly: false,
	Handler: func(ctx context.Context, d *Deps, args map[string]any) (string, error) {
		// Validate before transport (v0.176).
		pin := intOr(args, "pin", 0)
		if pin < 1 || pin > 8 {
			return "", fmt.Errorf("buspirate_pin_read: pin must be 1-8")
		}
		if err := d.RequireBusPirate(); err != nil {
			return "", err
		}
		v, err := d.BusPirate.PinRead(ctx, pin)
		if err != nil {
			return "", fmt.Errorf("buspirate_pin_read: %w", err)
		}
		body, _ := json.Marshal(map[string]any{"pin": pin, "voltage": v})
		return string(body), nil
	},
}
