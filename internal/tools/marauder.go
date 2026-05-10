package tools

import (
	"context"
	"encoding/json"
	"time"

	"github.com/xunholy/promptzero/internal/risk"
)

// marauder.go registers the marauder_* tools that were MCP-only prior to
// Wave 3. These tools address GPS, packet counters, SD storage, and LED
// control on the ESP32 Marauder devboard. They are now unified into the
// registry so both the MCP server and the agent can call them (§A.4).

//nolint:gochecknoinits
func init() {
	// --- GPS (passive read-only) ---

	Register(Spec{
		Name:        "marauder_gps_data",
		Description: "Return the last parsed GPS fix from the Marauder devboard (lat/lon/alt/date/accuracy). Silently returns empty when no GPS module is attached.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.GPSData()
		},
	})

	Register(Spec{
		Name:        "marauder_gps_field",
		Description: "Return a single GPS datum from the Marauder devboard. Valid fields: fix, sat, lon, lat, alt, date, accuracy, text, nmea. Optional nav_system: native, all, gps, glonass, galileo, navic, qzss, beidou.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"field":{"type":"string","description":"GPS field: fix|sat|lon|lat|alt|date|accuracy|text|nmea"},` +
			`"nav_system":{"type":"string","description":"Optional satellite system: native|all|gps|glonass|galileo|navic|qzss|beidou"}}}`),
		Required:  []string{"field"},
		Risk:      risk.Low,
		Group:     GroupMarauderWiFi,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.GPSField(str(p, "field"), str(p, "nav_system"))
		},
	})

	Register(Spec{
		Name:        "marauder_nmea",
		Description: "Stream raw NMEA sentences from the attached GPS module on the Marauder devboard. Empty on boards without GPS hardware.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Capture duration in seconds (default 5)"}}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.NMEACtx(ctx, time.Duration(intOr(p, "duration_seconds", 5))*time.Second)
		},
	})

	// --- Device-local utilities ---

	Register(Spec{
		Name:        "marauder_packet_count",
		Description: "Return the cumulative packet counters (per frame type) from the Marauder devboard since boot.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.PacketCount()
		},
	})

	Register(Spec{
		Name:        "marauder_storage_ls",
		Description: "List contents of a directory on the Marauder SD card.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","description":"Directory path to list (default /)"}}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.StorageLS(str(p, "path"))
		},
	})

	// --- LED control ---

	Register(Spec{
		Name:        "marauder_led_set",
		Description: "Set the Marauder devboard LED to a fixed 24-bit RGB hex colour. E.g. 'ff0000' for red, '00ff00' for green.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"rgb_hex":{"type":"string","description":"6-hex RGB colour e.g. ff0000 (no # prefix)"}}}`),
		Required:    []string{"rgb_hex"},
		Risk:        risk.Low,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.LEDSetHex(str(p, "rgb_hex"))
		},
	})

	Register(Spec{
		Name:        "marauder_led_rainbow",
		Description: "Start the cycling rainbow LED pattern on the Marauder devboard. Use any other LED command to stop it.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.LEDRainbow()
		},
	})
}
