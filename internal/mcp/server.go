package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/marauder"
)

type Server struct {
	flipper  *flipper.Flipper
	marauder *marauder.Marauder
	srv      *mcpserver.MCPServer
}

type toolHandler func(args map[string]interface{}) (string, error)

func NewServer(f *flipper.Flipper, m *marauder.Marauder) *Server {
	s := &Server{flipper: f, marauder: m}

	s.srv = mcpserver.NewMCPServer(
		"promptzero",
		"1.0.0",
		mcpserver.WithToolCapabilities(true),
	)

	s.registerFlipperTools()
	if m != nil {
		s.registerMarauderTools()
	}

	return s
}

func (s *Server) ServeStdio() error {
	// MCP has no shell to prompt on; every tool executes immediately.
	// Surface that trust boundary on startup so it's never implicit.
	fmt.Fprintln(os.Stderr, "\x1b[33m●\x1b[0m MCP mode: all tools execute without confirmation — trust your MCP client")
	return mcpserver.ServeStdio(s.srv)
}

func (s *Server) registerFlipperTools() {
	s.add("subghz_transmit", "Transmit a saved Sub-GHz signal file",
		[]mcp.ToolOption{mcp.WithString("file", mcp.Required(), mcp.Description("Path to .sub file"))},
		func(a map[string]interface{}) (string, error) { return s.flipper.SubGHzTx(sa(a, "file")) })

	s.add("subghz_receive", "Capture Sub-GHz signals on a frequency",
		[]mcp.ToolOption{mcp.WithNumber("frequency", mcp.Required(), mcp.Description("Frequency in Hz"))},
		func(a map[string]interface{}) (string, error) {
			return s.flipper.SubGHzRx(uint32(na(a, "frequency")), 30*time.Second)
		})

	s.add("ir_transmit", "Send an infrared command",
		[]mcp.ToolOption{
			mcp.WithString("protocol", mcp.Required(), mcp.Description("IR protocol")),
			mcp.WithString("address", mcp.Required(), mcp.Description("IR address")),
			mcp.WithString("command", mcp.Required(), mcp.Description("IR command")),
		},
		func(a map[string]interface{}) (string, error) {
			return s.flipper.IRTxParsed(sa(a, "protocol"), sa(a, "address"), sa(a, "command"))
		})

	s.add("nfc_detect", "Detect an NFC tag", nil,
		func(a map[string]interface{}) (string, error) { return s.flipper.NFCDetect(30 * time.Second) })

	s.add("nfc_emulate", "Emulate a saved NFC tag",
		[]mcp.ToolOption{mcp.WithString("file", mcp.Required(), mcp.Description("Path to .nfc file"))},
		func(a map[string]interface{}) (string, error) { return s.flipper.NFCEmulate(sa(a, "file")) })

	s.add("rfid_read", "Read a 125kHz RFID tag", nil,
		func(a map[string]interface{}) (string, error) {
			return s.flipper.RFIDRead(context.Background(), "", 15*time.Second)
		})

	s.add("rfid_emulate", "Emulate a saved RFID tag",
		[]mcp.ToolOption{
			mcp.WithString("protocol", mcp.Required(), mcp.Description("RFID protocol")),
			mcp.WithString("data", mcp.Required(), mcp.Description("RFID data")),
		},
		func(a map[string]interface{}) (string, error) {
			return s.flipper.RFIDEmulate(sa(a, "protocol"), sa(a, "data"))
		})

	s.add("gpio_set", "Set a GPIO pin high or low",
		[]mcp.ToolOption{
			mcp.WithString("pin", mcp.Required(), mcp.Description("GPIO pin name")),
			mcp.WithNumber("value", mcp.Required(), mcp.Description("0 or 1")),
		},
		func(a map[string]interface{}) (string, error) {
			return s.flipper.GPIOSet(sa(a, "pin"), int(na(a, "value")))
		})

	s.add("gpio_read", "Read GPIO pin state",
		[]mcp.ToolOption{mcp.WithString("pin", mcp.Required(), mcp.Description("GPIO pin name"))},
		func(a map[string]interface{}) (string, error) { return s.flipper.GPIORead(sa(a, "pin")) })

	s.add("badusb_run", "Execute a BadUSB script",
		[]mcp.ToolOption{mcp.WithString("file", mcp.Required(), mcp.Description("Path to script"))},
		func(a map[string]interface{}) (string, error) { return s.flipper.BadUSBRun(sa(a, "file")) })

	s.add("storage_list", "List files on Flipper SD card",
		[]mcp.ToolOption{mcp.WithString("path", mcp.Required(), mcp.Description("Directory path"))},
		func(a map[string]interface{}) (string, error) { return s.flipper.StorageList(sa(a, "path")) })

	s.add("storage_read", "Read a file from Flipper SD card",
		[]mcp.ToolOption{mcp.WithString("path", mcp.Required(), mcp.Description("File path"))},
		func(a map[string]interface{}) (string, error) { return s.flipper.StorageRead(sa(a, "path")) })

	s.add("storage_write", "Write content to Flipper SD card",
		[]mcp.ToolOption{
			mcp.WithString("path", mcp.Required(), mcp.Description("File path")),
			mcp.WithString("content", mcp.Required(), mcp.Description("File content")),
		},
		func(a map[string]interface{}) (string, error) {
			if err := s.flipper.StorageWrite(sa(a, "path"), sa(a, "content")); err != nil {
				return "", err
			}
			return "ok", nil
		})

	s.add("system_info", "Get Flipper system information", nil,
		func(a map[string]interface{}) (string, error) { return s.flipper.DeviceInfo() })

	s.add("power_info", "Get battery and power information", nil,
		func(a map[string]interface{}) (string, error) { return s.flipper.PowerInfo() })
}

func (s *Server) registerMarauderTools() {
	s.add("wifi_scan_ap", "Scan for WiFi access points", nil,
		func(a map[string]interface{}) (string, error) { return s.marauder.ScanAP(15 * time.Second) })

	s.add("wifi_deauth", "Deauthentication attack on selected targets", nil,
		func(a map[string]interface{}) (string, error) { return s.marauder.DeauthAttack(30 * time.Second) })

	s.add("wifi_beacon_spam", "Broadcast fake WiFi networks", nil,
		func(a map[string]interface{}) (string, error) { return s.marauder.BeaconSpamList(30 * time.Second) })

	s.add("wifi_sniff_pmkid", "Capture PMKID hashes", nil,
		func(a map[string]interface{}) (string, error) { return s.marauder.SniffPMKID("", 60*time.Second) })

	s.add("wifi_evil_portal_start", "Start evil portal captive portal", nil,
		func(a map[string]interface{}) (string, error) { return s.marauder.EvilPortalStart("") })

	s.add("wifi_evil_portal_stop", "Stop evil portal", nil,
		func(a map[string]interface{}) (string, error) { return s.marauder.EvilPortalStop() })

	s.add("wifi_info", "Get WiFi devboard info", nil,
		func(a map[string]interface{}) (string, error) { return s.marauder.Info() })
}

func (s *Server) add(name, desc string, opts []mcp.ToolOption, handler toolHandler) {
	allOpts := []mcp.ToolOption{mcp.WithDescription(desc)}
	allOpts = append(allOpts, opts...)
	tool := mcp.NewTool(name, allOpts...)

	s.srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := make(map[string]interface{})
		if req.Params.Arguments != nil {
			data, _ := json.Marshal(req.Params.Arguments)
			json.Unmarshal(data, &args)
		}
		result, err := handler(args)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("error: %v", err)), nil
		}
		return mcp.NewToolResultText(result), nil
	})
}

func sa(a map[string]interface{}, k string) string {
	if v, ok := a[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func na(a map[string]interface{}, k string) float64 {
	if v, ok := a[k]; ok {
		if f, ok := v.(float64); ok {
			return f
		}
	}
	return 0
}
