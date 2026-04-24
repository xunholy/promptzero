// hwtest is a developer-only smoke harness that drives a real Flipper Zero
// (and optional Marauder) over MCP. Run from the repo root:
//
//	go run ./cmd/hwtest --port /dev/ttyACM0
//
// It launches `bin/promptzero --mcp` as a subprocess, walks a curated tool
// list against the live device, and prints a one-line per-tool result table.
// Every case carries a per-call timeout so a stalled subshell can't hang
// the whole run. Read-only by default; -write enables a small SD round-trip.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	mcplib "github.com/mark3labs/mcp-go/mcp"
)

type testCase struct {
	name    string
	args    map[string]any
	timeout time.Duration
}

func main() {
	var (
		binPath = flag.String("bin", "./bin/promptzero", "path to promptzero binary")
		port    = flag.String("port", "/dev/ttyACM0", "Flipper serial port")
		write   = flag.Bool("write", true, "include SD-card round-trip")
		filter  = flag.String("only", "", "comma-separated substrings; only run cases whose names contain one")
	)
	flag.Parse()

	cases := []testCase{
		{name: "device_info", timeout: 10 * time.Second},
		{name: "power_info", timeout: 10 * time.Second},
		{name: "list_apps", timeout: 10 * time.Second},
		{name: "loader_info", timeout: 10 * time.Second},

		{name: "storage_info", args: map[string]any{"path": "/ext"}, timeout: 10 * time.Second},
		{name: "storage_list", args: map[string]any{"path": "/ext"}, timeout: 10 * time.Second},
		{name: "storage_list", args: map[string]any{"path": "/ext/subghz"}, timeout: 10 * time.Second},
		{name: "storage_list", args: map[string]any{"path": "/ext/nfc"}, timeout: 10 * time.Second},
		{name: "storage_list", args: map[string]any{"path": "/ext/infrared"}, timeout: 10 * time.Second},

		{name: "i2c_scan", timeout: 15 * time.Second},
		{name: "onewire_search", args: map[string]any{"duration_seconds": 3}, timeout: 12 * time.Second},

		{name: "led_set", args: map[string]any{"channel": "r", "value": 200}, timeout: 5 * time.Second},
		{name: "led_set", args: map[string]any{"channel": "r", "value": 0}, timeout: 5 * time.Second},
		{name: "vibro", args: map[string]any{"on": true}, timeout: 5 * time.Second},
		{name: "vibro", args: map[string]any{"on": false}, timeout: 5 * time.Second},

		{name: "subghz_receive", args: map[string]any{"frequency": 433920000, "duration_seconds": 3}, timeout: 12 * time.Second},
		{name: "ir_receive", args: map[string]any{"timeout_seconds": 3}, timeout: 12 * time.Second},
		{name: "nfc_detect", args: map[string]any{"timeout_seconds": 3}, timeout: 12 * time.Second},

		{name: "flipper_raw_cli", args: map[string]any{"command": "device_info"}, timeout: 10 * time.Second},
	}

	if *write {
		path := fmt.Sprintf("/ext/promptzero_hwtest_%d.txt", time.Now().Unix())
		body := fmt.Sprintf("promptzero hwtest %s\n", time.Now().UTC().Format(time.RFC3339))
		cases = append(cases,
			testCase{name: "storage_write", args: map[string]any{"path": path, "content": body}, timeout: 15 * time.Second},
			testCase{name: "storage_read", args: map[string]any{"path": path}, timeout: 10 * time.Second},
			testCase{name: "storage_md5", args: map[string]any{"path": path}, timeout: 10 * time.Second},
			testCase{name: "storage_delete", args: map[string]any{"path": path}, timeout: 10 * time.Second},
		)
	}

	if *filter != "" {
		needles := strings.Split(*filter, ",")
		filtered := cases[:0]
		for _, c := range cases {
			for _, n := range needles {
				if strings.Contains(c.name, strings.TrimSpace(n)) {
					filtered = append(filtered, c)
					break
				}
			}
		}
		cases = filtered
	}

	tr := transport.NewStdio(*binPath, os.Environ(), "--mcp", "--port", *port)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := tr.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "transport start: %v\n", err)
		os.Exit(1)
	}
	defer tr.Close()

	c := client.NewClient(tr)
	initCtx, initCancel := context.WithTimeout(ctx, 30*time.Second)
	var init mcplib.InitializeRequest
	init.Params.ProtocolVersion = mcplib.LATEST_PROTOCOL_VERSION
	init.Params.ClientInfo = mcplib.Implementation{Name: "promptzero-hwtest", Version: "0"}
	if _, err := c.Initialize(initCtx, init); err != nil {
		initCancel()
		fmt.Fprintf(os.Stderr, "initialize: %v\n", err)
		os.Exit(1)
	}
	initCancel()

	listCtx, listCancel := context.WithTimeout(ctx, 10*time.Second)
	tools, err := c.ListTools(listCtx, mcplib.ListToolsRequest{})
	listCancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "tools/list: %v\n", err)
		os.Exit(1)
	}
	available := map[string]bool{}
	for _, t := range tools.Tools {
		available[t.Name] = true
	}
	fmt.Printf("# Connected. %d tools advertised.\n", len(tools.Tools))
	fmt.Println()

	pass, fail, skipped := 0, 0, 0
	for _, tc := range cases {
		label := tc.name
		if len(tc.args) > 0 {
			b, _ := json.Marshal(tc.args)
			label = fmt.Sprintf("%s %s", tc.name, string(b))
		}
		if !available[tc.name] {
			fmt.Printf("SKIP  %-70s  not advertised\n", label)
			skipped++
			continue
		}

		callCtx, callCancel := context.WithTimeout(ctx, tc.timeout)
		start := time.Now()
		req := mcplib.CallToolRequest{}
		req.Params.Name = tc.name
		req.Params.Arguments = tc.args
		res, err := c.CallTool(callCtx, req)
		callCancel()
		dur := time.Since(start).Round(time.Millisecond)

		switch {
		case err != nil:
			fmt.Printf("FAIL  %-70s  %6s  transport: %v\n", label, dur, err)
			fail++
		case res != nil && res.IsError:
			fmt.Printf("FAIL  %-70s  %6s  %s\n", label, dur, summary(res))
			fail++
		default:
			fmt.Printf("PASS  %-70s  %6s  %s\n", label, dur, summary(res))
			pass++
		}
	}

	fmt.Println()
	fmt.Printf("# %d pass, %d fail, %d skip\n", pass, fail, skipped)
	if fail > 0 {
		os.Exit(1)
	}
}

func summary(res *mcplib.CallToolResult) string {
	if res == nil {
		return "(nil result)"
	}
	for _, c := range res.Content {
		if tc, ok := c.(mcplib.TextContent); ok {
			s := strings.ReplaceAll(strings.TrimSpace(tc.Text), "\n", " ⏎ ")
			if len(s) > 110 {
				s = s[:107] + "..."
			}
			return s
		}
	}
	return "(no text content)"
}
