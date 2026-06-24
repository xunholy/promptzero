// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"context"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/config"
)

// TestListDevices_OutputStableAndOmitsEmptyType verifies the list_devices
// view is deterministic (sorted by name, not random map order) and omits
// the "type:" field for shorthand devices that set only a file — the
// bare-string form added in v0.749.
func TestListDevices_OutputStableAndOmitsEmptyType(t *testing.T) {
	spec, ok := Get("list_devices")
	if !ok {
		t.Fatal("list_devices not registered")
	}
	cfg := &config.Config{Devices: map[string]config.Device{
		// Shorthand: only File set.
		"garage": {File: "/ext/subghz/garage.sub"},
		// Full mapping with multiple commands.
		"tv": {Type: "infrared", File: "/ext/infrared/tv.ir", Commands: map[string]string{
			"volume_up": "/ext/infrared/tv_volup.ir",
			"power":     "/ext/infrared/tv_power.ir",
		}},
	}}

	out, err := spec.Handler(context.Background(), &Deps{Config: cfg}, nil)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}

	want := "- garage (file: /ext/subghz/garage.sub)\n" +
		"- tv (type: infrared, file: /ext/infrared/tv.ir)\n" +
		"    command: power -> /ext/infrared/tv_power.ir\n" +
		"    command: volume_up -> /ext/infrared/tv_volup.ir\n"
	if out != want {
		t.Errorf("list_devices output mismatch:\n got:\n%s\nwant:\n%s", out, want)
	}

	// Shorthand device must NOT print an empty "type:".
	if strings.Contains(out, "type: ,") || strings.Contains(out, "(type: )") {
		t.Errorf("shorthand device printed an empty type:\n%s", out)
	}
}
