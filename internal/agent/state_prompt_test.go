package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/flipper"
)

func TestBuildDeviceStateBlock_NilFlipper(t *testing.T) {
	got := buildDeviceStateBlock(context.Background(), nil)
	if got != "" {
		t.Fatalf("nil flipper should yield empty block, got %q", got)
	}
}

func TestBuildDeviceStateBlock_ConnectedFlipper(t *testing.T) {
	f := flipper.NewForTest(flipper.Capabilities{
		FirmwareFork:    "Momentum",
		FirmwareVersion: "0.99.1",
	})
	got := buildDeviceStateBlock(context.Background(), f)
	if !strings.HasPrefix(got, "<device-state>\n") {
		t.Fatalf("missing open tag: %q", got)
	}
	if !strings.HasSuffix(got, "\n</device-state>\n\n") {
		t.Fatalf("missing close tag + newlines: %q", got)
	}
	if !strings.Contains(got, `"fork":"Momentum"`) {
		t.Errorf("block should contain fork, got: %q", got)
	}
	if !strings.Contains(got, `"connected":true`) {
		t.Errorf("block should report connected=true when caps populated, got: %q", got)
	}
}

func TestBuildUIContextBlock(t *testing.T) {
	cases := []struct {
		name, view, path, want string
	}{
		{"empty", "", "", ""},
		{"view only", "agent", "", "<ui-context view=\"agent\" path=\"\"/>\n"},
		{"path only", "", "/ext/subghz/garage.sub", "<ui-context view=\"\" path=\"/ext/subghz/garage.sub\"/>\n"},
		{"both", "preview", "/ext/nfc/card.nfc", "<ui-context view=\"preview\" path=\"/ext/nfc/card.nfc\"/>\n"},
		{"strip control chars", "preview", "/ext/foo\x00\x07bar", "<ui-context view=\"preview\" path=\"/ext/foobar\"/>\n"},

		// XML-attribute-special characters must be stripped so the
		// emitted block stays well-formed for the LLM. Pre-fix `%q`
		// emitted Go-escapes (e.g. `path="foo\"bar"`) which aren't
		// valid XML attribute syntax, and `&` / `<` would have made
		// the prefix actively malformed XML. The previous docstring
		// asserted upstream validation prevented this, but
		// setUIContextFromWS only checks NUL + length, leaving
		// Flipper filenames containing these characters as a real
		// path the cockpit can navigate to.
		{"strip double-quote in path", "files", `/ext/foo"bar.sub`,
			`<ui-context view="files" path="/ext/foobar.sub"/>` + "\n"},
		{"strip ampersand in path", "files", `/ext/a&b.sub`,
			`<ui-context view="files" path="/ext/ab.sub"/>` + "\n"},
		{"strip angle brackets in path", "files", `/ext/<tag>.sub`,
			`<ui-context view="files" path="/ext/tag.sub"/>` + "\n"},
		{"strip apostrophe in path", "files", `/ext/it's.sub`,
			`<ui-context view="files" path="/ext/its.sub"/>` + "\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildUIContextBlock(tc.view, tc.path)
			if got != tc.want {
				t.Errorf("buildUIContextBlock(%q,%q) = %q, want %q", tc.view, tc.path, got, tc.want)
			}
		})
	}
}
