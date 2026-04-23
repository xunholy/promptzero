package tools

import (
	"context"
	"encoding/json"
	"time"

	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() {
	Register(Spec{
		Name:        "nfc_detect",
		Description: "Detect an NFC tag/card and return UID/ATQA/SAK/Type. Use this when the operator asks what a tag IS. When the operator asks to SCAN / SAVE / CLONE a tag, prefer nfc_read_save — it detects and writes a .nfc file in one call.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"timeout_seconds":{"type":"number","description":"How long to wait for a tag in seconds (default 30)"}}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupFlipperNFC,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			timeoutSeconds := 30
			if v, ok := p["timeout_seconds"]; ok {
				switch n := v.(type) {
				case float64:
					timeoutSeconds = int(n)
				case int:
					timeoutSeconds = n
				}
			}
			raw, err := d.Flipper.NFCDetect(time.Duration(timeoutSeconds) * time.Second)
			if err != nil {
				return raw, err
			}
			parsed := flipper.ParseNFCDetect(raw)
			b, _ := json.Marshal(parsed)
			return string(b), nil
		},
	})
}
