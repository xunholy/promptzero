package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
)

// vision.go registers the analyze_image tool. AgentOnly:true — requires
// the Vision analyzer which is only wired in agent mode.

//nolint:gochecknoinits
func init() {
	Register(Spec{
		Name: "analyze_image",
		Description: "Analyze a photo of a device, remote, tag, lock, keypad, or any physical target. " +
			"The AI identifies what it is and suggests exactly how to interact with it using the Flipper Zero. " +
			"Send a photo and get back: device identification, protocol/frequency, and recommended promptzero commands.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"image":{"type":"string","description":"Base64-encoded image data or file path to an image"},` +
			`"question":{"type":"string","description":"Specific question about the image (default: identify the device and suggest Flipper actions)"}` +
			`}}`),
		Required:  []string{"image"},
		Risk:      risk.Low,
		Group:     GroupVision,
		AgentOnly: true,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			if d.Vision == nil {
				return "", fmt.Errorf("vision not available")
			}
			image := str(p, "image")
			question := str(p, "question")
			// Route to base64 handler if the data URI prefix is present, or if the
			// string has no path separator and no file extension dot (i.e. it looks
			// like raw base64 rather than a filesystem path).
			if strings.HasPrefix(image, "data:") || (!strings.HasPrefix(image, "/") && !strings.Contains(image, ".")) {
				return d.Vision.AnalyzeBase64(ctx, image, question)
			}
			return d.Vision.AnalyzeFile(ctx, image, question)
		},
	})
}
