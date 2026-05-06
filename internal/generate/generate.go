package generate

import (
	"context"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/provider"
)

// Generator creates, validates, deploys, and runs payloads on the Flipper Zero.
type Generator struct {
	llm provider.Provider
	// fallback is an optional secondary provider used when the primary
	// returns a model refusal (Anthropic policy walls a legitimate
	// red-team payload, etc.). When nil, refusals propagate to the
	// caller unchanged — same UX as pre-v0.20.0.
	fallback provider.Provider
	flipper  *flipper.Flipper
}

func New(llm provider.Provider, f *flipper.Flipper) *Generator {
	return &Generator{llm: llm, flipper: f}
}

// SetFallback wires a secondary provider that's consulted when the
// primary returns text matching a canonical refusal pattern. Pass nil
// to disable. The fallback is typically a local Ollama instance for
// engagements where Anthropic policy refuses legitimate offensive
// payload synthesis.
func (g *Generator) SetFallback(p provider.Provider) {
	g.fallback = p
}

// Result.Provider names the provider that actually generated the
// payload — empty string when the primary served (the common case),
// non-empty when a fallback was used. Surfaced so the operator can
// see "generated via ollama/llama3.1" rather than wondering why a
// previously-refused request now succeeded.

// Result of a generation operation.
type Result struct {
	Type     string `json:"type"`
	Content  string `json:"content"`
	Path     string `json:"path"`
	Deployed bool   `json:"deployed"`
	Preview  string `json:"preview"`
	// Provider names the LLM that served the request when a
	// refusal-fallback fired. Empty when the primary provider
	// generated the response (the common case).
	Provider string `json:"provider,omitempty"`
}

// --- Evil Portal ---

func (g *Generator) EvilPortal(ctx context.Context, description string) (*Result, error) {
	prompt := fmt.Sprintf(`Generate a complete, self-contained HTML page for a Flipper Zero Evil Portal captive portal.

DESCRIPTION: %s

REQUIREMENTS:
- Single HTML file with all CSS and JS inline — NO external resources (no CDN links, no external images)
- Maximum 20,000 characters total
- Must look convincing and professional with mobile-responsive design
- The form action MUST be "/get" (exactly this path — the Evil Portal FAP captures GET requests to /get)
- The form method MUST be "GET" (not POST)
- The credential input fields MUST be named exactly "email" and "password" — the Evil Portal FAP looks for these exact field names
- Make it visually identical to the real thing — matching colors, fonts, logos (use SVG inline or CSS), layout
- Include subtle details: favicon meta tags, proper page title, placeholder text
- Return ONLY the HTML, nothing else — no markdown, no explanation, no code fences`, description)

	resp, fbProvider, err := g.completeWithFallback(ctx,
		"You are an expert web developer and UI designer. You create pixel-perfect replicas of login pages. Output raw HTML only — no markdown, no explanation.",
		[]provider.Message{{Role: "user", Content: prompt}},
		"evil_portal")
	if err != nil {
		return nil, fmt.Errorf("generating evil portal: %w", err)
	}

	html := cleanOutput(resp.Content, "html")

	if len(html) > 20000 {
		html = html[:20000]
	}

	return &Result{
		Type:     "evil_portal",
		Content:  html,
		Preview:  truncate(html, 500),
		Provider: fbProvider,
	}, nil
}

// --- BadUSB / DuckyScript ---

// keyboardLayoutGuidance returns prompt-friendly notes for the model
// when a non-US layout is requested. Empty string for "us"/"" so the
// happy-path prompt stays unchanged. Curated list covers the layouts
// v1nc's CFW + Momentum / Unleashed actually ship .kl files for as
// of mid-2026; unknown layouts fall back to a generic note.
func keyboardLayoutGuidance(layout string) string {
	switch strings.ToLower(strings.TrimSpace(layout)) {
	case "", "us":
		return ""
	case "gb", "uk":
		return "Target uses the UK (gb) keyboard layout. £/$ swap, @/\" swap, # vs ~ position differs from US. Use ALTCHAR for £ (0163) when needed."
	case "de":
		return "Target uses the German (de) keyboard layout. Y/Z are swapped; ä ö ü ß occupy keys US has -, ;, ', /. AltGr modifier required for @ (Alt-Q). Use ALTCHAR for accented characters: ä=0228 ö=0246 ü=0252 ß=0223."
	case "fr":
		return "Target uses the French AZERTY (fr) layout. A/Q and W/Z swap; numbers require Shift. AltGr for @ (Alt-0), # (Alt-3). Use ALTCHAR for é=0233 è=0232 à=0224 ç=0231 ù=0249."
	case "es":
		return "Target uses the Spanish (es) layout. Tilde dead-key in front of vowels; ñ on the ; key. ALTCHAR for ñ=0241 á=0225 é=0233 í=0237 ó=0243 ú=0250 ¿=0191."
	case "it":
		return "Target uses the Italian (it) layout. Accented vowels on the right of L key. ALTCHAR for à=0224 è=0232 ì=0236 ò=0242 ù=0249."
	case "dk", "no", "sv", "se":
		return "Target uses a Nordic (dk/no/sv) layout. å, æ/ø/ä/ö occupy the right of L key. ALTCHAR for å=0229 æ=0230 ø=0248 ä=0228 ö=0246."
	case "pt":
		return "Target uses the Portuguese (pt) layout. Tilde dead-key. ALTCHAR for ã=0227 õ=0245 ç=0231."
	case "br":
		return "Target uses the Brazilian Portuguese (pt-BR) layout. Cedilla on dedicated key, accent dead-keys. ALTCHAR for ã=0227 ç=0231 á=0225."
	default:
		return fmt.Sprintf("Target uses the %q keyboard layout. Characters that don't map cleanly to US ASCII should use ALTCHAR <Unicode-decimal> rather than literal STRING.", layout)
	}
}

func (g *Generator) BadUSB(ctx context.Context, description string, targetOS string, keyboardLayout string) (*Result, error) {
	if targetOS == "" {
		targetOS = "windows"
	}
	if keyboardLayout == "" {
		keyboardLayout = "us"
	}
	layoutNote := keyboardLayoutGuidance(keyboardLayout)
	if layoutNote != "" {
		layoutNote = "\nKEYBOARD LAYOUT: " + layoutNote + "\n"
	}

	prompt := fmt.Sprintf(`Generate a Flipper Zero BadUSB (DuckyScript) payload.

DESCRIPTION: %s
TARGET OS: %s%s
REQUIREMENTS:
- Use valid DuckyScript syntax compatible with Flipper Zero
- Standard commands: REM, DELAY, STRING, ENTER, GUI, ALT, CTRL, SHIFT, TAB, ESCAPE, UP, DOWN, LEFT, RIGHT, CAPS_LOCK, DELETE, BACKSPACE, END, HOME, INSERT, PAGEUP, PAGEDOWN, PRINTSCREEN, SPACE, F1-F24, MENU
- Flipper Zero-specific commands:
  - STRINGLN <text>  (types a string and presses Enter)
  - REPEAT <n>  (repeats the previous command n times)
  - HOLD <key>  (holds a key down)
  - RELEASE <key>  (releases a held key)
  - SYSRQ <key>  (sends a SysRq key combination)
  - ALTCHAR <code>  (types a character by Alt+numpad code)
  - ALTSTRING <text>  (types a string using Alt+numpad codes, for non-ASCII)
  - WAIT_FOR_BUTTON_PRESS  (pauses until the Flipper OK button is pressed)
  - MEDIA <key>  (media key: MUTE, VOLUME_UP, VOLUME_DOWN, etc.)
  - GLOBE <key>  (Globe/Fn key on macOS)
  - MOUSEMOVE <x> <y>  (moves the mouse cursor)
  - MOUSESCROLL <delta>  (scrolls the mouse wheel)
  - DEFAULT_DELAY <ms>  (sets the default delay between all commands)
  - STRING_DELAY <ms>  (sets the delay between characters in STRING)
  - ID <VID>:<PID> <Manufacturer>:<Product>  (USB identity spoofing — must be the very first line if used)
- Compound keys use a hyphen separator for modifier+modifier combos: CTRL-ALT DELETE, CTRL-SHIFT ESCAPE
- Single modifier + key uses a space: GUI r, ALT F4, CTRL c
- Start with appropriate DELAY values for the USB device to be recognized
- Target the specified OS
- Be efficient — minimize delays where possible but keep it reliable
- Return ONLY the DuckyScript, nothing else — no markdown, no explanation`, description, targetOS, layoutNote)

	resp, fbProvider, err := g.completeWithFallback(ctx,
		"You are an expert in DuckyScript and USB HID attack payloads for Flipper Zero. You create reliable, efficient scripts. Output raw DuckyScript only.",
		[]provider.Message{{Role: "user", Content: prompt}},
		"badusb")
	if err != nil {
		return nil, fmt.Errorf("generating badusb: %w", err)
	}

	script := cleanOutput(resp.Content, "")
	// cap at 64KB — catches runaway LLM output; typical BadUSB scripts are <2KB
	script = capSize(script, 65536)

	return &Result{
		Type:     "badusb",
		Content:  script,
		Preview:  truncate(script, 500),
		Provider: fbProvider,
	}, nil
}

// --- Sub-GHz Signal ---

func (g *Generator) SubGHz(ctx context.Context, description string) (*Result, error) {
	prompt := fmt.Sprintf(`Generate a Flipper Zero .sub (Sub-GHz) signal file.

DESCRIPTION: %s

REQUIREMENTS:
- Use valid Flipper Zero .sub file format
- For parsed/known protocol files use this header and structure:
    Filetype: Flipper SubGhz Key File
    Version: 1
    Frequency: <Hz>
    Preset: <preset>
    Protocol: <name>
    Bit: <count>
    Key: XX XX XX XX XX XX XX XX   (8 bytes, space-separated hex)
    (plus any protocol-specific fields, e.g. TE: <value> for Princeton)
- For raw signal files use this header and structure:
    Filetype: Flipper SubGhz RAW File
    Version: 1
    Frequency: <Hz>
    Preset: <preset>
    Protocol: RAW
    RAW_Data: <values>   (positive = ON microseconds, negative = OFF microseconds; max 512 values per line; use multiple RAW_Data lines for longer captures)
- Common frequencies (Hz): 300000000, 315000000, 433920000, 868350000
- Valid presets: FuriHalSubGhzPresetOok270Async, FuriHalSubGhzPresetOok650Async, FuriHalSubGhzPreset2FSKDev238Async, FuriHalSubGhzPreset2FSKDev476Async, FuriHalSubGhzPresetMSK99_97KbAsync, FuriHalSubGhzPresetGFSK9_99KbAsync
- Supported protocols include: Princeton, CAME, Nice FLO, Nice FloR-S, KeeLoq, Linear, Chamberlain, FAAC SLH, BFT Mitto, Doitrand, Marantec, BETT, Hormann BiSecur, Somfy Telis, and others
- Choose the appropriate file type (key vs raw) and protocol based on the description
- Return ONLY the .sub file content, nothing else — no markdown, no explanation`, description)

	resp, fbProvider, err := g.completeWithFallback(ctx,
		"You are an expert in RF signal encoding and Sub-GHz protocols. You create valid Flipper Zero .sub files. Output raw file content only.",
		[]provider.Message{{Role: "user", Content: prompt}},
		"subghz")
	if err != nil {
		return nil, fmt.Errorf("generating subghz: %w", err)
	}

	content := cleanOutput(resp.Content, "")
	// cap at 128KB — RAW captures can be large; parsed protocol files are tiny
	content = capSize(content, 131072)

	return &Result{
		Type:     "subghz",
		Content:  content,
		Preview:  truncate(content, 500),
		Provider: fbProvider,
	}, nil
}

// --- Infrared Signal ---

func (g *Generator) IR(ctx context.Context, description string) (*Result, error) {
	prompt := fmt.Sprintf(`Generate a Flipper Zero .ir (Infrared) signal file.

DESCRIPTION: %s

REQUIREMENTS:
- Use valid Flipper Zero .ir file format
- File header (first two lines, exactly):
    Filetype: IR signals file
    Version: 1
- Each signal starts with a blank line then a "#" comment line (e.g. # Button name), then signal fields
- Parsed signal fields (in this order):
    name: <label>
    type: parsed
    protocol: <name>
    address: XX XX XX XX   (4 bytes hex, space-separated)
    command: XX XX XX XX   (4 bytes hex, space-separated)
- Raw signal fields (in this order):
    name: <label>
    type: raw
    frequency: 38000
    duty_cycle: 0.330000   (exactly 6 decimal places)
    data: <space-separated timing samples>   (max 1024 elements)
- Supported parsed protocols: NEC, NECext, NEC42, NEC42ext, Samsung32, RC6, RC5, RC5X, SIRC, SIRC15, SIRC20, Kaseikyo, RCA, Pioneer
- Include multiple useful commands if the description implies a device (e.g. power, vol up, vol down, mute, input select)
- Return ONLY the .ir file content, nothing else — no markdown, no explanation`, description)

	resp, fbProvider, err := g.completeWithFallback(ctx,
		"You are an expert in infrared protocols and consumer electronics. You create valid Flipper Zero .ir files. Output raw file content only.",
		[]provider.Message{{Role: "user", Content: prompt}},
		"ir")
	if err != nil {
		return nil, fmt.Errorf("generating ir: %w", err)
	}

	content := cleanOutput(resp.Content, "")
	// cap at 64KB — multi-signal IR files (universal remotes) can grow
	content = capSize(content, 65536)

	return &Result{
		Type:     "ir",
		Content:  content,
		Preview:  truncate(content, 500),
		Provider: fbProvider,
	}, nil
}

// --- NFC Data ---

func (g *Generator) NFC(ctx context.Context, description string) (*Result, error) {
	prompt := fmt.Sprintf(`Generate a Flipper Zero .nfc file.

DESCRIPTION: %s

REQUIREMENTS:
- Use valid Flipper Zero .nfc file format
- File header (first two lines, exactly):
    Filetype: Flipper NFC device
    Version: 4
- The device type field key is lowercase "t": Device type: <value>
- Device type values: Mifare Classic, NTAG/Ultralight, ISO14443-3A, ISO14443-4A, etc.
- For Mifare Classic tags include:
    Device type: Mifare Classic
    UID: XX XX XX XX (or 7-byte)
    ATQA: XX XX
    SAK: XX
    Mifare Classic type: 1K   (or 4K or MINI)
    Data format version: 2
    Block 0: XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX   (16 bytes hex, space-separated)
    Block 1: ...
    (all blocks for the tag size; sector trailers at blocks 3, 7, 11, … must have valid key A, access bits, key B)
- For NTAG/Ultralight tags include:
    Device type: NTAG/Ultralight
    UID: XX XX XX XX XX XX XX
    ATQA: 00 44
    SAK: 00
    Data format version: 2
    NTAG/Ultralight type: <NTAG213/NTAG215/NTAG216/etc.>
    Signature: XX XX ... (32 bytes)
    Mifare version: XX XX XX XX XX XX XX XX (8 bytes)
    Counter 0: <value>
    Tearing 0: XX
    Counter 1: <value>
    Tearing 1: XX
    Counter 2: <value>
    Tearing 2: XX
    Pages total: <count>
    Page 0: XX XX XX XX
    Page 1: XX XX XX XX
    (all pages)
- Format all hex values as uppercase pairs separated by spaces
- Return ONLY the .nfc file content, nothing else — no markdown, no explanation`, description)

	resp, fbProvider, err := g.completeWithFallback(ctx,
		"You are an expert in NFC protocols and MIFARE/NTAG technology. You create valid Flipper Zero .nfc files. Output raw file content only.",
		[]provider.Message{{Role: "user", Content: prompt}},
		"nfc")
	if err != nil {
		return nil, fmt.Errorf("generating nfc: %w", err)
	}

	content := cleanOutput(resp.Content, "")
	// cap at 32KB — covers MIFARE Classic 4K with metadata
	content = capSize(content, 32768)

	return &Result{
		Type:     "nfc",
		Content:  content,
		Preview:  truncate(content, 500),
		Provider: fbProvider,
	}, nil
}

// --- Deploy writes generated content to the Flipper SD card ---

func (g *Generator) Deploy(ctx context.Context, result *Result, path string) error {
	if path == "" {
		path = defaultPath(result.Type)
	}

	if idx := strings.LastIndex(path, "/"); idx > 0 {
		// Best-effort mkdir; ignore errors (directory often already exists).
		dir := path[:idx]
		_, _ = g.flipper.StorageMkdir(dir)
	}

	if err := g.flipper.WriteFileCtx(ctx, path, []byte(result.Content)); err != nil {
		return fmt.Errorf("deploying to %s: %w", path, err)
	}

	result.Path = path
	result.Deployed = true
	return nil
}

func defaultPath(payloadType string) string {
	switch payloadType {
	case "evil_portal":
		return "/ext/apps_data/evil_portal/index.html"
	case "badusb":
		return "/ext/badusb/generated_payload.txt"
	case "subghz":
		return "/ext/subghz/generated_signal.sub"
	case "ir":
		return "/ext/infrared/generated_remote.ir"
	case "nfc":
		return "/ext/nfc/generated_tag.nfc"
	default:
		return "/ext/generated_" + payloadType
	}
}

// capSize caps s at max bytes. label is for documentation purposes only.
// Applied after cleanOutput to bound runaway LLM output before it reaches
// the Flipper write path or the caller.
func capSize(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}

// cleanOutput strips markdown code fences and other wrapping from LLM output.
func cleanOutput(s string, lang string) string {
	s = strings.TrimSpace(s)

	// Try to extract content between code fences
	// Case-insensitive fence detection
	lower := strings.ToLower(s)
	fenceStart := -1
	fenceEnd := -1

	// Find opening fence
	for _, prefix := range []string{"```" + strings.ToLower(lang), "```"} {
		if strings.HasPrefix(lower, prefix) {
			fenceStart = strings.Index(s, "\n")
			if fenceStart == -1 {
				fenceStart = len(prefix)
			} else {
				fenceStart++ // skip the newline
			}
			break
		}
	}

	// Find closing fence (last occurrence)
	if fenceStart >= 0 {
		lastFence := strings.LastIndex(s, "```")
		if lastFence > fenceStart {
			fenceEnd = lastFence
		}
	}

	if fenceStart >= 0 && fenceEnd > fenceStart {
		s = s[fenceStart:fenceEnd]
	} else if fenceStart >= 0 {
		s = s[fenceStart:]
	}

	return strings.TrimSpace(s)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
