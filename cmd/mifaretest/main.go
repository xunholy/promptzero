// mifaretest exercises the realistic Mifare workflow against a tag held to
// the real Flipper: detect → inspect existing fixtures → dump protocol → save
// a UID-only file → diff vs an existing file → edit → emulate → cleanup.
// Each phase has its own per-call timeout so a stalled subshell can't hang
// the whole run. Walks the same shape a user would drive through the agent,
// but via direct MCP calls so we exercise the primitive surface.
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

type mcpClient struct {
	c *client.Client
}

func (m *mcpClient) call(ctx context.Context, name string, args map[string]any, timeout time.Duration) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req := mcplib.CallToolRequest{}
	req.Params.Name = name
	req.Params.Arguments = args
	res, err := m.c.CallTool(cctx, req)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, content := range res.Content {
		if tc, ok := content.(mcplib.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	if res.IsError {
		return sb.String(), fmt.Errorf("tool returned IsError")
	}
	return sb.String(), nil
}

type phase struct {
	name string
	run  func(ctx context.Context, m *mcpClient, st *state) error
}

type state struct {
	uid          string
	atqa         string
	sak          string
	tagType      string
	originalFile string // existing fixture we read for the diff
	originalBody string
	newFile      string
	newBody      string
	dumpedFile   string // /ext/nfc/dump-YYYYMMDD-HHMMSS.nfc auto-saved by phaseDumpProtocol
}

func summary(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " ⏎ "))
	if len(s) > 200 {
		s = s[:197] + "..."
	}
	return s
}

func main() {
	var (
		binPath     = flag.String("bin", "./bin/promptzero", "promptzero binary")
		port        = flag.String("port", "/dev/ttyACM0", "Flipper serial port")
		fixturePath = flag.String("fixture", "/ext/nfc/Test.nfc", "existing .nfc file used as a diff baseline + edit template")
		emulate     = flag.Bool("emulate", true, "exercise nfc_emulate (slow — 20s+ for loader teardown)")
	)
	flag.Parse()

	st := &state{originalFile: *fixturePath}

	phases := []phase{
		{"detect", phaseDetect},
		{"list_existing_nfc_files", phaseListNFC},
		{"read_existing_fixture", phaseReadFixture},
		{"parse_existing_fixture", phaseParseFixture},
		{"dump_protocol_classic", phaseDumpProtocol},
		{"build_and_write_uid_clone", phaseWriteClone},
		{"read_back_clone", phaseReadBack},
		{"parse_clone", phaseParseClone},
		{"diff_clone_vs_original", phaseDiffClone},
		{"edit_clone_uid", phaseEditClone},
		{"verify_edit_applied", phaseVerifyEdit},
	}
	if *emulate {
		phases = append(phases, phase{"emulate_clone", phaseEmulate})
	}
	phases = append(phases, phase{"cleanup", phaseCleanup})

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
	var ir mcplib.InitializeRequest
	ir.Params.ProtocolVersion = mcplib.LATEST_PROTOCOL_VERSION
	ir.Params.ClientInfo = mcplib.Implementation{Name: "promptzero-mifaretest", Version: "0"}
	if _, err := c.Initialize(initCtx, ir); err != nil {
		initCancel()
		fmt.Fprintf(os.Stderr, "initialize: %v\n", err)
		os.Exit(1)
	}
	initCancel()

	m := &mcpClient{c: c}

	pass, fail := 0, 0
	for i, p := range phases {
		fmt.Printf("──── phase %d/%d: %s ────\n", i+1, len(phases), p.name)
		start := time.Now()
		err := p.run(ctx, m, st)
		dur := time.Since(start).Round(time.Millisecond)
		if err != nil {
			fmt.Printf("FAIL  (%s)  %v\n\n", dur, err)
			fail++
			// Stop on first hard failure that would invalidate later phases,
			// but allow cleanup to still try.
			if p.name != "cleanup" && i < len(phases)-1 {
				fmt.Printf("──── short-circuiting; running cleanup only ────\n")
				_ = phaseCleanup(ctx, m, st)
				break
			}
			continue
		}
		pass++
		fmt.Printf("PASS  (%s)\n\n", dur)
	}

	fmt.Printf("# %d phases pass, %d fail\n", pass, fail)
	if fail > 0 {
		os.Exit(1)
	}
}

func phaseDetect(ctx context.Context, m *mcpClient, st *state) error {
	out, err := m.call(ctx, "nfc_detect", map[string]any{"timeout_seconds": 5}, 20*time.Second)
	if err != nil {
		return fmt.Errorf("nfc_detect: %v — %s", err, summary(out))
	}
	fmt.Printf("    raw: %s\n", summary(out))
	st.uid = extractField(out, "UID:")
	st.atqa = extractField(out, "ATQA:")
	st.sak = extractField(out, "SAK:")
	st.tagType = extractField(out, "Type:")
	if st.tagType == "" {
		// Momentum format: "Protocols detected: Mifare Classic"
		st.tagType = strings.TrimSpace(strings.TrimPrefix(extractField(out, "Protocols detected:"), "Protocols detected:"))
	}
	fmt.Printf("    parsed UID=%q ATQA=%q SAK=%q Type=%q\n", st.uid, st.atqa, st.sak, st.tagType)
	if st.uid == "" && !strings.Contains(strings.ToLower(out), "mifare") {
		return fmt.Errorf("no UID and no protocol identification — is the tag held to the NFC face of the Flipper?")
	}
	return nil
}

func phaseListNFC(ctx context.Context, m *mcpClient, _ *state) error {
	out, err := m.call(ctx, "storage_list", map[string]any{"path": "/ext/nfc"}, 10*time.Second)
	if err != nil {
		return err
	}
	fmt.Printf("    %s\n", summary(out))
	return nil
}

func phaseReadFixture(ctx context.Context, m *mcpClient, st *state) error {
	out, err := m.call(ctx, "storage_read", map[string]any{"path": st.originalFile}, 10*time.Second)
	if err != nil {
		return err
	}
	st.originalBody = stripStorageReadHeader(out)
	if st.originalBody == "" {
		return fmt.Errorf("empty file body — is %s missing?", st.originalFile)
	}
	fmt.Printf("    %d bytes loaded from %s\n", len(st.originalBody), st.originalFile)
	return nil
}

func phaseParseFixture(ctx context.Context, m *mcpClient, st *state) error {
	out, err := m.call(ctx, "fileformat_read", map[string]any{"path": st.originalFile}, 10*time.Second)
	if err != nil {
		return fmt.Errorf("fileformat_read: %v — %s", err, summary(out))
	}
	fmt.Printf("    %s\n", summary(out))
	if !strings.Contains(out, `"filetype"`) && !strings.Contains(out, "Filetype") {
		return fmt.Errorf("fileformat_read returned no filetype field — parser broken?")
	}
	return nil
}

func phaseDumpProtocol(ctx context.Context, m *mcpClient, st *state) error {
	// Mifare Classic with no known keys typically dumps UID + sector 0
	// only. The Momentum dump verb writes a file as a side effect; we
	// capture its path so the cleanup phase can delete it.
	out, err := m.call(ctx, "nfc_dump_protocol", map[string]any{"protocol": "Mifare_Classic", "timeout_seconds": 8}, 30*time.Second)
	if err != nil {
		return fmt.Errorf("nfc_dump_protocol: %v — %s", err, summary(out))
	}
	fmt.Printf("    %s\n", summary(out))
	st.dumpedFile = extractDumpedPath(out)
	if st.dumpedFile != "" {
		fmt.Printf("    auto-saved dump: %s (will be cleaned up)\n", st.dumpedFile)
	}
	return nil
}

// extractDumpedPath pulls the path out of the Momentum banner
// `Dump saved to '/ext/nfc/dump-YYYYMMDD-HHMMSS.nfc'`. Returns "" if
// the banner shape isn't present.
func extractDumpedPath(out string) string {
	const marker = "Dump saved to '"
	i := strings.Index(out, marker)
	if i < 0 {
		return ""
	}
	rest := out[i+len(marker):]
	j := strings.Index(rest, "'")
	if j < 0 {
		return ""
	}
	return rest[:j]
}

func phaseWriteClone(ctx context.Context, m *mcpClient, st *state) error {
	// Take the existing fixture and rewrite the UID line with the freshly
	// detected UID. Same file shape the agent's nfc_read_save would build.
	body := st.originalBody
	if st.uid != "" {
		body = replaceField(body, "UID", st.uid)
	}
	st.newFile = fmt.Sprintf("/ext/nfc/promptzero_mifaretest_%d.nfc", time.Now().Unix())
	st.newBody = body

	out, err := m.call(ctx, "storage_write", map[string]any{"path": st.newFile, "content": body}, 30*time.Second)
	if err != nil {
		return fmt.Errorf("storage_write: %v — %s", err, summary(out))
	}
	fmt.Printf("    wrote %d bytes to %s (%s)\n", len(body), st.newFile, summary(out))
	return nil
}

func phaseReadBack(ctx context.Context, m *mcpClient, st *state) error {
	out, err := m.call(ctx, "storage_read", map[string]any{"path": st.newFile}, 10*time.Second)
	if err != nil {
		return err
	}
	body := stripStorageReadHeader(out)
	if body != st.newBody {
		return fmt.Errorf("read-back mismatch: wrote %d bytes, read %d bytes", len(st.newBody), len(body))
	}
	fmt.Printf("    round-trip clean: %d bytes match exactly\n", len(body))
	return nil
}

func phaseParseClone(ctx context.Context, m *mcpClient, st *state) error {
	out, err := m.call(ctx, "fileformat_read", map[string]any{"path": st.newFile}, 10*time.Second)
	if err != nil {
		return fmt.Errorf("fileformat_read: %v — %s", err, summary(out))
	}
	fmt.Printf("    %s\n", summary(out))
	if st.uid != "" {
		// The parsed JSON should mention the new UID we wrote.
		needle := strings.ReplaceAll(strings.ToUpper(st.uid), " ", "")
		if !strings.Contains(strings.ToUpper(strings.ReplaceAll(out, " ", "")), needle) {
			return fmt.Errorf("parsed clone does not contain new UID %q", st.uid)
		}
	}
	return nil
}

func phaseDiffClone(ctx context.Context, m *mcpClient, st *state) error {
	out, err := m.call(ctx, "fileformat_diff", map[string]any{"path_a": st.originalFile, "path_b": st.newFile}, 10*time.Second)
	if err != nil {
		return fmt.Errorf("fileformat_diff: %v — %s", err, summary(out))
	}
	fmt.Printf("    %s\n", summary(out))
	return nil
}

func phaseEditClone(ctx context.Context, m *mcpClient, st *state) error {
	// fileformat_edit takes a top-level edits map. Rewrite the UID to a
	// recognisable canary so the next phase can verify the edit took.
	canary := "DE AD BE EF"
	out, err := m.call(ctx, "fileformat_edit", map[string]any{
		"path":  st.newFile,
		"edits": map[string]any{"UID": canary},
	}, 15*time.Second)
	if err != nil {
		return fmt.Errorf("fileformat_edit: %v — %s", err, summary(out))
	}
	fmt.Printf("    %s\n", summary(out))
	return nil
}

func phaseVerifyEdit(ctx context.Context, m *mcpClient, st *state) error {
	out, err := m.call(ctx, "storage_read", map[string]any{"path": st.newFile}, 10*time.Second)
	if err != nil {
		return err
	}
	body := stripStorageReadHeader(out)
	if !strings.Contains(strings.ReplaceAll(strings.ToUpper(body), " ", ""), "DEADBEEF") {
		return fmt.Errorf("edit did not take: file does not contain DEADBEEF after fileformat_edit")
	}
	fmt.Printf("    canary UID DEADBEEF present after edit ✓\n")
	return nil
}

func phaseEmulate(ctx context.Context, m *mcpClient, st *state) error {
	// NFCEmulate takes ~3-23 seconds because it has to wait for the loader
	// to release after the back-button shutdown. We don't need a reader to
	// be present — we're verifying the launch + clean teardown path.
	out, err := m.call(ctx, "nfc_emulate", map[string]any{"file": st.newFile}, 60*time.Second)
	if err != nil {
		return fmt.Errorf("nfc_emulate: %v — %s", err, summary(out))
	}
	fmt.Printf("    %s\n", summary(out))
	return nil
}

func phaseCleanup(ctx context.Context, m *mcpClient, st *state) error {
	deleted := 0
	for _, p := range []string{st.newFile, st.dumpedFile} {
		if p == "" {
			continue
		}
		out, err := m.call(ctx, "storage_delete", map[string]any{"path": p}, 10*time.Second)
		if err != nil {
			fmt.Printf("    delete %s: %v\n", p, err)
			continue
		}
		fmt.Printf("    deleted %s (%s)\n", p, summary(out))
		deleted++
	}
	if deleted == 0 {
		fmt.Println("    nothing to clean")
	}
	return nil
}

// --- helpers ---

// extractField returns the trimmed value following the first occurrence of
// key on its own line. Returns "" if absent.
func extractField(text, key string) string {
	for _, line := range strings.Split(text, "\n") {
		idx := strings.Index(line, key)
		if idx < 0 {
			continue
		}
		return strings.TrimSpace(line[idx+len(key):])
	}
	return ""
}

// replaceField rewrites a "Key: value" line in a Flipper key-value file.
// Append a new line if the key is absent. Preserves the rest of the file
// byte-for-byte.
func replaceField(body, key, value string) string {
	prefix := key + ":"
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) {
			lines[i] = key + ": " + value
			return strings.Join(lines, "\n")
		}
	}
	return body + "\n" + key + ": " + value + "\n"
}

// stripStorageReadHeader removes the "Size: N\n" prefix the Flipper's
// storage_read prepends. Body bytes follow on the next line.
func stripStorageReadHeader(out string) string {
	out = strings.TrimLeft(out, "\r\n")
	if idx := strings.Index(out, "\n"); idx >= 0 {
		first := out[:idx]
		if strings.HasPrefix(strings.TrimSpace(first), "Size:") {
			return out[idx+1:]
		}
	}
	return out
}

var _ = json.Marshal // silence unused import in case we ever switch outputs
