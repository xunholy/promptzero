// Package lnk decodes a Windows Shell Link (.lnk) and flags the command it runs.
//
// Malicious .lnk files are a top modern delivery vector: since Microsoft began
// blocking macros, phishing and USB-drop campaigns (Qbot, IcedID, Emotet, …)
// ship a benign-looking shortcut whose hidden command-line arguments launch
// powershell / mshta / rundll32 to stage the payload. The analyst question is
// "what does this shortcut actually run?" — this parses the documented
// [MS-SHLLINK] structure offline and surfaces the link flags, the show command,
// the StringData (name / relative path / working dir / COMMAND-LINE ARGUMENTS /
// icon), any LinkInfo local target path and EnvironmentVariableDataBlock target,
// and flags the LOLBins / techniques in the arguments.
//
// No confidently-wrong output: the file is recognised only by its 0x0000004C
// HeaderSize and the {00021401-…46} LinkCLSID; every offset/length is
// bounds-checked; an optional section that does not fit is skipped rather than
// over-read; and the "suspicious" flag is a labelled indicator scan (a clean
// scan is not a guarantee of safety). The shell-item IDList is skipped (its
// target often lives there in shell-encoded form, noted), not mis-decoded.
//
// Wrap-vs-native: native — a bounds-checked binary walk of [MS-SHLLINK]; stdlib
// only, no new go.mod dependency. Anchored to real pylnk3-generated shortcuts
// cross-decoded with LnkParse3 (see the package test).
package lnk

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

// linkCLSID is the Shell Link CLSID {00021401-0000-0000-C000-000000000046}.
var linkCLSID = []byte{ //nolint:gochecknoglobals
	0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
}

// flagNames maps each LinkFlags bit to its [MS-SHLLINK] 2.1.1 name.
var flagNames = []string{ //nolint:gochecknoglobals
	"HasLinkTargetIDList", "HasLinkInfo", "HasName", "HasRelativePath",
	"HasWorkingDir", "HasArguments", "HasIconLocation", "IsUnicode",
	"ForceNoLinkInfo", "HasExpString", "RunInSeparateProcess", "Unused1",
	"HasDarwinID", "RunAsUser", "HasExpIcon", "NoPidlAlias",
	"Unused2", "RunWithShimLayer", "ForceNoLinkTrack", "EnableTargetMetadata",
	"DisableLinkPathTracking", "DisableKnownFolderTracking", "DisableKnownFolderAlias",
	"AllowLinkToLink", "UnaliasOnSave", "PreferEnvironmentPath", "KeepLocalIDListForUNCTarget",
}

// Result is the decoded shortcut.
type Result struct {
	Format       string   `json:"format"`
	LinkFlags    []string `json:"link_flags"`
	ShowCommand  string   `json:"show_command"`
	Name         string   `json:"name,omitempty"`
	RelativePath string   `json:"relative_path,omitempty"`
	WorkingDir   string   `json:"working_dir,omitempty"`
	Arguments    string   `json:"arguments,omitempty"`
	IconLocation string   `json:"icon_location,omitempty"`
	// TargetPath is the LinkInfo LocalBasePath when present (the IDList target is
	// skipped — see TargetNote).
	TargetPath string `json:"target_path,omitempty"`
	// EnvTarget is the EnvironmentVariableDataBlock target (often the real
	// payload path, with %env% expansion).
	EnvTarget string `json:"env_target,omitempty"`

	Suspicious        bool     `json:"suspicious"`
	SuspiciousReasons []string `json:"suspicious_reasons,omitempty"`
	Note              string   `json:"note"`
}

const headerSize = 0x4C

// Decode parses a .lnk byte stream.
func Decode(data []byte) (*Result, error) {
	if len(data) < headerSize {
		return nil, fmt.Errorf("lnk: %d bytes < %d-byte ShellLinkHeader", len(data), headerSize)
	}
	if binary.LittleEndian.Uint32(data[0:4]) != headerSize {
		return nil, fmt.Errorf("lnk: bad HeaderSize (not 0x4C) — not a Shell Link")
	}
	if !bytes.Equal(data[4:20], linkCLSID) {
		return nil, fmt.Errorf("lnk: bad LinkCLSID — not a Shell Link")
	}

	flags := binary.LittleEndian.Uint32(data[20:24])
	res := &Result{
		Format:      "lnk",
		LinkFlags:   decodeFlags(flags),
		ShowCommand: showCommand(binary.LittleEndian.Uint32(data[60:64])),
	}

	r := &cursor{b: data, pos: headerSize}
	unicode := flags&(1<<7) != 0

	// LinkTargetIDList (skipped — the target there is shell-item-encoded).
	if flags&(1<<0) != 0 {
		if n, ok := r.u16(); ok {
			r.skip(int(n))
		}
	}
	// LinkInfo — extract the local target path when present.
	if flags&(1<<1) != 0 && flags&(1<<8) == 0 {
		res.TargetPath = r.linkInfo()
	}
	// StringData, in [MS-SHLLINK] order.
	if flags&(1<<2) != 0 {
		res.Name = r.stringData(unicode)
	}
	if flags&(1<<3) != 0 {
		res.RelativePath = r.stringData(unicode)
	}
	if flags&(1<<4) != 0 {
		res.WorkingDir = r.stringData(unicode)
	}
	if flags&(1<<5) != 0 {
		res.Arguments = r.stringData(unicode)
	}
	if flags&(1<<6) != 0 {
		res.IconLocation = r.stringData(unicode)
	}
	// ExtraData — pull the EnvironmentVariableDataBlock target if present.
	res.EnvTarget = r.extraDataEnvTarget()

	res.SuspiciousReasons = scanSuspicious(res)
	res.Suspicious = len(res.SuspiciousReasons) > 0
	res.Note = noteFor(res)
	return res, nil
}

func decodeFlags(f uint32) []string {
	var out []string
	for i, name := range flagNames {
		if f&(1<<uint(i)) != 0 {
			out = append(out, name)
		}
	}
	return out
}

func showCommand(v uint32) string {
	switch v {
	case 0x1:
		return "SW_SHOWNORMAL"
	case 0x3:
		return "SW_SHOWMAXIMIZED"
	case 0x7:
		return "SW_SHOWMINNOACTIVE"
	default:
		return fmt.Sprintf("SW_SHOWNORMAL (0x%x)", v)
	}
}

// lolbins / techniques flagged in the command line.
var indicators = []string{ //nolint:gochecknoglobals
	"powershell", "pwsh", "cmd.exe", "cmd /c", "cmd /k", "mshta", "rundll32",
	"regsvr32", "wscript", "cscript", "bitsadmin", "certutil", "msbuild",
	"installutil", "forfiles", "schtasks", "wmic", "curl", "wget",
	"-enc", "-encodedcommand", "-nop", "-noprofile", "-w hidden", "-windowstyle hidden",
	"hidden", "downloadstring", "downloadfile", "invoke-expression", "iex",
	"frombase64string", "http://", "https://", "ftp://", ".hta", ".ps1", ".vbs",
	".js", ".scr", ".bat", "\\\\", "start-process", "new-object",
}

func scanSuspicious(res *Result) []string {
	hay := strings.ToLower(res.Arguments + "\x00" + res.IconLocation + "\x00" + res.TargetPath + "\x00" + res.EnvTarget)
	var hits []string
	seen := map[string]bool{}
	for _, ind := range indicators {
		if strings.Contains(hay, ind) && !seen[ind] {
			seen[ind] = true
			hits = append(hits, ind)
		}
	}
	return hits
}

func noteFor(res *Result) string {
	base := "Offline parse only — the shortcut was not run. "
	if res.Suspicious {
		return base + "SUSPICIOUS: the command line uses a known LOLBin / staging technique (" +
			strings.Join(res.SuspiciousReasons, ", ") + "). Review before trusting this .lnk."
	}
	return base + "No known LOLBin / staging indicator found in the command line — not a guarantee of safety " +
		"(the target may live in the shell-item IDList, which is not decoded here)."
}

// --- cursor ---------------------------------------------------------------

type cursor struct {
	b   []byte
	pos int
}

func (c *cursor) remaining() int { return len(c.b) - c.pos }

func (c *cursor) skip(n int) {
	if n < 0 || n > c.remaining() {
		c.pos = len(c.b)
		return
	}
	c.pos += n
}

func (c *cursor) u16() (uint16, bool) {
	if c.remaining() < 2 {
		return 0, false
	}
	v := binary.LittleEndian.Uint16(c.b[c.pos:])
	c.pos += 2
	return v, true
}

// stringData reads a CountCharacters-prefixed StringData value.
func (c *cursor) stringData(unicode bool) string {
	n, ok := c.u16()
	if !ok {
		return ""
	}
	width := 1
	if unicode {
		width = 2
	}
	need := int(n) * width
	if need > c.remaining() {
		need = c.remaining()
	}
	raw := c.b[c.pos : c.pos+need]
	c.pos += need
	if unicode {
		u := make([]uint16, len(raw)/2)
		for i := range u {
			u[i] = binary.LittleEndian.Uint16(raw[i*2:])
		}
		return string(utf16.Decode(u))
	}
	// ANSI: treat as latin-1.
	sb := make([]rune, len(raw))
	for i, b := range raw {
		sb[i] = rune(b)
	}
	return string(sb)
}

// linkInfo parses the LinkInfo block, returning the LocalBasePath when present,
// and advances past the whole block.
func (c *cursor) linkInfo() string {
	start := c.pos
	if c.remaining() < 4 {
		return ""
	}
	size := int(binary.LittleEndian.Uint32(c.b[c.pos:]))
	if size < 4 || size > c.remaining() {
		c.pos = len(c.b)
		return ""
	}
	block := c.b[start : start+size]
	c.pos = start + size
	var path string
	if len(block) >= 20 {
		flags := binary.LittleEndian.Uint32(block[8:12])
		if flags&0x1 != 0 { // VolumeIDAndLocalBasePath
			off := int(binary.LittleEndian.Uint32(block[16:20]))
			if off > 0 && off < len(block) {
				path = cString(block[off:])
			}
		}
	}
	return path
}

// extraDataEnvTarget walks the ExtraData blocks and returns the
// EnvironmentVariableDataBlock target (Unicode preferred), or "".
func (c *cursor) extraDataEnvTarget() string {
	for c.remaining() >= 8 {
		size := int(binary.LittleEndian.Uint32(c.b[c.pos:]))
		if size < 4 || size > c.remaining() {
			return "" // terminal block / malformed
		}
		block := c.b[c.pos : c.pos+size]
		c.pos += size
		sig := binary.LittleEndian.Uint32(block[4:8])
		if sig == 0xA0000001 && len(block) >= 8+260+520 { // EnvironmentVariableDataBlock
			if u := utf16z(block[8+260 : 8+260+520]); u != "" {
				return u
			}
			return cString(block[8 : 8+260])
		}
	}
	return ""
}

// cString reads a NUL-terminated ANSI string.
func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	sb := make([]rune, len(b))
	for i, x := range b {
		sb[i] = rune(x)
	}
	return string(sb)
}

// utf16z reads a NUL-terminated UTF-16LE string from a fixed buffer.
func utf16z(b []byte) string {
	var u []uint16
	for i := 0; i+1 < len(b); i += 2 {
		v := binary.LittleEndian.Uint16(b[i:])
		if v == 0 {
			break
		}
		u = append(u, v)
	}
	return string(utf16.Decode(u))
}
