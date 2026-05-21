// vncrfb.go — host-side VNC RFB protocol decoder Spec. Wraps
// the internal/vncrfb walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/vncrfb"
)

func init() { //nolint:gochecknoinits
	Register(vncRFBDecodeSpec)
}

var vncRFBDecodeSpec = Spec{
	Name: "vnc_rfb_decode",
	Description: "Decode a VNC RFB (Remote Framebuffer) Protocol handshake " +
		"fragment per RFC 6143 plus the RealVNC / TightVNC / VeNCrypt / " +
		"Apple ARD extensions. TCP/5900-5999 default (display offset = " +
		"port - 5900); TCP/5800-5899 Java applet HTTP wrapper; TCP/6000-" +
		"6063 X11 (separate protocol). Universal remote-access pentest " +
		"target — RealVNC / TightVNC / TigerVNC / UltraVNC / x11vnc / " +
		"Vino (GNOME) / KRfb (KDE) / Apple Remote Desktop (macOS built-" +
		"in TCP/5900) / embedded device VNC (printers, ATMs, industrial " +
		"HMIs, KVM-over-IP boxes Raritan / Avocent / iLO / iDRAC / IPMI " +
		"BMC, digital signage, DVR / NVR) / cloud-managed VNC consoles " +
		"(AWS Workspaces, Azure Bastion, GCP VM serial-console-over-" +
		"VNC). The wire format leaks (all pre-auth — observed by passive " +
		"TCP capture of first ~100 bytes): **RFB version banner via " +
		"ProtocolVersion handshake** (server sends 12-byte ASCII " +
		"\"RFB 003.NNN\\n\" — reveals software class: 003.008 = RFC-6143 " +
		"conformant RealVNC 5+; 003.007 = legacy TightVNC 1.x; 003.003 " +
		"= very legacy single-type-only); **security-type enumeration " +
		"via security types list** (RFB 3.7+ sends 1-byte count + N " +
		"security-type bytes; RFB 3.3 sends single 4-byte type): 0 " +
		"Invalid (followed by reason); **1 None = NO AUTHENTICATION " +
		"REQUIRED, exposed! Shodan finds tens of thousands of internet-" +
		"exposed VNC with type=1**; **2 VNC Authentication = weak 8-" +
		"byte truncated DES challenge, offline-crackable hashcat mode " +
		"26200 / john --format=vnc**; 5 RA2 / 6 RA2ne RealVNC " +
		"proprietary; 16 Tight; 17 Ultra UltraVNC MS-Logon; 18 TLS " +
		"(encryption only); 19 VeNCrypt (multi-mechanism — sub-types " +
		"256 PLAIN cleartext / 257-263 TLS+X509 variants — **256 PLAIN " +
		"over unencrypted VeNCrypt session = cleartext credential " +
		"capture**); 20 SASL (GSSAPI Kerberos / DIGEST-MD5 / PLAIN / " +
		"EXTERNAL / CRAM-MD5); 21 MD5 hash UltraVNC MS-Logon II; 22 xvp " +
		"Xen; **30 Apple Diffie-Hellman = macOS built-in ARD**; " +
		"**brute-force feedback via SecurityResult Failed reason** " +
		"(RFB 3.8 + SecurityResult=1 followed by length-prefixed reason " +
		"string \"Authentication failure\" / \"Too many attempts\" — " +
		"hydra vnc / medusa vnc / ncrack vnc consume directly); " +
		"**hostname disclosure via ServerInit desktop name** (length-" +
		"prefixed UTF-8 name often leaks: \"<USER>'s Mac\" macOS ARD; " +
		"machine hostname \"ubuntu-server.local\" / \"dc01.corp.example." +
		"com\"; TigerVNC default \"desktop.local:1\"); **display " +
		"resolution + pixel-format fingerprinting** (framebuffer-width " +
		"× height + bpp/depth/true-colour-flag/RGB max+shift). " +
		"Decodes:\n\n" +
		"- **12-byte ProtocolVersion banner detection** — ASCII \"RFB " +
		"003.NNN\\n\" pattern. Surfaces `is_version_banner` boolean + " +
		"`protocol_version` (e.g. \"003.008\").\n" +
		"- **RFB 3.7+ security-types list walker** — 1-byte count + N " +
		"security-type bytes. Surfaces `security_types` array + " +
		"`security_types_names` with vulnerability classification (none-" +
		"auth flagging, VNC-auth weak flagging, ARD detection).\n" +
		"- **RFB 3.3 single 4-byte security-type walker** — surfaces " +
		"same fields with `is_rfb_3_3` boolean. Discrimination: when " +
		"input is exactly 4 bytes and value is 0 or 1, decoder prefers " +
		"the SecurityResult interpretation (modern common case); " +
		"explicit RFB 3.3 captures have value ≥ 2.\n" +
		"- **Security-type Invalid (0) reason walker** — when server " +
		"sends a single Invalid security type, follows with length-" +
		"prefixed reason string; surfaces `security_invalid_reason`.\n" +
		"- **SecurityResult walker** — 4-byte BE status (0=OK / " +
		"1=Failed); on RFB 3.8+ Failed, follows with length-prefixed " +
		"reason string. Surfaces `security_result` + " +
		"`security_result_failed` boolean + `security_failure_reason`.\n" +
		"- **ServerInit walker** — framebuffer-width (2 BE) + " +
		"framebuffer-height (2 BE) + 16-byte pixel-format + 4-byte BE " +
		"name-length + name-string. Surfaces `framebuffer_width` + " +
		"`framebuffer_height` + `bits_per_pixel` + `depth` + " +
		"`big_endian_flag` + `true_colour_flag` + `desktop_name` " +
		"(hostname disclosure!).\n" +
		"- **13-entry security-type name table** with vulnerability " +
		"classification: 0 Invalid / **1 None (NO AUTHENTICATION " +
		"REQUIRED!)** / **2 VNC Authentication (weak DES — hashcat mode " +
		"26200)** / 5 RA2 / 6 RA2ne / 16 Tight / 17 Ultra / 18 TLS / 19 " +
		"VeNCrypt (multi-mechanism) / 20 SASL / 21 MD5 hash UltraVNC " +
		"MS-Logon II / 22 xvp (Xen) / **30 Apple Diffie-Hellman (Apple " +
		"Remote Desktop)**.\n\n" +
		"Pure offline parser — operators paste VNC bytes (the TCP-" +
		"segment payload as hex; default TCP/5900-5999) from a `tcpdump " +
		"-X port 5900` line or a Wireshark RFB dissector view and get " +
		"the documented per-message breakdown. Decoder auto-discriminates " +
		"between ProtocolVersion banner / security-types list / " +
		"SecurityResult / ServerInit by inspecting the leading bytes; " +
		"call one fragment at a time.\n\n" +
		"Out of scope (deferred): framebuffer update encodings (Raw / " +
		"CopyRect / RRE / CoRRE / Hextile / Zlib / Tight / ZRLE / TRLE " +
		"/ ZRLEE / TightPNG / 30+ pseudo-encodings cursor / desktop " +
		"size / xCursor / richCursor / pointerPos / extendedDesktopSize " +
		"— each its own format); mouse + keyboard event PDUs " +
		"(PointerEvent / KeyEvent / ClientCutText / SetEncodings / " +
		"FramebufferUpdateRequest); **VNC password decryption** " +
		"(DELIBERATELY OMITTED — VNC Authentication challenge + response " +
		"requires offline hashcat mode 26200 / john --format=vnc; the " +
		"decoder surfaces the byte boundaries but does NOT crack the " +
		"password); VeNCrypt sub-handshake (TLS + sub-type selection " +
		"from 256-263 range; X509* sub-types require X.509 client/" +
		"server cert exchange); SASL mechanism inner-decode (GSSAPI " +
		"Kerberos via `kerberos_decode`; DIGEST-MD5 / CRAM-MD5 / PLAIN " +
		"deferred); Apple ARD DH key exchange details (1024-bit DH " +
		"modulus + generator + MD5 of shared secret for password " +
		"encryption — parsed for detection only); TightVNC sub-auth " +
		"list (additional capability exchange after Tight type 16 " +
		"selected); HTTP-tunneled VNC (TCP/5800-5899 Java applet " +
		"wrapper — handle HTTP layer separately).\n\n" +
		"Source: docs/catalog/gap-analysis.md (remote-access pentest " +
		"foundational decoder — canonical VNC RFB dissector for " +
		"security-type enumeration + None auth detection + VNC DES " +
		"weak-auth flagging + Apple ARD detection + ServerInit " +
		"hostname disclosure; pairs with `rdp_x224_decode` for the " +
		"complete remote-access pentest surface; common in DEF CON + " +
		"Black Hat + HITB + OffSec engagements + every nmap vnc-* NSE " +
		"/ metasploit auxiliary/scanner/vnc / hydra vnc / medusa vnc / " +
		"ncrack vnc-driven VNC attack workflow). Wrap-vs-native: native " +
		"— RFC 6143 is publicly available; handshake wire format is a " +
		"deterministic sequence of fixed-shape or length-prefixed " +
		"records; auto-discrimination between message kinds by leading-" +
		"byte inspection; framebuffer encodings + event PDUs + password " +
		"decryption + VeNCrypt sub-handshake + SASL inner-decode + ARD " +
		"DH exchange + TightVNC sub-auth list deliberately out of scope; " +
		"no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"VNC RFB handshake fragment bytes as hex (the TCP-segment payload; default TCP/5900-5999). Feed one message at a time; decoder auto-discriminates between ProtocolVersion banner, security-types list, SecurityResult, and ServerInit. Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   vncRFBDecodeHandler,
}

func vncRFBDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("vnc_rfb_decode: 'hex' is required")
	}
	res, err := vncrfb.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("vnc_rfb_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
