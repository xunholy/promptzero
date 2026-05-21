// Package vncrfb decodes VNC RFB (Remote Framebuffer) Protocol
// handshake messages per RFC 6143 plus the RealVNC / TightVNC /
// VeNCrypt / Apple ARD extensions. Runs on TCP/5900-5999 default
// (display offset = port - 5900); TCP/5800-5899 is the Java
// applet HTTP wrapper; TCP/6000-6063 X11 (separate protocol).
//
// Operationally, VNC is a **universal remote-access pentest
// target** — deployed everywhere:
//
//   - **Server / workstation remote-access**: RealVNC,
//     TightVNC, TigerVNC, UltraVNC, x11vnc, Vino (GNOME),
//     KRfb (KDE), TigerVNC Server bundled in every modern
//     Linux distro for headless console access.
//
//   - **Apple Remote Desktop (ARD)** — macOS built-in VNC
//     server on TCP/5900; uses the security type 30 (Apple
//     Diffie-Hellman) for password-based auth, falls back
//     to standard VNC auth.
//
//   - **Embedded device VNC** — printers, ATMs, industrial
//     HMIs, KVM-over-IP boxes (Raritan / Avocent / iLO /
//     iDRAC / IPMI BMC), digital signage controllers,
//     network DVRs / NVRs. Many ship with default
//     passwords or no auth at all.
//
//   - **Cloud-managed VNC consoles** — AWS Workspaces VNC
//     access, Azure Bastion VM console, GCP VM serial-
//     console-over-VNC.
//
// The wire format leaks (all pre-auth — observed by passive
// TCP capture of the first ~100 bytes):
//
//   - **RFB version banner via ProtocolVersion handshake** —
//     server sends 12 bytes of ASCII as soon as the TCP
//     connection is established: `RFB 003.008\n` (or `003.003`
//     / `003.007` for legacy servers). Client mirrors. The
//     version reveals server software class:
//     `RFB 003.008` = RFC-6143 conformant (RealVNC 5+, most
//     modern); `RFB 003.007` = legacy TightVNC 1.x;
//     `RFB 003.003` = very legacy (only 4-byte security
//     type, no negotiation).
//
//   - **Security-type enumeration via security types list**
//     — after version handshake, the RFB 3.7+ server sends
//     a 1-byte count followed by N security-type bytes
//     (RFB 3.3 sends a single 4-byte type). The list reveals
//     the server's auth-security posture:
//
//   - `0` Invalid — followed by a length-prefixed
//     reason string (the canonical "no compatible auth"
//     response; some servers return this when the client
//     is on a denylist).
//
//   - `1` None — **NO AUTHENTICATION REQUIRED** —
//     anyone can connect. Shodan finds tens of thousands
//     of internet-exposed VNC servers with type=1; the
//     classic "default install never configured" finding.
//
//   - `2` VNC Authentication — **weak 8-byte truncated
//     DES-encrypted challenge**; the VNC password is
//     truncated to 8 bytes, used as a DES key to encrypt
//     a 16-byte random challenge; the encrypted response
//     is observable on the wire and **offline-crackable
//     via hashcat mode 26200 / john --format=vnc**.
//
//   - `5` RA2 / `6` RA2ne — RealVNC proprietary auth.
//
//   - `16` Tight — TightVNC-specific (sub-auth list
//     follows).
//
//   - `17` Ultra — UltraVNC MS-Logon variant.
//
//   - `18` TLS — TLS-wrapped auth (encryption layer only;
//     no client-cert verification typically).
//
//   - `19` VeNCrypt — modern hardened multi-mechanism
//     (sub-types 256 PLAIN cleartext / 257 TLSPlain /
//     258 X509None / 259 X509Plain / 260 X509Vnc / 261
//     TLSVnc / 262 TLSSASL / 263 X509SASL); **256
//     PLAIN over an unencrypted VeNCrypt session is
//     cleartext credential capture**.
//
//   - `20` SASL — SASL negotiation (GSSAPI Kerberos /
//     DIGEST-MD5 / PLAIN / EXTERNAL / CRAM-MD5).
//
//   - `21` MD5 hash — UltraVNC MS-Logon II.
//
//   - `22` xvp — Xen Virtualization Platform.
//
//   - `30` Apple Diffie-Hellman (Apple Remote Desktop) —
//     macOS built-in VNC server's password-based auth
//     using DH key agreement.
//
//   - **Brute-force feedback via SecurityResult Failed
//     reason** — on RFB 3.8 + SecurityResult=1 (Failed),
//     the server sends a length-prefixed reason string
//     (commonly "Authentication failure" / "Too many
//     attempts" / "Failed too many tries"). Password-spray
//     tools (hydra vnc, medusa vnc, ncrack vnc) consume
//     this directly.
//
//   - **Hostname disclosure via ServerInit desktop name** —
//     after successful auth, the server sends a ServerInit
//     PDU containing the framebuffer dimensions + pixel
//     format + a length-prefixed UTF-8 desktop name string.
//     Common defaults: `<USER>'s Mac` (macOS ARD), the
//     machine hostname (`ubuntu-server.local`,
//     `dc01.corp.example.com`), or `<APP NAME> on <host>`
//     (TigerVNC `desktop.local:1`).
//
//   - **Display resolution + pixel-format fingerprinting** —
//     ServerInit framebuffer-width × framebuffer-height
//     (typically 1024×768 / 1920×1080 / 4K) + bpp / depth /
//     true-colour-flag / RGB max/shift; useful for client
//     compatibility matching and for fingerprinting headless
//     server defaults.
//
// Wrap-vs-native judgement
//
//	Native. RFC 6143 is publicly available; the handshake
//	wire format is a deterministic sequence of fixed-shape
//	or length-prefixed records. Framebuffer-update encoding
//	decoding (Raw / CopyRect / RRE / Hextile / TRLE / ZRLE /
//	Tight — 30+ encoding types) is out of scope; mouse +
//	keyboard event PDUs are out of scope; VNC password
//	decryption is deliberately omitted (DES-encrypted
//	challenge requires offline hashcat). VeNCrypt sub-
//	handshake (TLS / X.509) and SASL mechanism inner-decode
//	are out of scope.
//
// What this package covers
//
//   - **12-byte ProtocolVersion banner detection** — ASCII
//     "RFB 003.NNN\n" pattern at the start of the captured
//     bytes. Surfaces `is_version_banner` boolean +
//     `protocol_version` (e.g. "003.008").
//
//   - **RFB 3.7+ security-types list walker** — 1-byte count
//
//   - N security-type bytes. Surfaces `security_types`
//     array + `security_types_names` with vulnerability
//     classification (none-auth flagging; VNC-auth weak
//     flagging; ARD detection).
//
//   - **RFB 3.3 single 4-byte security-type walker** —
//     surfaces same fields with `is_rfb_3_3` boolean.
//
//   - **Security-type Invalid (0) reason walker** — when
//     the server sends a single Invalid security type, the
//     following bytes are a length-prefixed reason string;
//     surfaces `security_invalid_reason`.
//
//   - **SecurityResult walker** — 4-byte BE status (0=OK,
//     1=Failed); on Failed (RFB 3.8+), follows with
//     length-prefixed reason string. Surfaces
//     `security_result` + `security_result_failed` boolean
//
//   - `security_failure_reason`.
//
//   - **ServerInit walker** — framebuffer-width (2 BE) +
//     framebuffer-height (2 BE) + 16-byte pixel-format +
//     4-byte BE name-length + name-string. Surfaces
//     `framebuffer_width` + `framebuffer_height` +
//     `bits_per_pixel` + `depth` + `big_endian_flag` +
//     `true_colour_flag` + `desktop_name` (hostname
//     disclosure!).
//
//   - **13-entry security-type name table** with
//     vulnerability classification: 0 Invalid / 1 None
//     (NO AUTHENTICATION REQUIRED!) / 2 VNC Authentication
//     (weak DES — hashcat mode 26200) / 5 RA2 / 6 RA2ne /
//     16 Tight / 17 Ultra / 18 TLS / 19 VeNCrypt (multi-
//     mechanism) / 20 SASL / 21 MD5 hash / 22 xvp (Xen) /
//     30 Apple Diffie-Hellman (Apple Remote Desktop).
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Framebuffer update encodings** — Raw / CopyRect /
//     RRE / CoRRE / Hextile / Zlib / Tight / ZRLE / TRLE /
//     ZRLEE / TightPNG / 30+ pseudo-encodings (cursor /
//     desktop size / xCursor / richCursor / pointerPos /
//     extendedDesktopSize); each its own format.
//   - **Mouse + keyboard event PDUs** — PointerEvent (5),
//     KeyEvent (4), ClientCutText (6), SetEncodings (2),
//     FramebufferUpdateRequest (3); post-init client → server.
//   - **VNC password decryption** — DELIBERATELY OMITTED.
//     The VNC Authentication challenge is 16 bytes random
//     from server; client returns the challenge DES-
//     encrypted with the (8-byte-truncated) password.
//     Capturing the challenge + response pair allows offline
//     password cracking via hashcat mode 26200 (`vnc_blueprint`)
//     or john --format=vnc; the decoder surfaces the
//     challenge + response byte boundaries via the
//     SecurityResult walker but does NOT crack the password.
//   - **VeNCrypt sub-handshake** — after VeNCrypt (19) is
//     selected, a sub-protocol exchanges TLS handshake +
//     sub-type selection from the 256-263 range; for X509*
//     sub-types, X.509 client/server cert exchange ensues.
//   - **SASL mechanism inner-decode** — security type 20
//     SASL carries a mechanism-list exchange followed by
//     per-mechanism payloads (GSSAPI Kerberos via
//     `kerberos_decode`; DIGEST-MD5 / CRAM-MD5 / PLAIN
//     deferred).
//   - **Apple ARD DH key exchange details** — security
//     type 30 Apple Diffie-Hellman uses a 1024-bit DH
//     modulus + a generator + an MD5 of the shared secret
//     to encrypt the password; the wire exchange is
//     parsed for detection only.
//   - **TightVNC sub-auth list** — after Tight (16) is
//     selected, an additional capability list exchange
//     follows; not decoded.
//   - **HTTP-tunneled VNC (TCP/5800-5899)** — the Java
//     applet wrapper format is HTTP-encapsulated; handle
//     HTTP layer separately.
package vncrfb

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the structured decode of a VNC RFB handshake
// fragment.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// ProtocolVersion banner
	IsVersionBanner bool   `json:"is_version_banner"`
	ProtocolVersion string `json:"protocol_version,omitempty"`

	// Security types
	HasSecurityTypes      bool     `json:"has_security_types"`
	IsRFB33               bool     `json:"is_rfb_3_3"`
	SecurityTypes         []int    `json:"security_types,omitempty"`
	SecurityTypesNames    []string `json:"security_types_names,omitempty"`
	SecurityInvalidReason string   `json:"security_invalid_reason,omitempty"`

	// SecurityResult
	HasSecurityResult     bool   `json:"has_security_result"`
	SecurityResult        int    `json:"security_result,omitempty"`
	SecurityResultFailed  bool   `json:"security_result_failed"`
	SecurityFailureReason string `json:"security_failure_reason,omitempty"`

	// ServerInit
	HasServerInit     bool   `json:"has_server_init"`
	FramebufferWidth  int    `json:"framebuffer_width,omitempty"`
	FramebufferHeight int    `json:"framebuffer_height,omitempty"`
	BitsPerPixel      int    `json:"bits_per_pixel,omitempty"`
	Depth             int    `json:"depth,omitempty"`
	BigEndianFlag     bool   `json:"big_endian_flag"`
	TrueColourFlag    bool   `json:"true_colour_flag"`
	DesktopName       string `json:"desktop_name,omitempty"`
}

// Decode parses a VNC RFB handshake fragment from a hex string.
// The decoder auto-discriminates between the four canonical
// handshake messages by inspecting the leading bytes:
//
//   - 12-byte ASCII "RFB 003.NNN\n" → ProtocolVersion banner
//   - leading 0x00 / 0x00 / 0x00 / 0x01 + 4-byte length →
//     Invalid security type with reason
//   - leading 4-byte BE security type → RFB 3.3 single type
//   - leading 1-byte count + N bytes → RFB 3.7+ types list
//   - leading 4-byte SecurityResult → 0 or 1
//   - leading 2-byte width + 2-byte height + 16-byte pixel
//     format + 4-byte name length + name → ServerInit
//
// In practice, callers feed one message at a time; the decoder
// surfaces whichever message kind it recognizes.
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if len(clean) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex (%d nibbles)", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("empty body")
	}

	r := &Result{TotalBytes: len(b)}

	// 1) ProtocolVersion banner — exactly 12 bytes "RFB NNN.NNN\n"
	if len(b) >= 12 && string(b[0:4]) == "RFB " && b[11] == '\n' {
		r.IsVersionBanner = true
		r.ProtocolVersion = string(b[4:11])
		return r, nil
	}

	// 2) ServerInit — heuristic: 24+ bytes with a plausible
	// name-length at offset 20 that matches len(b)-24
	if len(b) >= 24 {
		nameLen := int(binary.BigEndian.Uint32(b[20:24]))
		if nameLen > 0 && nameLen < 256 && 24+nameLen <= len(b) {
			width := int(binary.BigEndian.Uint16(b[0:2]))
			height := int(binary.BigEndian.Uint16(b[2:4]))
			// Pixel format sanity check: bpp ∈ {8, 16, 32}
			bpp := int(b[4])
			if width > 0 && height > 0 &&
				(bpp == 8 || bpp == 16 || bpp == 32) {
				r.HasServerInit = true
				r.FramebufferWidth = width
				r.FramebufferHeight = height
				r.BitsPerPixel = bpp
				r.Depth = int(b[5])
				r.BigEndianFlag = b[6] != 0
				r.TrueColourFlag = b[7] != 0
				r.DesktopName = string(b[24 : 24+nameLen])
				return r, nil
			}
		}
	}

	// 3) SecurityResult Failed with reason — value=1 + 4-byte
	// length + reason, where reason occupies the rest
	if len(b) >= 8 && binary.BigEndian.Uint32(b[0:4]) == 1 {
		reasonLen := int(binary.BigEndian.Uint32(b[4:8]))
		if reasonLen > 0 && reasonLen < 1024 && 8+reasonLen == len(b) {
			r.HasSecurityResult = true
			r.SecurityResult = 1
			r.SecurityResultFailed = true
			r.SecurityFailureReason = string(b[8 : 8+reasonLen])
			return r, nil
		}
	}

	// 4) RFB 3.7+ Invalid (single 0x00 + 4-byte length + reason
	// where the reason occupies the rest)
	if b[0] == 0x00 && len(b) >= 5 {
		reasonLen := int(binary.BigEndian.Uint32(b[1:5]))
		if reasonLen > 0 && reasonLen < 1024 && 5+reasonLen == len(b) {
			r.HasSecurityTypes = true
			r.SecurityTypes = []int{0}
			r.SecurityTypesNames = []string{securityTypeName(0)}
			r.SecurityInvalidReason = string(b[5 : 5+reasonLen])
			return r, nil
		}
	}

	// 5) SecurityResult OK / Failed — exactly 4 bytes, value 0
	// or 1 (modern preference: SecurityResult wins over RFB 3.3
	// single security type for these values since SecurityResult
	// is the common case in modern traffic; explicit RFB 3.3
	// captures will have value ≥ 2).
	if len(b) == 4 {
		v := int(binary.BigEndian.Uint32(b[0:4]))
		if v == 0 || v == 1 {
			r.HasSecurityResult = true
			r.SecurityResult = v
			r.SecurityResultFailed = v == 1
			return r, nil
		}
		// Otherwise treat as RFB 3.3 single security type
		r.HasSecurityTypes = true
		r.IsRFB33 = true
		r.SecurityTypes = []int{v}
		r.SecurityTypesNames = []string{securityTypeName(v)}
		return r, nil
	}

	// 6) RFB 3.7+ security types list — 1-byte count + N bytes
	count := int(b[0])
	if count > 0 && count < 32 && 1+count <= len(b) {
		r.HasSecurityTypes = true
		for i := 0; i < count; i++ {
			st := int(b[1+i])
			r.SecurityTypes = append(r.SecurityTypes, st)
			r.SecurityTypesNames = append(r.SecurityTypesNames,
				securityTypeName(st))
		}
		return r, nil
	}

	return r, nil
}

func securityTypeName(t int) string {
	switch t {
	case 0:
		return "Invalid (followed by reason string)"
	case 1:
		return "None (NO AUTHENTICATION REQUIRED — exposed!)"
	case 2:
		return "VNC Authentication (weak 8-byte truncated DES — offline-crackable hashcat mode 26200)"
	case 5:
		return "RA2 (RealVNC proprietary)"
	case 6:
		return "RA2ne (RealVNC proprietary)"
	case 16:
		return "Tight (TightVNC sub-auth list follows)"
	case 17:
		return "Ultra (UltraVNC MS-Logon)"
	case 18:
		return "TLS (encryption only; no client-cert verification typically)"
	case 19:
		return "VeNCrypt (multi-mechanism — sub-types 256 PLAIN cleartext / 257-263 TLS/X509 variants)"
	case 20:
		return "SASL (GSSAPI Kerberos / DIGEST-MD5 / PLAIN / EXTERNAL / CRAM-MD5)"
	case 21:
		return "MD5 hash (UltraVNC MS-Logon II)"
	case 22:
		return "xvp (Xen Virtualization Platform)"
	case 30:
		return "Apple Diffie-Hellman (Apple Remote Desktop)"
	case 35:
		return "Mac OS X (alternative ARD form)"
	}
	return fmt.Sprintf("uncatalogued security type %d", t)
}

func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', ':', '-', '_':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
