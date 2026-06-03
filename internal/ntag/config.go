// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ntag decodes the NTAG21x (NTAG213/215/216) configuration pages —
// the registers that control an NFC Type-2 tag's password protection, lock
// state, NFC counter, and UID/counter ASCII-mirror feature. Given a tag dump,
// it answers the operator's first questions about a tag: is it
// password-protected, read+write or write-only, is the configuration
// permanently locked, how many failed password attempts are allowed, and is
// the NFC read counter enabled. The protection-state complement to the t2t
// package (which decodes the Type-2 header / capability container / NDEF).
//
// Input is the two configuration pages CFG0 + CFG1 (8 bytes), optionally
// followed by the PWD and PACK pages (16 bytes total). The NTAG21x config
// pages live at different addresses per variant (29h-2Ch NTAG213, 83h-86h
// NTAG215, E3h-E6h NTAG216) but the layout is identical, so this decodes the
// page bytes regardless of where they were read from.
//
// Wrap-vs-native: native. Fixed bit-field extraction from a handful of bytes;
// no third-party dependency is warranted. The page layout, the MIRROR byte
// (Table 9), the ACCESS byte (Table 10), and every field's value meaning
// (Table 11) are taken verbatim from the NXP NTAG213/215/216 data sheet
// (rev 3.2, section 8.5.7) — verified against the document, not recalled.
//
// Layout (NXP §8.5.7):
//
//	CFG0: byte0 MIRROR, byte1 RFUI, byte2 MIRROR_PAGE, byte3 AUTH0
//	CFG1: byte0 ACCESS, byte1-3 RFUI
//	PWD : 4-byte password (reads as FFs when protected)
//	PACK: byte0-1 PACK, byte2-3 RFUI
//
//	MIRROR byte: b7-6 MIRROR_CONF, b5-4 MIRROR_BYTE, b2 STRG_MOD_EN
//	ACCESS byte: b7 PROT, b6 CFGLCK, b4 NFC_CNT_EN, b3 NFC_CNT_PWD_PROT,
//	             b2-0 AUTHLIM
//
// No confidently-wrong output: an undocumented MIRROR_CONF value (0b11) is
// surfaced as reserved rather than guessed; AUTH0 protection is expressed
// relative to the configured page (the tag's last user page isn't known from
// the config alone, so a disabled-protection AUTH0=0xFF is noted, not asserted
// against a specific memory size).
package ntag

import (
	"encoding/hex"
	"fmt"
	"strings"
)

var mirrorConf = map[int]string{
	0: "no ASCII mirror",
	1: "UID ASCII mirror",
	2: "NFC counter ASCII mirror",
	3: "reserved (0b11)",
}

// Config is a decoded NTAG21x configuration.
type Config struct {
	MirrorConf             string   `json:"mirror_conf"`
	MirrorConfRaw          int      `json:"mirror_conf_raw"`
	MirrorByte             int      `json:"mirror_byte"`
	StrongModulation       bool     `json:"strong_modulation"`
	MirrorPage             int      `json:"mirror_page"`
	Auth0                  int      `json:"auth0"`
	Protection             string   `json:"protection"`
	ConfigLocked           bool     `json:"config_locked"`
	NFCCounterEnabled      bool     `json:"nfc_counter_enabled"`
	NFCCounterPwdProtected bool     `json:"nfc_counter_pwd_protected"`
	AuthLimit              int      `json:"auth_limit"`
	Password               string   `json:"password_hex,omitempty"`
	PACK                   string   `json:"pack_hex,omitempty"`
	Notes                  []string `json:"notes,omitempty"`
}

// DecodeHex decodes hex-encoded config pages (':' / '-' / '_' / whitespace
// separators ignored). 8 bytes = CFG0+CFG1; 16 bytes additionally decodes the
// PWD and PACK pages.
func DecodeHex(s string) (*Config, error) {
	clean := strings.NewReplacer(":", "", "-", "", "_", "", " ", "", "\n", "", "\t", "").Replace(s)
	if clean == "" {
		return nil, fmt.Errorf("ntag: empty input")
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("ntag: invalid hex: %w", err)
	}
	return Decode(b)
}

// Decode decodes NTAG21x config pages: 8 bytes (CFG0+CFG1) or 16 bytes
// (CFG0, CFG1, PWD, PACK).
func Decode(b []byte) (*Config, error) {
	if len(b) != 8 && len(b) != 16 {
		return nil, fmt.Errorf("ntag: expected 8 bytes (CFG0+CFG1) or 16 bytes (+PWD+PACK), got %d", len(b))
	}
	mirror := b[0]
	access := b[4]

	c := &Config{
		MirrorConfRaw:          int(mirror>>6) & 0x03,
		MirrorByte:             int(mirror>>4) & 0x03,
		StrongModulation:       mirror&0x04 != 0,
		MirrorPage:             int(b[2]),
		Auth0:                  int(b[3]),
		ConfigLocked:           access&0x40 != 0,
		NFCCounterEnabled:      access&0x10 != 0,
		NFCCounterPwdProtected: access&0x08 != 0,
		AuthLimit:              int(access & 0x07),
	}
	c.MirrorConf = mirrorConf[c.MirrorConfRaw]
	if access&0x80 != 0 {
		c.Protection = "read+write (PROT=1)"
	} else {
		c.Protection = "write-only (PROT=0)"
	}

	if c.Auth0 == 0xFF {
		c.Notes = append(c.Notes, "AUTH0=0xFF: password protection effectively disabled (no page is protected)")
	} else {
		c.Notes = append(c.Notes, fmt.Sprintf("pages from 0x%02X onward require password verification (AUTH0)", c.Auth0))
	}
	if c.AuthLimit == 0 {
		c.Notes = append(c.Notes, "AUTHLIM=0: negative-password-attempt limiting disabled")
	}
	if c.ConfigLocked {
		c.Notes = append(c.Notes, "CFGLCK=1: configuration pages permanently locked against writes (except PWD/PACK)")
	}

	if len(b) == 16 {
		c.Password = strings.ToUpper(hex.EncodeToString(b[8:12]))
		c.PACK = strings.ToUpper(hex.EncodeToString(b[12:14]))
		if c.Password == "FFFFFFFF" {
			c.Notes = append(c.Notes, "PWD reads as FFFFFFFF (factory default or password-protected / unreadable)")
		}
	}
	return c, nil
}
