// otpauth_migration.go — host-side Google Authenticator export decoder Spec,
// delegating to internal/otpmigration.
//
// Wrap-vs-native: native — the otpauth-migration://offline?data=… payload is a
// small public-schema protobuf (MigrationPayload), parsed directly with the
// protowire low-level reader (already an indirect module dependency; no
// codegen, no new go.mod entry) + stdlib base64/base32. Bulk-recovers every
// 2FA secret from one export QR, each reconstructed into an otpauth:// URI ready
// to feed into totp_generate. Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/otpmigration"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(otpauthMigrationDecodeSpec)
}

var otpauthMigrationDecodeSpec = Spec{
	Name: "otpauth_migration_decode",
	Description: "Decode a **Google Authenticator export** payload — the `otpauth-migration://offline?data=…` " +
		"URI (or the bare base64 behind it) produced by Authenticator's *Export accounts* / *Transfer " +
		"accounts* QR — into the list of 2FA accounts it carries. A single export QR packs **all** of a " +
		"user's seeds, so decoding one **bulk-recovers every TOTP/HOTP secret** in one step — a high-value " +
		"post-exploitation / device-forensics capability (a captured export QR, screenshot, or deep-link " +
		"yields every second factor at once). Each account is returned with issuer, name, base32 secret, " +
		"algorithm (SHA1/256/512), digits, type (totp/hotp), HOTP counter, **and a reconstructed " +
		"`otpauth://` URI ready to paste straight into `totp_generate`** for the live codes.\n\n" +
		"Accepts the full `otpauth-migration://` URI or the bare base64 `data` value (standard / URL / " +
		"padded / unpadded all tolerated). An unknown algorithm/digit/type enum value is surfaced raw " +
		"(`UNSPECIFIED(n)`) rather than guessed; a single `otpauth://` URI (not a migration export), a " +
		"non-base64 payload, or a payload carrying no accounts is rejected. No network, no device, " +
		"transmits nothing — Low risk. Pairs with `totp_generate` (single-seed → codes) and the credential " +
		"tooling (`hash_identify` / `jwt_decode`).\n\n" +
		"Source: docs/catalog/gap-analysis.md (2FA loot — the bulk-export sibling of totp_generate's " +
		"single otpauth:// URI). Wrap-vs-native: native — a public-schema protobuf parsed with the " +
		"protowire low-level reader (already an indirect dep; no codegen, no new go.mod entry) + stdlib " +
		"base64/base32. Anchored to the canonical example secret JBSWY3DPEHPK3PXP.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"data":{"type":"string","description":"The otpauth-migration://offline?data=… URI, or the bare base64 data value behind it (the Google Authenticator 'Export accounts' QR payload)."}
		},
		"required":["data"]
	}`),
	Required:  []string{"data"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   otpauthMigrationDecodeHandler,
}

func otpauthMigrationDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	data := strings.TrimSpace(str(p, "data"))
	if data == "" {
		return "", fmt.Errorf("otpauth_migration_decode: 'data' is required")
	}
	res, err := otpmigration.Decode(data)
	if err != nil {
		return "", fmt.Errorf("otpauth_migration_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
